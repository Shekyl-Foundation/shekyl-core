# V4 Design Notes — Staker Archival as Useful Work

**Status:** Design exploration, V4-scoped. V3 ships without this mechanism;
V3's design must not foreclose adding it in V4.

**Author / decision context:** Originated in Phase 1 wallet-rewrite session
(2026-04-26) as an answer to the long-running question "what useful work do
stakers actually do for the network?" The framing has been held by Rick
since approximately 2010 and crystallized when FCMP++'s historical
reference-block archival need (already in `docs/FOLLOWUPS.md`) was paired
with BitTorrent-style scarcity-priced commons coverage as the mechanism
shape.

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

- **Existing**: `staker_pool_share=25%`, `staker_emission_share=15%`,
  `staker_emission_decay=0.90/year`. Principal bond yield. Unconditional.
- **New (V4)**: archival reward stream. Conditional on archival
  performance. Funded from a separate slice (see "Funding" below).

A staker doing both consensus-bonding and archival earns the sum. A staker
doing only consensus-bonding (archival outage, intentionally passive,
not opted in) earns only the principal yield. The two yield streams are
additive and independent.

### Tier interaction: lock duration as archival commitment depth

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

### Privacy: mandatory anonymization on queries

Open concern. A staker serving "wallet at IP X queried block H's curve
tree state" learns that wallet X is constructing a transaction with
reference block H. That's metadata FCMP++ specifically protects against;
distributing archival to many stakers means many parties have query
metadata.

**Defense (V4-required):** mandatory Tor / I2P / mixnet routing for
archival queries. The wallet routes queries through anonymizing
infrastructure before reaching the staker. This is consistent with
Shekyl's existing privacy stance (the chain already supports Tor for
daemon connections per `docs/ANONYMITY_NETWORKS.md`). The cost is
latency, which is acceptable for archival queries (they're not in the
transaction-broadcast hot path).

**Stronger defense (post-V4, optional):** wallets query for cover traffic
in addition to actual queries. The staker can't infer which historical
block the wallet actually needs. More expensive but stronger.

For V4 ship, mandatory Tor/I2P is sufficient. The privacy story for
distributed archival is *better* than foundation-only archival, because
trust is distributed across stakers (no single trusted operator) rather
than concentrated.

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

- **Months 0–6 post-launch**: chain is small, full retention is cheap
  for anyone. Foundation nodes carry whatever archival the network needs.
  Staker archival mechanism *exists* in the protocol but isn't load-
  bearing. Active stakers playing the market are hunting trivial rewards;
  quick-pick stakers earn near-zero archival yield. This is fine — the
  consensus-bond yield is the dominant return.

- **Months 6–18 post-launch**: chain has grown enough that pruning
  becomes attractive for some operators. Foundation nodes stay full-
  archival. Active stakers start finding meaningful rare shards as
  pruning consumers shed deep history. Archival reward stream becomes
  meaningful.

- **Months 18+ post-launch**: archival is a real economic activity.
  Foundation nodes can selectively shed shards that are well-replicated
  by the staker market, becoming more of a coverage-floor than primary-
  archive. Staker archival is load-bearing.

This means the V4 ship can include the mechanism without it being
immediately load-bearing. The economic structure is in place; the load
arrives when the chain is large enough to need it. No "the mechanism has
to work at launch" pressure.

It also means the bootstrap path naturally avoids the cold-start
allocation problem I worried about in earlier discussion: when the first
staker joins, *the network doesn't need archival yet*, so it's fine that
their allocation choices don't cover history uniformly. By the time
archival load matters, the staker population is large enough for the
market to converge to good coverage.

This phasing aligns with the V3 economy's existing late-cycle dynamics —
early-cycle stakers are mostly capital-anchoring (consensus bond
dominant), late-cycle stakers shift toward service provision (archival
reward dominant) as chain maturity demands it.

---

## What V3 must not foreclose

This mechanism is V4-scoped. V3 ships without it. But V3's design
choices must not foreclose V4's ability to add it. Specifically:

**1. Staker reward distribution architecture must support layering an
archival reward stream.** The existing `staker_pool_share=25%` and
`staker_emission_share=15%` define the principal yield. V4 needs to add
an archival reward stream alongside, without modifying principal payout.
**Status: probably fine** — the existing structure doesn't preclude
additive streams, but worth confirming during Phase 2b's stake-lifecycle
work that the disbursement code paths can accommodate a second reward
type.

**2. Tier system's lock-duration semantics must remain consistent with
using lock duration as an archival commitment indicator.** Lock duration
is already a governance signal; V4 adds "archival commitment depth" as a
second meaning. **Status: already fine** — lock duration is structural
not nominal; nothing prevents adding a second interpretation.

**3. Component 3 governance burn redirect must be flexible enough to
fund a new reward stream.** The burn-rate-to-archival path requires the
Component 3 mechanism to permit redirecting burn flow to a non-emission
target. **Status: needs confirmation** — the existing Component 3 spec
should be reviewed for whether burn-redirect targets are extensible.

**4. Daemon RPC surface must permit "query historical state from staker
peer" alongside "query from foundation node."** Wallets need to be able
to route archival queries to either source. **Status: open question**
— this is exactly the kind of thing Phase 2a's daemon RPC discussion
should be aware of, even if it doesn't directly affect the API. The
RPC surface for `assemble_tree_path_for_output` (per the existing
FOLLOWUPS entry on historical reference handling) should not assume
foundation-node-only.

**5. The wallet's daemon-selection logic must not foreclose multi-peer
archival.** Currently wallets connect to a single daemon. Archival
queries against the staker network might need multi-peer routing.
**Status: probably needs design work** — V3's single-daemon assumption
is fine for V3 but might be the binding constraint for V4 archival.
Worth flagging for the Phase 4b RPC method set work.

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

Not blockers; next-steps if this direction proceeds.

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

**Privacy-of-queries detailed protocol.** Mandatory Tor/I2P is the V4
default; cover-traffic protocols are post-V4. The exact integration with
existing `ANONYMITY_NETWORKS.md` infrastructure needs design.

**Foundation-node integration.** Foundation `--no-prune` nodes are the
floor. How do they signal "I'm covering shards X, Y, Z so the staker
market can de-prioritize them"? Or do they just always serve and let
the market self-organize? The latter is simpler; the former is more
economically efficient. Needs design.

---

## Simulation as separate project

This design should be validated via simulation before any V4
implementation work begins. Treat it as a separate project, parallel
to (not blocking) the V3 ship.

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

The simulation project is a useful artifact independent of V4 ship
decisions: it produces public documentation of how the mechanism would
behave, which can inform the community discussion that should precede
any V4 protocol changes.

---

## Conclusion

This design might be the answer to the long-running "what real work do
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
   the mechanism doesn't need to be load-bearing at V4 ship.

The structural innovation: **decoupling consensus-securing work from
useful work**, paying them from related but distinct streams, letting
stakers self-select. This pattern doesn't appear in prior PoS, PoW, or
storage-chain designs.

V3 ships without this. V3's design must not foreclose it. V4's protocol
addition is purely additive (no consensus-layer hard fork required).
Simulation work proceeds as a separate project with no dependency on
V3 ship timing.

---

## References and cross-cutting concerns

- `docs/FOLLOWUPS.md` — historical reference-block archival need
  (`assemble_tree_path_for_output`)
- `docs/DESIGN_CONCEPTS.md` — V3 economic structure
  (`staker_pool_share`, `staker_emission_share`, lock tiers,
  Component 3 governance)
- `docs/ANONYMITY_NETWORKS.md` — existing Tor/I2P infrastructure
- `docs/SEED_NODE_DEPLOYMENT.md` — foundation `--no-prune` archival
  policy
- `docs/STAKER_REWARD_DISBURSEMENT.md` — existing reward distribution
  mechanics that the V4 archival stream layers atop
- `docs/V3_WALLET_DECISION_LOG.md` — Phase 1 decision context
