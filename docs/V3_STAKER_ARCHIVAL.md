# V3 Design Notes — Staker Archival as Useful Work

**Status:** LIVING CONTRACT — last verified 2026-09-19 at `dev@6c41bf820`,
**contracted** that day under the `PDM` propagation sweep (document 3 of 4;
[`FOLLOWUPS.md`](FOLLOWUPS.md) "`PDM` propagation sweep" row, ruled
2026-09-19). This is the **front door** to archival staking — the problem it
solves, the economic design, the query-privacy doctrine, and the
firewalled-pseudonym model — and it keeps only what no other document holds.
Everything mechanism-shaped is a **cited pointer** to the contract that owns
it, never a second copy:

| Surface | Owning contract |
|---|---|
| What is archived, what a shard is, what every daemon keeps and discards | [`ARCHIVAL_PRUNED_DAEMON_MODE.md`](design/ARCHIVAL_PRUNED_DAEMON_MODE.md) — `PDM-Q6` (the good: each transaction's prunable body + `pqc_auths`), `PDM-Q-F32` (a shard: a consecutive `tx_id` range `[b_k, b_{k+1})` closed on crossing `SHARD_BYTES`, sized in `[SHARD_BYTES, SHARD_BYTES + MAX_TX_SIZE)`), `PDM-Q12` (the segment freeze is retired; the serving unit is the body), `PDM-Q2` (the universal discard window `W`), `PDM-Q9` (the daemon holds no serving state) |
| Where an archiver's bodies live | [`design/WALLET_SIDE_STORE.md`](design/WALLET_SIDE_STORE.md) — `P`'s serving store, the wallet's only redb, `StakeEngine`-owned (`WSS-Q1` (a)); erased only on the two-epoch pin-release gate (`WSS-Q8`); the principal's proving state is not a store (§6.3) |
| Fetch and countersignature | [`design/ARCHIVAL_SHARD_FETCH.md`](design/ARCHIVAL_SHARD_FETCH.md) — one client, two callers (`SF-D1`); uniform memoryless holder draw (`SF-D10`); signed message (`SF-D8`) |
| The route `P` serves | [`design/ARCHIVAL_SERVING_ROUTE.md`](design/ARCHIVAL_SERVING_ROUTE.md) (`RF-R1`, `/shard/{id}`); the daemon is the client, no wallet talks to a wallet ([`design/ARCHIVAL_ENDPOINT_UPDATE.md`](design/ARCHIVAL_ENDPOINT_UPDATE.md) `EU-D1`) |
| Challenges, settlement, slash | [`design/ARCHIVAL_CHALLENGE_MECHANISM.md`](design/ARCHIVAL_CHALLENGE_MECHANISM.md) (derived assignment, 2-of-3 per epoch, whole-shard read verified per-tx); [`design/ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md`](design/ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md) (`SO-D8`) |
| Bond wire, `P` FSM, bond-post kinds | [`design/ARCHIVAL_BOND_GATE4.md`](design/ARCHIVAL_BOND_GATE4.md); [`design/PHASE_2B_FSM_RETOOL.md`](design/PHASE_2B_FSM_RETOOL.md) |
| The principal's lifecycle (stake in, release, drain) | [`design/PRINCIPAL_STAKE_LIFECYCLE.md`](design/PRINCIPAL_STAKE_LIFECYCLE.md) |
| Reward emission and the reward formula | [`design/REWARD_EMISSION_LEG.md`](design/REWARD_EMISSION_LEG.md) (§4 three-channel stack, §4.0 `Curve` ∘ servo pin); [`design/ARCHIVAL_CONSENSUS_STATE.md`](design/ARCHIVAL_CONSENSUS_STATE.md) (`market_R` as a derived ledger count, §3.3) |
| The `P` ↔ principal firewall | [`design/ARCHIVAL_FIREWALL_GATE6.md`](design/ARCHIVAL_FIREWALL_GATE6.md) |
| Foundation identity set, `CompleteTree`, nominal bond, slash chain, key rotation | [`design/FOUNDATION_GENESIS_IDENTITY_SET.md`](design/FOUNDATION_GENESIS_IDENTITY_SET.md); disclosure posture in [`design/FOUNDATION_ARCHIVAL_DISCLOSURE.md`](design/FOUNDATION_ARCHIVAL_DISCLOSURE.md) |
| Economics validation | [`design/STAKER_ARCHIVAL_SIM.md`](design/STAKER_ARCHIVAL_SIM.md) (sealed 2026-06-16, §L18) |

Archival pay-for-service is the **genesis (V3.0) staking model**. The
confidential claim / lock-tier staking it replaced was deleted pre-genesis
([`completed/LEGACY_CLAIM_ERA_RETIREMENT.md`](completed/LEGACY_CLAIM_ERA_RETIREMENT.md);
rule 95's standing instruction). That is a design pin, not an implementation
claim; status per leg lives with the owning contracts. The archival bond and
emission legs are built and exercised as genesis-live (the emission-claim regtest
e2e drove an accepted-and-applied claim 2026-07-19, PR #345;
[`design/PRINCIPAL_STAKE_LIFECYCLE.md`](design/PRINCIPAL_STAKE_LIFECYCLE.md) §4a);
the serving leg is built and being wired
([`design/ARCHIVAL_SHARD_FETCH.md`](design/ARCHIVAL_SHARD_FETCH.md) §9). Nothing
here is scoped to a later dot-release.
**Author / decision context:** Originated in Phase 1 wallet-rewrite
session (2026-04-26) as an answer to the long-running question "what
useful work do stakers actually do for the network?" The framing has
been held by Rick since approximately 2010 and crystallized when
FCMP++'s historical reference-block archival need (already in
`docs/FOLLOWUPS.md`) was paired with BitTorrent-style scarcity-priced
commons coverage as the mechanism shape. Rescoped to V3 ship in the
2026-04-27 actor-architecture decision; the rescoping does not change
the design. (That entry planned an `ArchivalEngine` Stage-5 sibling actor;
what landed is the `StakeEngine` actor with the serving host composed beside it
in `shekyl-p-host` — [`design/ARCHIVAL_CHALLENGE_MECHANISM.md`](design/ARCHIVAL_CHALLENGE_MECHANISM.md)
§9.7 is the record.)

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
**Problem 2: complete transactions must stay retrievable after every daemon
discards them.** Every node keeps the curve tree complete — its layer 0 is
never pruned and is the tree's own commitment — and a wallet proves a spend from
its own output's path plus the public root, so **spending never needs a pruned
region** ([`design/WALLET_SIDE_STORE.md`](design/WALLET_SIDE_STORE.md) §6.3;
`PDM-Q-F11`). What every daemon *does* discard, uniformly, is the bulk of each
old transaction: its prunable body (`CtSigPrunable`) and its `pqc_auths` — ~95 %
of transaction bytes — for every shard below the universal window `W`
(`PDM-Q2`, `PDM-Q6`). The txid components that commit to those bytes
(`txs_prunable_hash`, `txs_pqc_auth_hash`) are kept forever on every node, so
anyone who holds a body can prove it is the right one; but the body itself has
to be held by *someone* or it is gone. Rescan from seed, audit, and dispute all
need it. Foundation-only retention is a centralization concern; discarding
without a distributed holder is a data-loss concern.

*Not* "FCMP++ proof construction needs historical tree state served by
archival nodes": that claim is false — the tree is complete on every node and
spending never touches pruned regions — so it is not a problem this design
solves. The problem is the **retrievability of complete transactions**
(`PDM-Q6`, `WSS-1`).

These two problems have a joint solution: **stakers archive the chain.**
Stakers' unique properties — long-term presence, bonded reputation, and
long-horizon economic incentive — make them the only network actor
structurally suited to performing distributed long-term archival. Miners
optimize for current block; transactors are transient. Stakers are the
only class with skin-in-the-game on the chain's *long-term* health, and
archival is exactly long-term-health work.
The move that makes this coherent — followed to its end in *Pay-for-service
rebasing* below — is that **staking *is* archiving**: one staker type, one
work-paid reward, the principal a small eligibility gate that is never slashed,
and the service bonded by slashable per-shard collateral. Earlier drafts framed
it as two decoupled reward streams; that framing is superseded there.

---
## Service promise — genesis-pinned commitments
This section is a **set of commitments**, not a description. The sim
(`docs/design/STAKER_ARCHIVAL_SIM.md` §*Soundness pass*) validated market
retention economics **conditional** on these pins, and the pins shipped —
several are **cheap at genesis, unfixable after** (key rotation,
replication-count semantics, the on-chain foundation identity set).
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

**Owned by `PDM`; cited here, never restated.** Three distinct things appear in
archival discourse, and user-facing retention claims are unverifiable if they
are conflated:

- **The archival good** is each transaction's prunable body plus its
  `pqc_auths` (`PDM-Q6` items 1–2). It is what archivers hold, serve, and are
  challenged on; it is verified per transaction against the two txid components
  every node keeps forever.
- **The skeleton** — headers, the curve tree (complete on every node, its layer 0
  never pruned), the txid hash rows, and the retained per-transaction length rows
  — is kept by **every** daemon, uniformly, forever (`PDM-Q1`, `PDM-Q9`). It is
  not archival: nobody is paid to hold it and no challenge tests it.
- **A shard** is a consecutive `tx_id` range `[b_k, b_{k+1})` of the good,
  closed when its cumulative bytes cross `SHARD_BYTES` (`PDM-Q-F32`). Bonds,
  the wire's holdings echo, and the challenge draw all name this one unit
  (`PDM-Q6` item 3). There is no leaf-shaped shard, no shard root `R_k`, and no
  segment freeze (`PDM-Q12`).

**Who holds what.** Every daemon prunes uniformly at `W` and holds no serving
state (`PDM-Q9`). Market archivers hold the bodies of their bonded shards in
`P`'s serving store ([`design/WALLET_SIDE_STORE.md`](design/WALLET_SIDE_STORE.md)),
filled from their own daemon while the shard is still universally held and
served whole-shard over `P`'s onion. The Foundation `CompleteTree` holds every
shard — behind a persona, never on a daemon (`WSS-Q10`). A wallet that does not
stake holds no archival good at all; its proving state is not a store
(`WSS` §6.3).

**User-facing promise mapping (load-bearing).** *Permanent retention* (hard)
depends on the good being held for every closed shard — the Foundation floor
plus market redundancy. *"Your old transaction history won't disappear"*
depends on the same thing: rescan from seed needs the complete transaction, and
the complete transaction is exactly the skeleton (everyone's) plus the good
(the archivers'). *Auditable foundation floor*: the Foundation `CompleteTree` is
challengeable on every shard with public pass/fail.

**Legal / FAQ inheritance.** User-facing copy must say what is actually
retained — **complete transactions for all of chain history** — not "the
archival tree"; the tree is never at risk. `docs/PUBLIC_NARRATIVE_FAQ.md` and
`design/FOUNDATION_ARCHIVAL_DISCLOSURE.md` are re-keyed to this pin
(2026-09-19); counsel's lock is on this section.
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
Foundation **seed nodes are seeds of the tree, not just of discovery:** each
holds the **complete archival good for every shard** plus the skeleton every
node keeps (§*Archival data scope*) from genesis, at **known `.onion` v3
addresses** — retrieved over an **ordinary v3 rendezvous**, exactly as any other
`P` is. **All shard retrieval occurs across Tor, period** (ruled 2026-08-03):
"known" describes the *address*, not the transport; there is no separate
Foundation retrieval mechanism and no clearnet leg (`ADD_ONION`'s `NonAnonymous`
flag is unrepresentable in `shekyl_tor_control_client::control::onion::OnionFlags`).
They provide:
- **Durability floor** — observable, placement-controlled correlated-loss
  tail (you choose providers/jurisdictions — a **placement** property; the
  *durability* argument does not lean on location-hiding, which is a separate
  statement from the transport, and the transport is still a rendezvous).
- **Bootstrap source** — real complete tree before any market archiver
  seats (L12 cold-start closes against a source, not a synthetic decay
  alone).
- **Fast seeding source** — new archivers backfill from the Foundation's
  complete copies **over the same v3 rendezvous** every other read uses. What is
  "public" about the source is its **published address**, not its transport;
  backfill is not a privileged or clearnet path.
- **Fee-era backstop** — always present when the market thins (replaces
  L12 **decaying** floor — see gate-list item 5 amendment below).

**Retention vs internal redundancy vs serving participation (authority
pin — swan-4, 2026-06-11).** Three distinct properties travel under the
word "floor"; conflating them produced the swan-2/-3 extinction
over-claim and is named here so it cannot recur:

1. **Retention (the guarantee).** Every active genesis `CompleteTree`
   seat holds **all of B + C, permanently** — complete over all deep
   history, held continuously, **no sunset** (per this gate-list's
   item 5: foundation withdrawal is rejected as mutable-governance +
   gap risk). Consequence: a market-side replica count of **zero on
   any shard is never data loss** — it is a transition to
   **foundation-as-sole-source**, an availability state. Simulation
   reads that count market holder-set wipe-outs (`extT`/`shkExt` in
   `STAKER_ARCHIVAL_SIM.md` §L17) measure this availability exposure,
   not irrecoverability.
2. **Internal redundancy (foundation operations).** The guarantee's
   own durability is `N_active = 3` replica-complete trees across
   diverse providers and jurisdictions (the "many nines" managed-archive
   number above), plus the W4 treasury requirement that
   floor-operating reserves be crisis-uncorrelated with the token
   price. This is ops policy with authority, not consensus code.
   **Domain diversity is part of the requirement, not a deployment
   detail:** during a sole-source window the shard's availability *is*
   the foundation's uptime with effective domain count 1 in the L15
   sense unless the `N_active` seats are placed across distinct failure
   domains — internal redundancy counts toward the diversity floor only
   if the three seats are domain-diverse; otherwise the L17
   "degraded, foundation as sole source" verdicts are degraded further
   than the rows imply. **Seeding capacity is sized at the crisis
   multiple, not steady state:** provision re-seed bandwidth at **~4×
   the steady-state seeding flow** (the swan-4 `reseed_rate = 12` arm —
   halves sole-source exposure *and* cuts trough wipe-out count 40 → 10
   by interrupting the cascade; `STAKER_ARCHIVAL_SIM.md` §L17
   Finding 4). Surge seeding is the foundation's own action, not a
   consensus rule an adversary can trigger, so the static-margin
   objection to adaptive enforcement
   (`ARCHIVAL_FAILURE_CONFIRMATION_PIN.md` §3.3) does not apply.
3. **Serving participation (the modeled floor).** The sim's
   `floor_replicas` / `floor_decay_pop` / `foundation_floor_aged`
   knobs model how many **serving** replicas the floor contributes to
   coverage and retrieval latency — an availability lever. The L13
   "~57 % backstop" and the L17 floor-on arms are serving-layer
   measurements; they size degraded-retrieval exposure, **not** the
   retention guarantee, which holds regardless of the serving
   schedule.

**The threat model this concentrates.** For irreplaceable history the
durability backstop of record is **one organization**: correlated
infrastructure loss across the `N_active` seats, seizure, and
dissolution over mission timeframes 2–3 are the binding failure
modes — no privacy cost (chain data is public), but a single point the
market architecture otherwise exists to avoid. Mitigations are the
disclosed-backstop posture (`FOUNDATION_ARCHIVAL_DISCLOSURE.md`),
jurisdiction/provider diversity in §2, and the market trajectory
dwarfing the floor. **Reversion clause:** the no-sunset pin is the
substrate; if it is ever reopened (foundation-independence becomes a
design goal), the swan-3 W12/W13 questions — deep-set completeness of
any successor mechanism, mid-deep-modal trough exposure — re-activate
at that design round and are parked here against it, not deleted.

**Accountability.** Foundation archivers are **registered and
challengeable** — public challenge pass/fail is the accountability
mechanism. They are **fully excluded from archival reward claims** (no
reward path exists). Reputational failure on a public challenge is the
binding deterrent for a known entity; the slash amount is not the
economic lever.
**Nominal uniform bond, slash → release → removal, holdings wire, bonding
reversion ladder.** Mechanism — owned by
[`design/FOUNDATION_GENESIS_IDENTITY_SET.md`](design/FOUNDATION_GENESIS_IDENTITY_SET.md)
§3 (one `ARCHIVAL_BOND_FLOOR` bond per active genesis `P`, standard slash path,
the `CompleteTree` slash chain), §4 (`HoldingsDescriptor` / `CompleteTree`
sentinel), and its rejections (zero bond with a skip-slash branch; per-shard
rows for the complete tree). The economic consequence this document owns:
`N_active = 3` is sized so one failed sample knocks one whole seat out of the
durability floor until re-bond — margin is challenge-failure absorption, not
only geographic diversity.
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
Membership confers **one** distinctive protocol consequence: genesis
enumeration is required for a **`CompleteTree`** holder to count in
**`durability_count`** for all shards. Everything else (descriptor, nominal
bond, reward exclusion, challenge path) follows from the general archival model
and any `CompleteTree` registrant gets it ([`design/FOUNDATION_GENESIS_IDENTITY_SET.md`](design/FOUNDATION_GENESIS_IDENTITY_SET.md)
§2, §6–§7).
This is the concrete form of "our security includes the foundation" —
same trust class as hard-coded seed discovery keys, not a hidden flag.
**Irreversible without fork:** even if the market eventually dwarfs the
seeds, protocol privilege remains; vestigial-but-benign is acceptable
because privilege is non-extractive and verifiable.

#### Key rotation — over-enumeration (pinned at genesis)

Immutability of the enumerated set does **not** mean operational keys
never rotate — compromise, hardware lifecycle, and handoff require it over
a multi-decade horizon. A compromised operational identity **lingers** as a benign ghost (failing
public challenges, **released after slash**, absent from `durability_count`
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

**Good standing:** bonded retention commitment posted; not **released** after
slash; most recent challenged sample for the holder passed (or within grace
per challenge cadence — exact window pinned at gate 4). A compromised ghost
that keeps failing challenges is **released or not good-standing** and **does
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
queries do not inherit that bound. **Transport for seeding does not differ from
user query transport** — both are the v3 rendezvous (2026-08-03 correction; the
earlier "may differ … if fetch is from public foundation complete copies" wording
contradicted the one-mechanism ruling).
---

## The mechanism

### BitTorrent-style scarcity-priced commons coverage

Chain history is partitioned into **shards** — consecutive `tx_id` ranges of
transactions' prunable bodies and `pqc_auths`, each closed when its cumulative
bytes cross `SHARD_BYTES` (`PDM-Q-F32`; the unit and its boundaries are
`PDM`'s, §*Archival data scope*). A shard becomes bondable when it closes and
scarce only when every daemon discards it at `W` (`PDM-Q6` item 3); between
the two, the archiver's wallet fills its store from its own daemon.
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

Not every staker wants to play the rare-shard market. **Quick-pick allocation**
is this design's answer: the staker opts into a default allocation, the wallet
proposes a balanced portfolio of shards (mix of common/rare, recent/historical,
weighted to roughly average market reward), and they earn average archival
yield without making decisions. Active stakers pick their own shards. The two
classes coexist — active stakers hunt rare shards and do the work of optimizing
coverage; quick-pick stakers take the default and do none — and the default's
allocation rule is a **coverage backstop**: if active stakers over-cluster,
the default can lean passive stakers toward under-served shards. The landed
selection surface — what the wallet shows and how a shard is chosen — is
[`design/ARCHIVAL_SHARD_SELECTION_LIST.md`](design/ARCHIVAL_SHARD_SELECTION_LIST.md)
(`SL-`); a protocol-level quick-pick allocator is design intent here, not a
landed mechanism.

### Verification: challenge-response

Owned by [`design/ARCHIVAL_CHALLENGE_MECHANISM.md`](design/ARCHIVAL_CHALLENGE_MECHANISM.md).
What this document needs from it: assignment is **derived** from chain state,
not committed (§2 there); every bonded pair `(P, s)` is challenged **three
times per epoch** and credited on **2-of-3** passes (§3); the challenge *is* an
ordinary read — the witness (the producer of block `h`) fetches the **whole
shard** over `P`'s onion and verifies it **per transaction** against the txid
components every node keeps (`PDM-Q6`; `SF-D1`, `SF-D8`); sustained failure
slashes the **shard's bond**, never the principal. There is no latency-based
query routing and no "lazy storage" market: organic reads draw a holder
**uniformly at random** (`SF-D10`), and the reward pays **retention**, not
retrieval volume (§*The reward curve*).
### Privacy: mandatory anonymization on queries

A holder serving "daemon at IP X fetched shard *s*" would learn that some
wallet behind X wants old history — metadata this chain exists to protect;
distributing archival to many stakers means many parties could hold such
metadata. Two rulings close it:

- **Every fetch rides Tor, in both directions, with no clearnet leg.** `P`
  serves from a v3 onion; the requester is a **daemon** acting as a Tor client
  with no address of its own, so witness, recovery, and operator reads are
  indistinguishable on the wire (`SF-D2`, `SF-D3`, `PDM-Q9`). No wallet ever
  talks to a wallet (`EU-D1`). The cost is latency, which is acceptable for
  archival reads — they are not in the transaction-broadcast hot path — and it
  is why retrieval latency is a *soft* expectation (§*Service promise*).
- **The reader is not the wallet.** A wallet never needs a pruned region to
  spend (§*The problem this solves*), so no spend leaks a reference block to
  an archiver; the daemon fetches a shard episodically for rescan or repair and
  retains nothing (`PDM-Q9`, `WSS-Q9`).

Cover reads remain an optional later strengthening; nothing rules them in.

**Self-advertisement is the residual.** `P`'s held shard-set is public by
function (the bond record is the advertisement), and a distinctive portfolio is
recognizable if its owner shows it around. Shard visualizations are designed to
be shared ([`V3_SHARD_VISUALIZATION.md`](V3_SHARD_VISUALIZATION.md)), so the
person who publishes their portfolio bridges real-world identity → `P`. That
bridge is the sharer's choice and never the protocol's: the firewall's job is
that *nothing else* draws the `P` ↔ principal edge (*The firewall is a stack*).

**Commitment binding — RESOLVED: private, firewalled pseudonym.** The archival
commitment ("I archive shard *s*, I earn the reward") binds to a **pseudonym
`P`** that is a stable, discoverable, challengeable identity by function, and
whose link to the principal is what the whole design protects. Public
address-bound archival was rejected: with mandatory archival it would have made
every staker's participation public by construction. The model is the next
section.

---
## Pay-for-service rebasing and the firewalled-pseudonym identity model

**Status: the genesis staking model — built, wire-frozen
([`design/GENESIS_TX_WIRE_FORMAT.md`](design/GENESIS_TX_WIRE_FORMAT.md) Q11),
and sim-sealed ([`design/STAKER_ARCHIVAL_SIM.md`](design/STAKER_ARCHIVAL_SIM.md)
§L18, 2026-06-16).** It supersedes the two-stream / consensus-bond framing and
the tier-weighted pricing of earlier drafts, both deleted from this document
with the claim era; the gate-list at the end of this section records where each
gate closed.
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
  (`design/PHASE_2B_FSM_RETOOL.md` §7.5.3). Staking contributes zero to the property
  PoS systems invoke to justify staking.
- **Capital-at-risk "security bond" — not a service, and weaker than the label.**
  A bond secures something only if it is *slashable for the misbehavior it bonds
  against*. Here the principal is slashable for **nothing**: consensus is not
  staking's job, and the design explicitly keeps archival failure off
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
network need staking fills — complete transactions kept retrievable after every
daemon discards their bodies below `W` (§*The problem this solves*; `PDM-Q6`)
— as the chain outgrows full
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
  the earlier draft collapse into this single stream; the unconditional
  `staker_emission_share` consensus-bond yield — payment for no service — is
  retired (subject to the bootstrap caveat in the gate-list).
- **Principal becomes locked collateral, not yield-bearing-for-being-a-bond.** It
  always returns at unlock and is **never slashed** (preserving the resilience
  rationale the earlier two-stream draft named: an infra outage costs reward, not
  principal, so a staker does not rage-unstake). The lock stops being a yield multiplier and becomes
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
**The mechanism this model is built on — each piece cited to its owner:**

- **Transfer-shaped admission.** Stake-in (principal → `P`) and drain (`P` →
  principal) are ordinary FCMP++ main-tree transfers with no consensus minimum
  and no wallet minimum — firewall = base privacy
  ([`design/PRINCIPAL_STAKE_LIFECYCLE.md`](design/PRINCIPAL_STAKE_LIFECYCLE.md)
  DQ1; [`design/PHASE_2B_FSM_RETOOL.md`](design/PHASE_2B_FSM_RETOOL.md)
  "Admission shape"). There is no linkable "active staker" lookup; `P` is keyed
  off the **bond record**.
- **`P` is an independent keypair, HKDF-derived from the wallet seed** — never
  an algebraic offset of the principal key — with its own cold bond authority
  and hot serving identity ([`rust/shekyl-crypto-pq/src/archival_p.rs`](../rust/shekyl-crypto-pq/src/archival_p.rs);
  [`design/ARCHIVAL_FIREWALL_GATE6.md`](design/ARCHIVAL_FIREWALL_GATE6.md) §9.4/§9.6).
- **Two irreducible consensus-special surfaces:** the per-shard **bond**
  (`txin_archival_bond_post`; join-Market is the registration event —
  [`design/ARCHIVAL_BOND_GATE4.md`](design/ARCHIVAL_BOND_GATE4.md)) and
  **reward emission** (mint authorized by public work + membership-only backing,
  deduped on the bond record's claimed-epoch set —
  [`design/REWARD_EMISSION_LEG.md`](design/REWARD_EMISSION_LEG.md) §6, §7).
- **`R_market` is a derived ledger count**, not a published tag
  ([`design/ARCHIVAL_CONSENSUS_STATE.md`](design/ARCHIVAL_CONSENSUS_STATE.md) §2–§3).
- **Sybil-resistance lives in per-shard bonds** (total bond = shards × rate),
  not in `P`-uniqueness (*Per-shard retention bonds*, below).
Net on-chain: **P ↔ shard-set ↔ performance is public; principal link is hidden by
transfer privacy + gate 6 firewall.** Crypto novelty on the reward leg is
**membership-only control** (subtraction from today's verify) — not
ClaimLinkability / non-spending SAL sibling — when dedup is state-based.

### Tier-neutral shard pricing — breaking the tier oracle

Even firewalled, P's shard-set is public, and any tier-weighted shard pricing (an
earlier draft priced shards by the backing stake's lock tier) would make that
shard-set a **tier oracle**: a deep-historical portfolio would Bayesian-signal a
long-lock backing stake, narrowing which stakes could back P. The rule is
**tier-neutral shard pricing** — price purely by replication scarcity (the
BitTorrent insight) — and with the tiers themselves deleted there is nothing
left to sort on.

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
never-slashed, bounded and voluntary, consistent with the resilience rationale
above). Three things fall out of one mechanism:

- **The deep-history guarantee becomes real, not inferred.** A bond at risk is a
  credible commitment to *future* retention — exactly what demonstrated-longevity
  could not provide. This is the property tier-weighting was actually buying,
  recovered honestly.
- **The staker-wide tier disappears, and the oracle dies with it.** With no
  principal tier driving shard allocation there is no tier to leak anywhere, and
  the public residual is "**pseudonym P holds these shard-types**,"
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
**Holdings descriptor and the two counts.** Mechanism — the `HoldingsDescriptor`
(`ShardSetCompact` / `CompleteTree`) is
[`design/FOUNDATION_GENESIS_IDENTITY_SET.md`](design/FOUNDATION_GENESIS_IDENTITY_SET.md)
§4's; `market_R` as a derived ledger count at epoch close is
[`design/ARCHIVAL_CONSENSUS_STATE.md`](design/ARCHIVAL_CONSENSUS_STATE.md)
§3.3's; which consumer reads which count is §*Replication count* above.
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
- **Output.** Rewards land in **stealth outputs `P` controls**. No linkable
  consolidation back to principal — and per the 2026-07-16 re-walk (F-W10,
  `ARCHIVAL_FIREWALL_GATE6.md` §12.9) this holds **by construction** under FCMP++:
  the drain is not an identifiable transaction (no spend graph, spend set
  unenumerable), so the earlier "decorrelated drains, no lump sweep" wallet
  discipline is retired as a ring-signature-era carry with no substrate here. The
  consensus delay floor (`RELEASE_COOLDOWN_EPOCHS`) stands.
- **Bond funding.** Bond is `P`'s central collateral; lump principal→`P` bond
  funding is a correlation channel — weigh fund-from-earnings ramp vs lump initial
  bond in wallet hygiene.
### A bond is immutable for its life

**Ruled 2026-09-20.** A persona's bond is **immutable for its life**. The
holdings set is fixed at the bond post and never mutates. The only
holdings-change mechanism is **persona rotation**: under the two-active
overlap, the new persona bonds the new set and the old releases and drains —
two events of two pseudonyms, decorrelated, with the overlap covering serving
continuity and the cooldown. `Reinstate` (né `Rebond`) survives as the sole
in-place record operation: zero-money, post-slash, and not a change of
holdings.

**Why — and this paragraph is the protection, not commentary.** Clustering
requires **same-class repetition**; a single event cannot be clustered. The
design caps `P`-authored same-class events at **one per class per persona
lifetime** — fund, bond, release, drain — bond amounts are **quantized** at
`|S| · FLOOR` so the amount dimension carries no operator signal, and serving
is **miner-authored** (the credit wire rides coinbases). A persona's authored
chain footprint is therefore ~four transactions of four *distinct* classes.
**The clusterable object is an incremental-update stream, and this ruling makes
it unconstructible.**

Read that as a standing constraint on future work, because the failure mode is
specific and cheap to reach: **without this paragraph, incremental holdings
updates return as an obvious efficiency PR** — *"why post a whole new bond to
add one shard?"* — and silently destroy the property. The answer is that the
efficiency is real and the cost is the anonymity set. Any proposal to
re-introduce in-place holdings mutation must first say what it does about
same-class repetition; *"it's only one more event"* is the argument that ends
with a stream.

**History — the shape of how this resolved is part of the record.** The idea
was proposed early and **tabled** while shard selection was still open: under
system-assigned shards an operator's holdings would be mutated *involuntarily
and incrementally*, which forced exactly the update stream this ruling
forbids — so the objection was real, and fatal, on the design as it then
stood. Shard **self-selection** (market picker with the Foundation
complete-tree floor) removed that premise entirely; the objection did not
weaken, its subject ceased to exist. Reopened and ratified 2026-09-20. **The
fence was not indecision — it was a dependency**, and tabling rather than
deciding is what let the ruling be taken cleanly once the dependency cleared.

### The reward curve — retention, scarcity, banded plateau-cap

- **Reward retention, not retrieval.** "Work" means **proven retention** —
  scarcity-weighted challenge passes over time — **not** query-serving volume.
  Rewarding retrieval volume starves the rarely-read deep-historical shards
  (precisely the critical history), so nobody holds them. Retrieval has **no**
  reward role and no routing market: organic reads draw a holder uniformly
  (`SF-D10`).
- **Challenge unpredictability.** A holder must not be able to store only the
  challengeable subset. Under the landed mechanism the challenged pair and the
  read window are **derived from the previous block's hash** and the read is the
  **whole shard** verified per transaction, so there is no challengeable subset
  to store ([`design/ARCHIVAL_CHALLENGE_MECHANISM.md`](design/ARCHIVAL_CHALLENGE_MECHANISM.md)
  §2; `PDM-Q6`).
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
The landed formula is [`design/REWARD_EMISSION_LEG.md`](design/REWARD_EMISSION_LEG.md)
§4: `work_P(E) = Σ_s scarcity(s,E) · serve_credit_bit(P,s,E)` with the
three-channel `scarcity`, and `reward_P = budget · Curve(work_P) / Σ Curve(work)`
(§4.0, cap in the numerator, market-only denominator).

### What this dissolves (the convergence)

Work-based reward is **publicly computable**, so privacy stops being "hide the
amounts" and becomes entirely **firewall the identity**. The confidential-yield
apparatus that needed a hidden per-staker amount — cleartext tiers on the claim
wire, confidential entitlement and its range proofs, a portfolio that
Bayesian-signalled a tier — has no reason to exist and was deleted with the
claim era. What the existential soundness question became is **retention-proof
unforgeability**: anyone recomputes `P`'s payout from public archival history,
so inflation would be *loud* (detectable) rather than *silent*. Its feasibility
record is [`design/ARCHIVAL_RETENTION_PROOF_8C_FEASIBILITY.md`](design/ARCHIVAL_RETENTION_PROOF_8C_FEASIBILITY.md).
Reward is publicly computable **globally, not locally** — a `P`'s payout needs
the public aggregate `Σwork` via the supply servo — and *public, not local* is
what kills silent inflation.

### Gate-list — closure record

Seven gates stood between this rebasing and consensus-real. Each is closed;
the ruling lives where it was made:

1. **`Σwork` supply-safety servo** — `reward_P = budget · Curve(work_P) / Σ_{P'∈Market} Curve(work_{P'})`,
   cap in the numerator, market-only denominator, full budget distributed;
   differencing-clean because every input is continuously public.
   [`design/REWARD_EMISSION_LEG.md`](design/REWARD_EMISSION_LEG.md) §4.0 (E-1).
2. **Retention-proof soundness (loud 8c)** —
   [`design/ARCHIVAL_RETENTION_PROOF_8C_FEASIBILITY.md`](design/ARCHIVAL_RETENTION_PROOF_8C_FEASIBILITY.md);
   the test is [`design/ARCHIVAL_CHALLENGE_MECHANISM.md`](design/ARCHIVAL_CHALLENGE_MECHANISM.md).
3. **`R_market` derived ledger count (no `ν`)** —
   [`design/ARCHIVAL_CONSENSUS_STATE.md`](design/ARCHIVAL_CONSENSUS_STATE.md) §2–§3.
4. **Per-shard retention bond replacing the tier (the keystone)** —
   [`design/ARCHIVAL_BOND_GATE4.md`](design/ARCHIVAL_BOND_GATE4.md); bond-rate
   calibration is a sim output ([`design/STAKER_ARCHIVAL_SIM.md`](design/STAKER_ARCHIVAL_SIM.md)).
5. **Bootstrap shape — permanent foundation floor, market overlapped** —
   §*Service promise* here; identity set in
   [`design/FOUNDATION_GENESIS_IDENTITY_SET.md`](design/FOUNDATION_GENESIS_IDENTITY_SET.md).
   The bootstrap **subsidy** is flat per-active-bonded-market-shard and sunsets;
   the floor never does.
6. **`P` backing-and-firewall design** — built:
   [`design/ARCHIVAL_FIREWALL_GATE6.md`](design/ARCHIVAL_FIREWALL_GATE6.md),
   [`design/PRINCIPAL_STAKE_LIFECYCLE.md`](design/PRINCIPAL_STAKE_LIFECYCLE.md).
7. **Economic simulation re-priced** — sealed 2026-06-16 with zero parameter
   change ([`design/STAKER_ARCHIVAL_SIM.md`](design/STAKER_ARCHIVAL_SIM.md) §L18);
   gate 7 closed bonds-only (`ARCHIVAL_TIMING_CONSTANTS.md` / REL §10.2).
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
The landed budget — `budget(E)` and its three reward channels — is
[`design/REWARD_EMISSION_LEG.md`](design/REWARD_EMISSION_LEG.md) §4's; the
three paths above are the design rationale that produced it.

---

## Bootstrap dynamics: archival load matches network maturity

**The archival problem does not exist at chain launch, and the design does not
need it to.** Nothing is scarce until the first shard is discarded, which
happens only once the chain is older than the universal window `W`
(`PDM-Q2`: while `tip < W` nothing discards). Until then every daemon holds
every shard, and the economics run in a **launch free regime** — bonds are
posted on shards everyone still has, so that scarcity arrives with holders
already committed rather than with the Foundation `CompleteTree` as the first
and only holder of everything (`PDM-Q6` item 3; the in-window reward weight is
routed to [`design/REWARD_EMISSION_LEG.md`](design/REWARD_EMISSION_LEG.md)).
Every later shard has the same window: closed and bondable while universally
held, scarce `≥ W` blocks later. So the mechanism ships at genesis and carries
weight only when the chain is large enough to need it — no "it has to work at
launch" pressure, and no cold-start allocation problem, because by the time
coverage matters the staker population has had `W` blocks to form. The
Foundation floor stays complete throughout (§*Service promise*); it never sheds.

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
The structural difference from prior art: **staking is archiving** — the
staking reward is payment for a service the chain itself consumes, bonded by
slashable per-shard collateral, with consensus left entirely to proof of work.
Prior art is either-or (PoW conflates consensus and work; PoS has no useful
work); paying stakers only for archival, and for nothing else, is the
unconventional answer.

---

## Formerly open design questions — where each closed

These once gated the ship. Each is now ruled, and the ruling lives with its
owner:

- **Shard granularity** → byte-bounded `tx_id` ranges closing at `SHARD_BYTES`
  (`PDM-Q-F32`).
- **Query routing protocol** → no registry, no gossip, no wallet-to-wallet: the
  bond record is the advertisement, the daemon is the client, holders are drawn
  uniformly (`PDM-Q9`, `EU-D1`, `SF-D10`;
  [`design/ARCHIVAL_SERVING_ROUTE.md`](design/ARCHIVAL_SERVING_ROUTE.md)).
- **Challenge-response interval** → three derived challenges per pair per
  epoch, 2-of-3 ([`design/ARCHIVAL_CHALLENGE_MECHANISM.md`](design/ARCHIVAL_CHALLENGE_MECHANISM.md)
  §3); `MAX_CLAIM_AGE_W` bounds unclaimable epochs
  ([`design/ARCHIVAL_CONSENSUS_STATE.md`](design/ARCHIVAL_CONSENSUS_STATE.md) §5).
- **Price curve shape** → the three-channel scarcity stack under a banded
  plateau-cap ([`design/REWARD_EMISSION_LEG.md`](design/REWARD_EMISSION_LEG.md) §4).
- **Quick-pick portfolio composition** → the landed selection surface is
  [`design/ARCHIVAL_SHARD_SELECTION_LIST.md`](design/ARCHIVAL_SHARD_SELECTION_LIST.md);
  tier-keyed composition is gone with the tiers.
- **Unstake-cascade dynamics** → the age-stratified bond-mobility
  reconciliation, sealed ([`design/STAKER_ARCHIVAL_SIM.md`](design/STAKER_ARCHIVAL_SIM.md)
  §L18); release cooldown and slashable-through-cooldown in
  [`design/PHASE_2B_FSM_RETOOL.md`](design/PHASE_2B_FSM_RETOOL.md) P2B-7.
- **Privacy-of-queries protocol** → Tor v3 rendezvous both ways, daemon as the
  client (`SF-D2`, `SF-D3`; §*Privacy* above).
- **Foundation-node integration** →
  [`design/FOUNDATION_GENESIS_IDENTITY_SET.md`](design/FOUNDATION_GENESIS_IDENTITY_SET.md)
  (§*Service promise* above for the economics).

## Simulation

The simulation this design was validated by is built
(`rust/shekyl-staking-sim`) and its record is
[`design/STAKER_ARCHIVAL_SIM.md`](design/STAKER_ARCHIVAL_SIM.md): coverage
dynamics, bond mobility, cold-start, the swan scenarios, and the R-3
age-stratified reconciliation that gated the seal — **sealed 2026-06-16 with
zero parameter change** (§L18). The sim is the authority on the numbers this
document argues about; where the two differ, the sim wins.

---

## Conclusion

This design is the answer to the long-running "what real work do stakers do?"
question:

1. **Staking is archiving.** If you stake, you hold and serve shards of the
   archival good; there is no other staking.
2. **Shards are priced by scarcity**, not by demand — rare shards pay more, and
   picking one up dilutes its price.
3. **One work-paid reward.** Payment for proven retention; the principal is a
   small eligibility gate, never slashed; the service is bonded by slashable
   per-shard collateral, which is also the Sybil cost.
4. **Verification is an ordinary read**, derived from chain state, no human
   judgment.
5. **Privacy is a firewalled pseudonym** — `P` is public by function; the
   `P` ↔ principal edge is what the crypto, network, timing, output, and
   bond-funding layers protect.
6. **Every daemon prunes uniformly and holds no serving state**; archivers hold
   bodies in the wallet; the Foundation `CompleteTree` is a permanent,
   reward-invisible floor.
7. **Bootstrap-aligned**: nothing is scarce until the chain is older than `W`,
   so the mechanism ships at genesis and carries weight when the chain needs it.

---

## References and cross-cutting concerns

- Owning contracts for every mechanism named here: the table at the top.
- `docs/V3_WALLET_DECISION_LOG.md` — *2026-04-27 — Engine architecture: actor
  model with staged migration from composition* (the rescoping of this document
  from V4 to V3 ship); *2026-09-17 — Two stores by obligation* (the wallet holds
  serving state, the daemon holds only archival consensus state).
- `docs/V3_SHARD_VISUALIZATION.md` — companion shard-surface design
  (deterministic data art over shard content; `shekyl-shard-visual`; *Not
  tradeable*).
- `docs/ANONYMITY_NETWORKS.md` — Tor infrastructure.
- `docs/PUBLIC_NARRATIVE_FAQ.md` — user/partner archival promise.
- `docs/design/FOUNDATION_ARCHIVAL_DISCLOSURE.md` — legal disclosure draft.
- `docs/completed/LEGACY_CLAIM_ERA_RETIREMENT.md` — the claim-era staking this
  model replaced, and its deletion.
