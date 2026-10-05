# Shekyl public narrative and FAQ

**Status:** living document. Archival service-promise section ratified with
`docs/V3_STAKER_ARCHIVAL.md` §*Service promise* (2026-06). **Data scope pin**
re-keyed 2026-09-19 to `docs/design/ARCHIVAL_PRUNED_DAEMON_MODE.md` (`PDM-Q6`:
the archival good is the complete transaction body) — counsel lock gates on
`V3_STAKER_ARCHIVAL.md` §*Archival data scope*.

Legal/regulatory framing for foundation archival lives in
`docs/design/FOUNDATION_ARCHIVAL_DISCLOSURE.md` — counsel review required
before genesis.

For a plain-language walkthrough of how the PoW + PoS economy regulates
itself — emission, release pacing, adaptive burn, staker rewards, with worked
numerical examples — see [`ECONOMY_EXPLAINED.md`](ECONOMY_EXPLAINED.md).

---

## Positioning statement

Shekyl is privacy-preserving digital cash designed to last: quantum-resilient
from genesis, private by default, and governed by transparent protocol rules
users can verify without trusting a vendor's word.

---

## Core message (external)

**Privacy is the product.** Every user gets the same anonymity guarantees by
default — not a setting, not a premium tier.

**Rules are public; identities are not.** Protocol economics and archival
commitments are auditable on-chain and in specification. User activity stays
private within the threat model the protocol defines.

**Durability is disclosed, not hidden.** Deep chain history is permanently
retained. A foundation-operated complete archive is part of the design — public,
checkable, and separate from the market layer that decentralizes redundancy over
time.

---

## Archival service promise (user-facing)

This is what users and integrators should expect when fetching **historical**
chain state (old transaction bodies for rescan, audit, or dispute backstop). It is **not**
a CDN or cloud-storage SLA.

**What we store (plain language).** Shekyl separates three things:

1. **Your wallet's scanned outputs** — kept on your device once synced (not
   the foundation's job).
2. **The chain skeleton** — block headers, the membership-proof tree, and every
   transaction's fingerprint — kept by **every** node forever. It is never at
   risk and nobody is paid to hold it.
3. **Complete transaction bodies** — the full content of every transaction,
   which ordinary nodes discard after a window and archivers hold and are
   challenged on. Rescan from seed, audit, and dispute all need it.

The foundation complete archive holds **(3) for all of chain history**; with
(2), which every node has, that is every complete transaction ever confirmed.
The permanent retention promise applies to **complete transactions**, not to
proof-tree structure alone.

### What we guarantee

**Permanent retention.** Complete transactions for all of chain history are
never deleted. If data existed on the canonical chain, the network's archival
layer retains the material needed for rescan, audit, and dispute backstop — not
merely the proof tree, which every node keeps anyway. This is a hard guarantee,
not a probability.

**Never gone — auditable.** Foundation seed archivers listed in genesis hold
**every transaction body for all of chain history** at **known, public**
endpoints. Anyone can verify they serve the full archive. You do not have to trust
anonymous peers alone for the question "does the data still exist?"

### What we do not guarantee

**Real-time or bounded latency.** Historical reads may be slow. They traverse
anonymizing transport (Tor-class paths) to firewalled archivers. We promise
**best-effort** retrieval latency — typical success over time, not instant
availability and not a seconds-or-minutes bound. Do not read "eventual" as a
latency deadline; read it as **permanent retention + honest effort to serve**.

**Maximum decentralization at every moment.** The market layer adds redundant
holders over time; the foundation floor is the transparent backstop. Decentralization
is a **trajectory** (how much redundancy exists beyond the floor), not a claim
that no trusted party exists.

---

## FAQ — archival and history

### Will my old transaction history disappear?

No — **provided complete transaction history remains retrievable** for rescan
and your wallet has synced (or can rescan) outputs. Shekyl commits to
**permanent retention** of every transaction's complete body, not proof-tree
structure alone (every node keeps that regardless). The foundation operates
complete archives you can audit; market archivers add redundancy on top.
Restoring from seed still requires fetching **transaction bodies** from the
archival layer; the proof tree alone is not enough.

### How fast will a deep historical fetch be?

There is **no guaranteed latency**. Fetches may retry across holders and routes.
Foundation seeds are public fast sources when you need a complete copy; day-to-day
queries may use anonymized market archivers and can be slower. Plan for **hours,
not milliseconds**, for rare deep history — and for success, not for a deadline.

### Is this "centralized storage"?

Partially, and we say so on purpose. Genesis enumerates foundation archiver
identities that hold **every transaction body for all of chain history** —
auditable, challenge-tested, outside market reward economics. That is
**foundation-as-feature**: a transparent backstop, not a hidden admin key.
Decentralization means the **market layer growing beyond that floor**, observable
on-chain, not pretending the floor does not exist.

### Do foundation archivers earn staking rewards for holding everything?

No. Foundation complete-tree archivers are **outside the market reward formula**.
They do not compete for scarcity-priced archival yield. Market stakers earn from
holding under-served shards; the foundation holds the complete floor for
durability and auditability.

### Do foundation archivers post retention bonds?

Yes — a **nominal minimum bond** per active foundation identity, uniform across
the genesis set. This is not economic skin-in-the-game (they earn no market
reward); it keeps them on the **same challenge and slash path** as everyone else.
A failed challenge **slashes the whole nominal bond** and removes that seed from
the durability floor until it re-bonds — one failed check can take a whole seed
offline temporarily, which is why several active seeds are operated in parallel.

### What happens if market archivers thin out?

The foundation complete archive remains. Worst case is **more reliance on the
disclosed floor** (a decentralization regression), not silent data loss — provided
operators monitor market coverage (see disclosure doc). Fee-era economics may shift
how fast the market rebounds; terminal subsidy targets **decentralization margin**,
not durability survival.

This is a load-bearing answer, not a comfort line. Crash-scenario simulations
showed that a deep market trough can briefly empty **every market copy** of some
old shards even when market coverage later recovers in full. Because the
foundation archive is complete and held permanently, no scenario in the grid
loses data — those shards become **foundation-only** until the market re-seeds
from the foundation, and the measured cost is an availability window (in the
worst recovering crash, up to ~10 epochs of foundation-only retrieval for the
affected shards, bounded by the foundation's seeding bandwidth). Two honest
implications follow. First, through a crash trough the durability of
irreplaceable history rests on **one disclosed organization**, which is why
foundation treasury policy is required to be diversified rather than
token-denominated — the backstop must not shrink in the crisis it exists to
absorb. Second, foundation seeding capacity is an availability commitment,
sized from the same simulations.

### What should exchanges and institutions record?

- Archival promise = **permanent retention + best-effort latency**, not CDN SLA.
- Foundation complete-tree archivers are **genesis-enumerated and public**.
- Regulatory and partnership questions about "who holds the data" should use
  `docs/design/FOUNDATION_ARCHIVAL_DISCLOSURE.md`, not this FAQ alone.

---

## FAQ — economics (summary)

See also `docs/V3_STAKER_ARCHIVAL.md` for mechanism detail.

### Why stakers archive

Stakers perform **useful work the network needs** — distributed long-term
archival — paid by a scarcity-priced reward for proven retention, not for query
volume.

### Is staking inflationary or deflationary?

Both dynamics can exist at different phases. Emission, burn, and terminal subsidy
rules are deterministic and on-chain observable. Archival economics are separate
from the foundation floor (no reward extraction there).

---

## Short boilerplate (website / deck)

Shekyl is privacy-preserving digital cash with hybrid post-quantum cryptography
from genesis. Deep chain history — **every complete transaction** — is
**permanently retained** with an **auditable foundation complete archive** and a
market of stakers adding decentralized redundancy. Historical retrieval is
**best-effort over private transport**, not instant cloud delivery — honest about
what the protocol promises and what it does not.
