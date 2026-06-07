# Shekyl public narrative and FAQ

**Status:** living document. Archival service-promise section ratified with
`docs/V3_STAKER_ARCHIVAL.md` §*Service promise* (2026-06). Broader
positioning draws from V3 economics; update when those surfaces change.

Legal/regulatory framing for foundation archival lives in
`docs/design/FOUNDATION_ARCHIVAL_DISCLOSURE.md` — counsel review required
before genesis.

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
chain state (old blocks, curve-tree paths, dispute backstop material). It is **not**
a CDN or cloud-storage SLA.

### What we guarantee

**Permanent retention.** Deep history is never deleted. If data existed on the
canonical chain, it remains retrievable from the network's archival layer. This
is a hard guarantee, not a probability.

**Never gone — auditable.** Foundation seed archivers listed in genesis hold a
**complete copy** of the archival tree at **known, public** endpoints. Anyone
can verify they serve the full archive. You do not have to trust anonymous
peers alone for the question "does the data still exist?"

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

No. Shekyl commits to **permanent retention** of canonical chain history needed
for wallets, auditors, and dispute resolution. The foundation operates complete
archives you can audit; market archivers add redundancy on top.

### How fast will a deep historical fetch be?

There is **no guaranteed latency**. Fetches may retry across holders and routes.
Foundation seeds are public fast sources when you need a complete copy; day-to-day
queries may use anonymized market archivers and can be slower. Plan for **hours,
not milliseconds**, for rare deep history — and for success, not for a deadline.

### Is this "centralized storage"?

Partially, and we say so on purpose. Genesis enumerates foundation archiver
identities that hold a complete tree — auditable, challenge-tested, excluded from
market reward economics. That is **foundation-as-feature**: a transparent backstop,
not a hidden admin key. Decentralization means the **market layer growing beyond
that floor**, observable on-chain, not pretending the floor does not exist.

### Do foundation archivers earn staking rewards for holding everything?

No. Foundation complete-tree archivers are **outside the market reward formula**.
They do not compete for scarcity-priced archival yield. Market stakers earn from
holding under-served shards; the foundation holds the complete floor for
durability and auditability.

### Do foundation archivers post retention bonds?

Yes — a **nominal minimum bond** per active foundation identity, uniform across
the genesis set. This is not economic skin-in-the-game (they earn no market
reward); it keeps them on the **same challenge and slash path** as everyone else
without a special consensus exception. The amount is floored at the protocol
minimum, not tuned for market signal.

### What happens if market archivers thin out?

The foundation complete archive remains. Worst case is **more reliance on the
disclosed floor** (a decentralization regression), not silent data loss — provided
operators monitor market coverage (see disclosure doc). Fee-era economics may shift
how fast the market rebounds; terminal subsidy targets **decentralization margin**,
not durability survival.

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
from genesis. Deep chain history is **permanently retained** with an **auditable
foundation complete archive** and a market of stakers adding decentralized
redundancy. Historical retrieval is **best-effort over private transport**, not
instant cloud delivery — honest about what the protocol promises and what it
does not.
