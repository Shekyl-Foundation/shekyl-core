# Shekyl Staker-Operator Guide

This guide is for operators who run an **archival staker** -- a bonded
participant (`P`) that posts collateral, holds shards, and answers
retention/liveness challenges in exchange for archival rewards. It is **not**
the ordinary-wallet guide; if you only send, receive, and hold, see the
[CLI User Guide](USER_GUIDE.md) (the [Staking](USER_GUIDE.md#staking) section
covers ordinary staking). This guide covers the parts of running a `P` that
the protocol **cannot** enforce for you -- the places where a normal,
set-and-forget operator can still strand capital or weaken their own privacy by
doing something that looks reasonable.

The design goal is dependability for everyone, not optimization for experts.
You should not need to think like a "financial wizard" to run a `P` safely. The
defaults are chosen to be safe; this guide explains the small number of actions
that are *footguns the protocol will not stop you from pulling*, and why.

> **Status (V3.0).** Some of the protections described here as "the wallet
> should warn you" are **wallet-side and not yet implemented** (tracked as V3.1
> wallet-conformance guards). Until they ship, the operator is the last line of
> defense, which is exactly why this guide exists. Each such item is marked
> **[operator-enforced until V3.1]**.

---

## Table of Contents

1. [Who this is for](#who-this-is-for)
2. [The three things to know before you bond](#the-three-things-to-know-before-you-bond)
3. [Footgun 1: the drop-to-reallocate capital strand](#footgun-1-the-drop-to-reallocate-capital-strand)
4. [Footgun 2: the shared-anchor funding tell](#footgun-2-the-shared-anchor-funding-tell)
5. [Operational security (opsec)](#operational-security-opsec)
6. [Cold-start: the earliest operators carry the thinnest cover](#cold-start-the-earliest-operators-carry-the-thinnest-cover)
7. [What the protocol enforces vs. what you enforce](#what-the-protocol-enforces-vs-what-you-enforce)
8. [Further reading](#further-reading)

---

## Who this is for

You are running an archival `P` if you have posted (or intend to post) an
archival bond, hold shards, and expect to answer challenges over time. A `P` is
a **long-lived** participant by design: the lock tiers, bond duration, and
release cooldown all assume you set it up and keep it running, rather than
churning in and out. The safest way to run a `P` is the way most people will
naturally run one -- **set it up correctly once and leave it alone.** Low churn
is the safest operating regime; almost every way to hurt yourself below requires
*active, frequent* rebalancing that a set-and-forget operator never does.

---

## The three things to know before you bond

1. **Collateral is locked, and freeing it is slow.** Each shard you hold is
   backed by a flat `ARCHIVAL_BOND_FLOOR` of collateral. When you voluntarily
   release collateral (a full `Unbond`, or a partial-unbond via
   `HoldingsUpdate` that drops a shard), the freed collateral enters a
   **release cooldown of `RELEASE_COOLDOWN_EPOCHS = 2` epochs (20,000 blocks)**
   before it is spendable again. This is deliberate: it is the anti-dodge
   property that stops an operator from shedding an obligation and immediately
   refunding elsewhere. Plan around it (see [Footgun 1](#footgun-1-the-drop-to-reallocate-capital-strand)).

2. **Your bond-post timing is a privacy surface, and the wallet handles it for
   you.** When you join, the wallet draws a randomized delay before your bond
   posts on-chain so the posting time does not become a deterministic tell that
   links your funding source to your `P`. **Let the wallet do this.** Do not try
   to time your own bond-posts (see [Footgun 2](#footgun-2-the-shared-anchor-funding-tell)).

3. **Your `P` talks to the network over an anonymity transport, not clearnet.**
   A `P` hosts an onion service and answers challenges over it. The challenge
   traffic is exactly the traffic the archival firewall exists to protect, so a
   `P` **refuses** to answer a challenge that did not arrive over the anonymity
   transport rather than falling back to clearnet (see
   [Opsec](#operational-security-opsec)).

---

## Footgun 1: the drop-to-reallocate capital strand

**The mistake:** you drop a shard you are holding (a `HoldingsUpdate`
partial-unbond) intending to immediately use the freed collateral to fund a
*different* shard.

**Why it hurts you:** the freed collateral is **frozen for the release cooldown
(2 epochs / 20,000 blocks)**. It is not available to back the new shard during
that window. So the new shard is left under-collateralized -- you cannot post it
until the cooldown expires -- and the coverage you were trying to move is
*stranded*, present in neither the old position (you dropped it) nor the new one
(you cannot fund it yet). In the normal "lean" operating regime, other operators
are too pinned by their own locked collateral to quickly backfill the gap you
just created, so the network briefly loses the coverage and **you** carry the
self-inflicted hole.

This is the single most common way an attentive operator can hurt themselves and
the network at once, and it is entirely self-inflicted: a set-and-forget operator
never does it.

**What to do instead:**

- **Do not drop a shard to fund another shard within the cooldown.** If you want
  to take on a new shard, post it from **fresh capital**, not from collateral
  you are simultaneously freeing.
- **If you must rebalance** (drop one, take another), accept that the freed
  collateral is unavailable for ~2 epochs and **wait out the cooldown** before
  treating it as funding for the new position.
- **Prefer not to rebalance at all.** A `P` is long-lived; churning your shard
  set chases marginal optimization at the cost of exactly this stranding risk.
  The shards you hold are already covered; leaving them alone is the dependable
  choice.

> **[operator-enforced until V3.1]** A future wallet release will **warn or
> refuse** a `HoldingsUpdate` drop whose freed collateral you are visibly trying
> to redeploy within the cooldown. Until then, this is on you.

---

## Footgun 2: the shared-anchor funding tell

**The mistake:** you cause several funding/bond events to happen around a
**common time anchor** -- for example, batch-funding several `P`s at the same
moment, scripting your bond-post to fire on a fixed schedule or an external
trigger, or funding and posting in a tight, repeatable rhythm.

**Why it hurts you:** the wallet protects your join by drawing a **uniform,
independent** random gap (`s ~ U[0, 600]` blocks) between the funding event and
the bond-post, so the on-chain timing does not reveal which funding source is
yours. That protection assumes the gaps are **independent across your events.**
If you anchor multiple events to a common trigger, their on-chain times cluster
together -- and a clustered set of bond-posts is a fingerprint that links them to
each other and back to the shared source, *even though each individual gap still
looks random.* A marginal "is this one delay random?" check cannot see the
clustering; the linkage lives in the *correlation across events*, which only you
control.

**What to do instead:**

- **Let the wallet draw the gap, every time, independently.** Do not override it,
  do not batch, do not schedule your bond-posts to a clock or an external event.
- **Fund and join one `P` at a time, on its own independent schedule.** If you
  run several `P`s, do not spin them up in a synchronized burst.
- **Do not reconstruct the delay yourself.** In particular, never approximate the
  gap by jittering two event-times around a common anchor -- that produces a
  *clustered* separation that passes a naive "within 600 blocks" check while
  defeating the entire point of the standoff.

The reference wallet can **self-certify** its own draw (it ships a conformance
harness that grades the realized distribution against uniformity, order-balance,
and serial-independence). That tool checks that the *wallet's randomness* is
sound; it cannot check that *you* are not anchoring your events to a common
trigger. That part is operator behavior.

> **[operator-enforced until V3.1]** The wallet's uniform-independent draw is a
> conformance requirement with a published test vector, but it is **wallet-side
> and not consensus-enforced** -- the funding anchor is hidden on-chain, so
> nothing in consensus can police it. A conforming wallet protects you; a
> misbehaving or hand-rolled one does not.

---

## Operational security (opsec)

Running a `P` exposes a small number of correlation channels that the protocol
narrows but cannot fully close. The defaults are conservative; the rules below
keep them that way.

- **Never run challenge traffic over clearnet.** A `P` hosts an onion service
  and answers retention/liveness challenges over the anonymity transport. The
  correct behavior -- and the wallet/node default -- is a **loud refusal** to
  answer a challenge that did not arrive over the anonymity transport, *not* a
  clearnet fallback. If you see your `P` attempting clearnet challenge responses,
  stop and fix the transport configuration; a single clearnet exchange links your
  `P`'s IP to the exact traffic the firewall exists to hide.

- **Keep your `P` and your principal wallet isolated.** Your `P`'s network
  identity must not share a circuit, guard, or stream with your ordinary
  (principal) wallet traffic. Stream or guard reuse links the two at the network
  layer, which can connect your archival identity to your spending identity.
  Use separate transport state for the `P`.

- **Do not put principal-identifying metadata in `P` traffic.** The pre-join
  backing presentation and announce are your `P`'s first network appearance; they
  travel over the anonymity transport on a fresh circuit and carry no
  principal-correlated data. Do not add any.

- **Let timing be the wallet's job.** Beyond the funding gap (Footgun 2), avoid
  introducing any deterministic timing relationship between your `P`'s on-chain
  events and anything externally observable.

---

## Cold-start: the earliest operators carry the thinnest cover

At genesis the network has the **thinnest funding traffic** and the
**longest-lived foundational `P`s** at the same time. The entry-seam cover (the
crowd your funding event hides in) is at its structural weakest right at the
start, and it **strengthens on its own** as organic funding traffic accrues. This
is a known, bounded, self-resolving residual -- it is *not* a permanent property
-- but it has a direct operator consequence:

> **If you are one of the earliest operators, you carry the thinnest cover. Be
> the most opsec-conservative.** Apply every rule above with extra care:
> strict transport isolation, no synchronized funding, no correlatable timing,
> no clearnet anything. The cover that protects later operators by default is
> not yet there for you; your discipline substitutes for it until the network
> fills in.

Shekyl deliberately does **not** inject decoy funding to paper over this. Decoys
sourced by the foundation would be attributable, so a sophisticated adversary
would simply discount them -- buying a centralization/trust cost for cover that
does not actually fool the adversary it targets. The honest answer is operator
discipline during the cold-start window, which this section is.

---

## What the protocol enforces vs. what you enforce

| Concern | Enforced by | Your responsibility |
| --- | --- | --- |
| Collateral lock + 2-epoch release cooldown | **Consensus** (hard rule) | Plan around it; do not drop-to-reallocate within it |
| Bond-post randomized delay (entry standoff) | **Wallet** (conformance, self-certifiable) | Use a conforming wallet; do not override, batch, or schedule it |
| Independence *across* your funding events | **You** | Do not anchor multiple events to a common trigger |
| Challenge traffic over anonymity transport | **Wallet/node** (loud refusal default) | Do not reconfigure it to allow clearnet |
| `P` ↔ principal network isolation | **You** (transport config) | Keep separate circuits/guards/streams |
| Cold-start thin cover | **Time** (self-resolves) | Extra opsec discipline while early |

The pattern: **the protocol protects what it can see and police; the residuals
that live in operator behavior are routed here, to you, because consensus cannot
reach them.** The good news is that all of them are avoided by the same posture
-- set it up correctly and leave it alone.

---

## Further reading

- [CLI User Guide](USER_GUIDE.md) -- general wallet/node operation, including the
  [Staking](USER_GUIDE.md#staking) section.
- [Installation Guide](INSTALLATION_GUIDE.md) -- node and wallet setup.
- [Wallet Threat Model](THREAT_MODEL_WALLET.md) -- the adversary model the wallet
  is built against.
- [Anonymity Networks](ANONYMITY_NETWORKS.md) -- Tor/I2P transport details and the
  stream-reuse hazards referenced above.
