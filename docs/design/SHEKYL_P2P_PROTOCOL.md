# Shekyl P2P protocol — normative specification

**Status:** OPEN — **P2P-2 design round; cluster I (identity and Sybil resistance) delivered
for ratification; clusters T, B and A not yet drafted.** Produced by the P2P-2
design round dispatched on
[`P2P_2_DISPATCH_BRIEF.md`](P2P_2_DISPATCH_BRIEF.md). Ratification is Rick's,
**per cluster**, on the relay-round convention; the umbrella chat reviews each
package first. **Nothing here is implemented — implementation is P2P-3.**

**Pinned:** `dev` @ `47bfa66c33000249b1402a4bb104ae20ab68b757`
(`git ls-remote origin dev`, 2026-09-01). Papers corpus at `shekyl-dev`
`4cabe8ef2`. Every claim below was read at these pins.

**Identifier family:** `PWD-` (P2P wire decision), registered at birth in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md).

---

## 0. How a decision is stated here

Every decision carries four things, and **a decision missing the fourth is not
ruled — it is a deferral with extra words**:

1. **Options** actually considered.
2. **The adversary and the channel** each option answers. Naming `T` and its
   channel is the threat-model bar; an option that answers no named adversary
   is decoration.
3. **What is conceded.**
4. **The falsifier.** For a value choice with no experiment to run, this is a
   **named reopening criterion** — a concrete future observation. The
   operational test: *a future reader must be able to recognise the trigger
   without re-deriving the decision.* "Reopen if p99 handshake latency at the
   Pi-4 floor exceeds X" passes; "reopen if this turns out wrong" does not.

---

## 1. Invariants — requirements in, not subjects

Restated from the brief §3 so no decision below reopens them.

1. **Ratified D++ / relay-privacy mechanisms are requirements-in** — the stem
   graph, `STEMS = 2`, the embargo backstop, the per-zone `hop`, and the
   arrival-is-stemmed rule (Q12-U2, landed).
2. **No authentication between unknown peers** (PW-19a), jointly entailed by
   three landed rulings. `XK`/`IK` are *inapplicable*, not declined: the `K`
   pre-message is the assumption that the parties are not strangers.
3. **Structural unlinkability.** Privacy is not a setting.
4. **PW-4/PW-5 are moot for gossip** (PW-7b) and carried as ground.
5. **The transport's adversary is the non-participant path observer.** The
   counterparty is conceded; arrival metadata is D++'s scope, taxed not
   eliminated.
6. **Clearnet gives confidentiality and integrity, not anonymity** (PW-3a).
   Anonymity is Tor's.

**The check that disposes of a whole family of proposals** (PW-19a, and it has
now killed four): *any mechanism that would let a node distinguish a legitimate
peer from a prober requires prior knowledge of that peer, and prior knowledge is
forbidden.* Test a proposal against that sentence **before** costing it.

**The second check, named after this round hit its second instance —
*inherited defences that advertise more than the code delivers*.**

> **A constant naming a defence is a claim about code, not a description of it.
> Before crediting the number, trace the path that consumes it.**

Two instances, both inherited, both flattering the defence, both of which would
pass a review that reads only the constant:

- **`ANCHOR_CONNECTIONS_COUNT = 2`** advertises two anchor-backed outbound
  slots. The dial path delivers **at most one** — zero if every persisted anchor
  fails to handshake — and destroys the rest of the persisted set on first use
  (PWD-I4). Found only because a review challenged the figure rather than the
  reasoning. *"At most one" is the honest form and this line said "one" through
  two rounds: the overstatement the check exists to catch reappeared in the
  check's own statement of it.*
- **`PER_BLOCK_CHECKPOINT`** is default-on (`CMakeLists.txt:470`,
  `set(PER_BLOCK_CHECKPOINT 1)`), but every consumer guards on
  `blockchain_height < m_blocks_hash_check.size()` — with an empty hash corpus
  the fast check never fires, so the defence is compiled in and inert.

The census's **`inherited-defensive`** evidence class was minted for exactly
this row type: *a defence the tree carries by lineage with no Shekyl record
examining it.* This check is how such a row is **found** rather than how it is
labelled once found. The failure direction is always the same — the constant
overstates — because a constant that understated would have been noticed by
whoever needed the capability.

**The third check, and unlike the first two it interrogates *our own* output
rather than the tree's — *a countermeasure must sit on the path the attacker's
action traverses*.**

> **Name the attacker's action; name the code path that action traverses; show
> the countermeasure sits on that path.** Three steps, each mechanically
> answerable, run *before* costing the countermeasure or arguing its merits.

It exists because everything else this round checks is a property of an
artifact's **form** — sum checks, falsifier presence, named blockers, evidence
pointers, option tables with adversary columns. **Every one of those reads green
on a countermeasure pointed backwards.** That is rule 47 turned on the review
process itself: a gate whose subject is *"is this well-formed"* cannot see
whether the mechanism faces the attack.

Two instances, both in PWD-I2, and the second was found only by running the
check deliberately on already-approved text:

- **The peerlist rule was adopted sender-side.** The attacker's action is
  *sending* trash records; the path is `handle_remote_peerlist`; the approved
  rule restricted what this node **discloses**. Caught in review, corrected
  receiver-side.
- **The white-list rule did not cover the second writer.** The attacker's
  action in Shi §III-B is *connecting inbound and answering a back-ping*; the
  path is `handle_handshake` (`net_node.inl:2766`), not
  `handle_remote_peerlist`; the adopted rule spoke of "peerlist **records**"
  and that path inserts no record. **Sub-attack ② was declared closed by a rule
  that never touched its channel** — and PWD-I6's own disposition table said so
  in the next screenful, deferring PWC-D11 (*the back-ping gate to the white
  list*) to cluster B while the prose above it called ② closed.

**The generalisable lesson is in that second one.** The census had described the
mechanism **correctly** — §5.2 records ② as *"1,000 IPs cycled as inbound
connections"* — and the countermeasure still missed it, because a correct
description and a correctly-aimed defence are independent properties. **Reading
the attack right is not evidence of having answered it.**

**The two failures are a pair, and the pair yields the standing form.** Both
countermeasures were scoped to *a named code path*; both defended that path and
nothing else. **A countermeasure scoped to a code path defends that path. A
countermeasure scoped to an invariant over the protected asset defends the
asset.** The first reads better in review — it is concrete, and it names
something greppable — which is exactly why it survives: it fails only when a
*second* writer exists, and nothing in its own statement can reveal one.

> **Standing form for every countermeasure decision in clusters T, B and A:
> state the invariant over the protected asset, then enumerate the asset's
> writers and show each is covered.**

The enumeration is the load-bearing half, and it is what makes the coverage
claim **falsifiable rather than assumed** — a reader can grep for writers and
find one the decision missed. PWD-I2's corrected rule is written in that form
for exactly this reason: *the white list may only be written for connections
this node initiated* constrains the asset, so it covers both existing writers
and any future one, where "peerlist records" covered one of two.

**The fourth check, and it is a *disposal* rule like the first rather than a
review step — *prefer a mechanism whose input is your own observation to one
whose input is the peer's claim*.** (Rick, 2026-09-02.)

> **Claims require verification; verification requires identity; identity is
> forbidden by PW-19a. Observations require nothing.**

That chain is why the inherited p2p keeps needing guards for its guards. It asks
*"is this peer the same node as that one?"* — a question about **identity**,
which here is self-asserted, unverifiable, public once gossiped, and forbidden as
durable state. So `peer_id` needs `is_same_host` to stop replay, and the
back-ping needs a `peer_id` echo to stop substitution, and each patch is a better
way to verify a claim that should never have been made.

**The consciously designed question is *"is my own outbound pool
over-concentrated?"*** — a property of state this node already holds. No
cooperation, no claimed value, nothing to spoof.

**This is the reframe `DAEMON_RELAY_PRIVACY.md` §12.10 already performed one
layer up** — *"bounding pool-share `g` was bounding the wrong quantity"* —
restated at the connection layer. The project has made this move before and it
held.

It disposes of a family the way PW-19a's check does: **PWD-I1's four jobs, and
with them `peer_id`, `peerlist_entry.id`, the back-ping and `COMMAND_PING`.**
Applied *before* costing a proposal, it is cheaper than any of the four rounds of
patching it replaces.

**The fifth check, and it is the one this round earned hardest — *a coverage
claim is only as wide as the frontier it enumerates, and the frontier is almost
always narrower than the claim*.** (Rick, 2026-09-02, naming it a class after the
third instance.)

> **Before asserting that something is covered, complete or unnecessary, state
> the frontier you enumerated — and check whether the claim is about a wider
> one.**

**Three instances in this cluster, failing at successively larger scope**, which
is why it is a class rather than a recurrence:

| Frontier enumerated | Frontier the claim was about | Result |
| --- | --- | --- |
| Callers of `append_with_peer_white` (**the setter**) | Writers of `m_peers_white` (**the state**) | Missed the persisted restore, which writes the container directly and through an index view |
| Writers of one **path** | Writers of the **asset** | Missed `handle_handshake`'s insert; sub-attack ② declared closed by a rule that never touched its channel |
| Consumers within the **p2p layer** | Consumers in the **system** | Nearly deleted self-detection, which the **relay** layer depends on without saying so |

**The third is the sharpest, because the reasoning that produced it was
correct.** The observation-over-assertion reframe killed the back-ping rightly
and would have killed self-detection wrongly — *identical argument, opposite
verdicts* — and the only thing separating them was a **cross-subsystem consumer
check**. So:

> **A reframe that finds a mechanism unnecessary has only checked the layer it
> reasoned about.** Before deleting, enumerate consumers in the *other*
> subsystems; a p2p-layer "costs one slot" was a relay-layer propagation defect
> (PWD-I1, stem selection).

**The four checks above all answer *"is this right?"*. This one answers *"is
this complete?"*** — and unlike the others it cannot be run by reading the
artifact at all, only by going back to the tree with a wider question. That is
why it is last, and why it is the one most easily skipped.

---

## 2. Cluster I — identity and Sybil resistance

Delivered first because **PWD-I5's cross-document obligation is scoped against
the relay lane**, so it carries the longest external latency and should run in
parallel with the remaining clusters rather than after them. *(It is the
**obligation** that is scoped there; there is no closure yet — the write-back is
gated on PWD-I4. An earlier wording said "closure", which is where PWD-I5's own
heading drifted from: the ordering rationale was written before the row's scope
was settled, and then the row was named to match the argument.)* (The *disposition* load runs
the other way — cluster B carries ~20 bucket-4 rows to cluster I's 10 — so this
ordering is about latency, not volume.)

### PWD-I1 — no peer identifier on the wire at all; the four jobs it served are replaced

**RULED — and amended 2026-09-02, reversing this row's original verdict.** The
transport carries **no peer identity, durable or ephemeral**. `peer_id` is
removed from `basic_node_data` and `id` is removed from `peerlist_entry`. A
per-process identifier is **retained internally** for connection tracking and
rotation, and is never serialized to any surface.

**This row previously adopted the status quo** — keep the per-process random
`peer_id` — on the reasoning that its wire *durability* was already nil, with
each surviving use to be justified later in cluster B. **That deferral is what
the amendment removes.** The justification exercise was run (Rick, 2026-09-02)
and **no consumer survived it**, which is precisely the trigger this row's own
falsifier named.

**The falsifier fired, in this decision's disfavour, and that is recorded rather
than quietly rewritten.** It read: *"Name a mechanism the protocol requires that
cannot work without recognising a peer across sessions on the wire. If one
exists, this decision reopens."* The enumeration below is that challenge
executed. Four mechanisms read the identifier; none of them needs it **on the
wire**. A falsifier that fires and flips its decision is the artifact working —
a standing challenge nobody runs is decoration.

#### The four jobs, enumerated at the tree

| # | Site | What it decides | Why the wire field is not required |
| --- | --- | --- | --- |
| 1 | `:1114`, `:2718-2725` | Self-connection detection at handshake | **A handshake nonce does it.** Emit random `N`; a handshake arriving with an `N` you recently emitted is you |
| 2 | `is_peer_used` `:1213`, `:1238` | Don't dial an address whose stored id is my own | **Same job as #1, earlier.** Pure optimisation — losing it costs one wasted dial that #1 catches a moment later |
| 3 | `is_peer_used` `:1219`, `:1244` | Duplicate-connection avoidance | **Replaced by an address-based same-host outbound cap** — see below; the cap is *stronger* than the id |
| 4 | `:2585` / `:2792` | Back-ping: is this address the node that handshaked me? | **Deleted, not replaced** — its only job was gating whitelist promotion of an inbound peer, which PWD-I2 has already forbidden. Consumer inventory run below |
| **5** | `net_node.h:271`, `:2708-2712`, `:2072-2075` | **Handshake-complete sentinel** — `context.peer_id` starts at `0` and is read as a boolean: reject a second handshake, and *"do idle sync only with handshaked connections"* | **Replaced by an explicit local session-state flag.** Nothing here needs a *value*, only the fact that a handshake completed — which this node **observed** |

**Job 5 was missing from the first version of this table, and its absence is the
fourth instance of §1's fifth check — on the check's own round.** The
enumeration was run over the **identity** frontier: peerlist entries, handshake
fields, dial selection. `context.peer_id`'s use as a **connection-state**
sentinel is on a different frontier entirely, and nothing in the identity sweep
could reach it. **Had the field been removed as first ruled, every connection
would sit at `peer_id == 0`**: the double-handshake guard would never fire, and
`peer_sync_idle_maker` would exclude **every** peer from timed sync — a
network-wide liveness failure, not a degradation.

> **Ruled: the connection context carries an explicit `handshake_complete` flag,
> set locally when the handshake completes. Never on the wire.** Routed to
> **PWD-T1** with the nonce.

**This is the fourth check making the design better rather than merely
smaller.** An identifier doubling as a sentinel is the *assertion* pattern one
level in: the value's presence is being read as a claim about session state,
when session state is something this node **observes directly**. A boolean named
for its job cannot be zero-by-accident, cannot collide, and states its meaning at
every read site — three properties the overloaded identifier had none of.

Jobs 1–4 are public-zone-gated; **job 5 is not** — it runs on every zone, which
is why its replacement is not optional on any of them. **On anonymity zones the identifier does no work
at all**: self-detection is already a plain address comparison against
`m_our_address` (`net_node.inl:1291`, `:1697` — *"It's ourselves, obviously don't
take that"*), which is correct because a node on an anonymity network
definitionally knows its own address, having generated the keypair. The
`peer_id` half of the split exists **only** because a clearnet node behind NAT
cannot learn its public address.

> **The rule-16 shape in its purest form: the identifier exists because the
> session did not.** A single value serves an internal connection-tracking role
> and is announced on the wire as a side effect (`node_data.peer_id =
> zone.m_config.m_peer_id`, `:2153`), so the internal need appears to license the
> external exposure. They were never separable in the inherited design because
> there was no encrypted session to do the internal job. Once there is one, the
> internal job is the channel's and the wire field is residue.

#### The one job that is not nonce-shaped, and the correction it forced

**#3 is not subsumed by its own guard, and an earlier version of this amendment
said it was.** The condition is

```
(is_public && cntxt.peer_id == peer.id && peer.adr.is_same_host(cntxt.m_remote_address))
|| (!cntxt.m_is_income && peer.adr == cntxt.m_remote_address)
```

and `is_same_host` is `ip() == other.ip()` (`net_utils_base.h:83-84`) — **port-blind**.
So the second disjunct, which requires *exact* address equality and considers
only outbound connections, does **not** cover the first: disjunct A catches **the
same node at a different port on the same host**, and **a host we already hold an
inbound connection from**. The `is_same_host` conjunct is not redundant either —
it is what stops a remote party suppressing your dials by replaying a `peer_id`
it read out of gossip. **That guard exists because the identifier is public**,
which is a cost of the exposure, not an argument for it.

**But #3 needs the identifier at *connection* time, not at *selection* time**, and
that is what makes it removable. Losing it costs the pre-dial check, not the
detection.

**The replacement is not an identifier — it is an address-based same-host cap on
outbound slots**, and it is strictly stronger than what `peer_id` delivers:

- The id bounds the **multi-port** case and does **nothing** against multi-IP.
  A cap bounds multi-port identically and is the same shape as the outbound
  selection mechanism the residual in PWD-I2 already routes to.
- It needs no claimed value, so there is nothing to spoof and the `is_same_host`
  conjunct's job disappears with it.

**The amplifier this closes is real, and it lives in the gray list
specifically.** `append_with_peer_white` calls `evict_host_from_peerlist`
(`net_peerlist.h:374`), so the **white list already holds at most one entry per
host**. `append_with_peer_gray` has **no such call** — verified, zero
occurrences in the function — so **gray may hold many entries for one IP at
different ports**, bounded only by the 5,000 total. Remove `peer_id` with no
replacement and one adversary IP gossiped at N ports can occupy several outbound
slots through gray draws. **The cap is therefore not optional cleanup; it is the
condition under which removing the field is safe.**

#### The back-ping dissolves — consumer inventory, run rather than assumed

**The hypothesis was that the back-ping has no job left once PWD-I2 forbids
inbound whitelist promotion. It survives the inventory**, and the inventory was
run by the method the previous two rounds got wrong: enumerate what *consumes*
the mechanism, then check the state each consumer writes.

- **`try_ping` has exactly one caller** — `net_node.inl:2746`, inside
  `handle_handshake`, and its callback does one thing: `append_with_peer_white`.
- **`try_ping` writes no state of its own.** It opens a throwaway connection,
  invokes `COMMAND_PING`, checks `rsp.status` and the `peer_id` echo, and fires
  the callback. Delete the callback's job and nothing else observes it.
- **The only claim it verifies is `my_port`.** The IP is *observed* from the
  connection, never asserted — so a peer can lie about its own port and nothing
  else.
- **A wrong port now costs one failed dial.** Under PWD-I2 the inbound peer
  lands in **gray**, and `gray_peerlist_housekeeping` evicts an entry whose dial
  fails. The back-ping spends an extra TCP connection and a protocol round trip
  to learn eagerly what the ordinary dial establishes for free.
- **And a bad gray entry cannot propagate.** `get_peerlist_head` reads
  `m_peers_white` only (`net_peerlist.h:295-330`) and has exactly two callers,
  both on the wire path (`net_node.inl:2658` timed-sync, `:2778` handshake).
  **Nothing in gray is ever disclosed**, so an unverified entry poisons no
  peer's view but our own, for one dial.

> **Ruled: the back-ping is deleted. `COMMAND_PING` (1003) is deleted with it.**

**The command falls because the back-ping was its only user** — `try_ping` is
the sole invoker outside `tests/unit_tests/levin.cpp:2690`, and
`connection_context.cpp:46` merely carries its size limit. **Four p2p commands
become three** (PWC-B1).

**PWC-D11 dissolves rather than being decided.** It asked whether the back-ping
gate is kept; the gate's only purpose was a promotion that no longer happens.
**This is the shape worth noticing: the fix upstream removed the reason the
downstream question existed**, which is why it resolves to deletion and not to
the challenge protocol an earlier version of this decision proposed. **PWD-B10
inherits deletion as its answer**, not a design task.

#### Self-detection does *not* dissolve, and the reason is a finding

The same reframe invites folding self-connection into concentration — your own
address is one host, a cap already bounds it to one slot, so tolerate it. **That
does not hold, and the check is at the relay layer rather than the p2p one.**

`get_out_connections` (`levin_notify.cpp:232-233`) selects stem candidates on
`!context.m_is_income && context.m_remote_blockchain_height >= blockchain_height`
— **no self-exclusion**. An undetected self-connection is therefore an eligible
**stem peer**, and stemming to yourself advances the transaction nowhere: with
`STEMS = 2` a single self-edge **silently halves stem width** and leaves the
embargo to fire. That is a D++ propagation and timing consequence, not a wasted
slot, so **self-detection stays a real mechanism.**

**On the local socket-pair check** (a process connecting to itself holds both
endpoints, so one connection's local `address:port` mirrors another's remote):
**mechanically available but not a replacement.** The local endpoint is reachable
at the socket layer — `connection_basic::socket().local_endpoint()` is already
read at `abstract_tcp_server2.inl:1098-1099` — but is **not surfaced in the
connection context** the p2p layer iterates, so it would need plumbing. More
decisively, it **fails exactly where the identifier was needed**: on a NAT'd node
dialling its own *public* address, the local endpoint is the private address and
the mirror never matches. It covers the public-address node, which is the case
that least needed help. **Recorded as a possible optimisation for PWD-T1, not as
the mechanism** — the nonce covers both cases and the socket check covers one.

> **Binding on PWD-T1: the clearnet nonce is load-bearing for D++ stem width,
> not for slot hygiene, and its failure mode is silent.** A nonce that is wrong,
> or whose per-zone window is too short to cover the handshake round trip, does
> not produce a wasted dial — it produces an **undetected self-edge**, which at
> `STEMS = 2` halves effective stem width and leaves the embargo to fire. **The
> p2p-layer symptom is the invisible one**, so PWD-T1 must state this and must
> carry a falsifier that trips on **stem width**, not on connection count:
> *reopen if measured effective stem width falls below `STEMS` on a node whose
> connection count is nominal* — the relay lane's own stem observation
> (`shekyl-relay` `stem_width()`, `record_stem`) is the instrument, and a
> connection-count trigger would read green throughout.

#### The nonce must be zone-scoped, and this is a requirement on cluster T

**The inherited design carries a warning that the nonce would otherwise
re-create verbatim.** `handle_handshake` (`:2719`) says: *"test only the remote
end's zone, otherwise an attacker could connect to you on clearnet and pass in a
tor connection's peer id, and deduce the two are the same if you reject it."*

A naive nonce reproduces exactly this: you dial an attacker over Tor, the nonce
travels inside that session, the attacker presents it on an inbound **clearnet**
connection to a suspected IP, and **your self-detection firing is the
confirmation**. The drop is the oracle.

> **Required: per-zone emitted-nonce windows; self-detection compares only
> within the zone the handshake arrived on.**

Within-zone correlation is already conceded below. **This is stated here rather
than left to PWD-T1 because a countermeasure designed without it would be
pointed the wrong way** — §1's third check, applied forward instead of in
review.

#### Options

| Option | Adversary / channel it answers | Verdict |
| --- | --- | --- |
| **No identifier on the wire; nonce + same-host cap + local session-state flag, and the back-ping deleted outright** | The peerlist-scraping observer correlating `(address, id)` pairs network-wide, and across zones | **Adopted.** No job requires the field; two are nonce-shaped, one is better served by an address cap, one is *weakened* by the exposure |
| Keep per-process random `peer_id` (the original verdict) | Self-connection and duplicate detection, locally | **Refused on amendment.** It is a node-scoped identifier broadcast to every peer and propagated in peerlists, bought with an occasional avoided dial. **That trade does not survive being written down** |
| Remove from `peerlist_entry`, keep in the encrypted handshake | The gossip-scraping observer only | **Refused as insufficient, though it is the safe fallback.** It closes the network-wide surface and preserves #3 exactly; it is recorded here because if the same-host cap proves unworkable in cluster B, **this is the position to retreat to** rather than reinstating gossip exposure |
| Durable node id | Sybil-resistance-by-identity | **Refused — PW-19a**, unchanged from the original verdict |

#### Conceded

- **The nonce needs state the identifier did not** — recently-emitted values per
  zone, over a short window. It is small, bounded, and **local**, which is the
  direction PW-18 already wants; an identifier avoids the state by publishing
  the value instead, which is the trade being reversed.
- **The same-host cap costs a legitimate multi-node host.** Two honest nodes
  behind one IP will together receive at most one outbound slot from any given
  peer. Real, small, and the same concession the white list already makes
  silently via `evict_host_from_peerlist`.
- **The cap sits near `DAEMON_RELAY_PRIVACY.md` §6.10's exclusion, and the
  distinction is argued rather than assumed.** §6.10 ruled the address family
  out — *"on clearnet it lies (Sybils spread across subnets cheaply, and
  subnet-diversity heuristics quietly punish legitimate home users)"* — **as an
  *admission* basis.** A cap is a third job, distinct from both admission and
  from PWD-I3's continuity bookkeeping: **it makes no judgement about the peer
  at all.** A diversity *heuristic* infers trustworthiness from an address, which
  the address cannot support; a cap bounds **this node's own pool** and applies
  the identical bound whoever is on the other end. Nothing is scored, nobody is
  ranked, and the input is local state rather than a claim — §1's fourth check
  is precisely what separates them.
  **What does carry over is the second half of §6.10's objection**, and it is
  conceded above: honest users behind shared NAT are affected. They are not
  *punished* — no inference is drawn about them — but they are **bounded**, and
  the bound is the same one an adversary gets. **Its value is an eclipse bound,
  so it is set with PWD-I4's sub-round, not before it.**
- **Within-session and within-zone correlation remain**, unchanged: a peer is
  trivially correlatable across the connections *it* dialled. Cross-session and
  cross-zone linkage is the asset, and that is what removal denies.

#### What this supersedes, and the surfaces it must be swept across

- **`ANON_ZONE_SENTINEL_PEER_ID = 1`** (`net_node.h:180`) is **superseded, not
  retired for cause**: no identifier is strictly stronger than an identifier
  pinned to a constant. **`DAEMON_RELAY_PRIVACY.md` §91.4's unlinkability
  composition names the sentinel as one of three composed decisions**, and
  `rust/shekyl-relay/src/zone/mod.rs:190-199` builds a load-bearing argument on
  it. **Both must be re-grounded on "no identifier on the wire" rather than left
  citing a retired mechanism** — the composition gets stronger, but the text
  that states it becomes false.
- **There is a *third* disclosure surface, and it is the one the enumeration
  nearly missed.** `shekyl_rpc_connection_facts.peer_id`
  (`src/rpc/rpc_facts_ffi.h:315`, populated at `rpc_facts_ffi.cpp:1050-1056`)
  exposes the **peer's announced id** through `get_connections`. Gossip,
  handshake and RPC are three surfaces, and Rick's finding is precisely that an
  internal need licensed external exposure — so **the retained internal
  identifier must not leak here either.** When the field leaves the wire this
  struct member loses its source and is removed; `connection_id`, already
  present and locally generated, is the correct operator-facing handle.
- **`peerlist_entry.id` is persisted**, so its removal is a stored-format change.
  It rides **the same rule-42 version bump** as PWD-I2's white→gray
  reclassification: **one bump, two migrations.**

#### Routing — named owners, because a cluster is not an owner

**Two of these have no owning row today, and that is a gap in the dispatch
brief rather than something to leave as "cluster B owns it."**

| Replacement | Owner |
| --- | --- |
| Zone-scoped handshake nonce | **PWD-T1** (it is a handshake token). **This amendment must land before T1 is drafted**, and T1 must carry the stem-width consequence below — the nonce is not slot hygiene |
| Same-host outbound cap | **PWD-B9 — new row**, outbound connection diversity. No existing B row covers outbound selection: B1 is command rate limiting, B7 is *drop* semantics by host |
| ~~Back-ping challenge~~ — **answered here: deleted**, with `COMMAND_PING` | **PWD-B10** carries the deletion and the command's removal from the wire surface (PWC-B1), not a design task |

**Falsifier.** The original standing challenge has been executed and answered, so
it is replaced by one with a measurable subject. **Reopen if any mechanism in
clusters T, B or A is specified that requires recognising a peer across
connections without an address**, or **if a fleet run shows outbound peer
diversity — distinct hosts per node's outbound set — falling below the diversity
achieved with `peer_id`-based dedup**, which the Q12-D6a rig can measure on both
configurations. The second is the one that would indict the same-host cap
specifically, and it is the replacement carrying the most new risk.

### PWD-I2 — peerlist *acceptance* is restricted; disclosure is retained unchanged, and the Shi et al. amplifiers are closed

**RULED.** **Disclosure is not reduced — it is retained exactly as it is**, and
**three changes are made to what this node *accepts*.**

**The heading said "disclosure is reduced" through three rounds, and it was the
original defect surviving in the title.** None of the three adopted rules
touches what this node sends: the anonymised head (PWC-D2) is kept unchanged,
the cross-zone refusal (PWC-D10) is kept unchanged, and "stop disclosing
entirely" is refused below. A decision named for the side it does not act on is
how the sender/receiver confusion got in, and leaving the name would keep the
door open for it.

The current shape (all verified): up to 250 entries per message (PWC-D1),
disclosed on **both** handshake and timed-sync (PWC-B4), sampled over the whole
white list then shuffled and `last_seen`-zeroed (PWC-D2, an explicit defence
citing Cao et al.), refused wholesale if any entry is from another zone
(PWC-D10), with white/gray capped at 1000/5000 (PWC-D3).

| Option | Adversary / channel | Verdict |
| --- | --- | --- |
| Status quo | — | **Refused.** Shi et al. §III-A fills the 5000-entry FIFO graylist from *timed-sync responses* alone; §III-B cycles 1000 IPs through the white list |
| **Accept peerlist records only on connections *this node initiated outbound*** | The graylist-filling adversary, over inbound connections it opened | **Adopted — and note this is *receiver-side*.** An earlier draft adopted the mirror of this (restricting what we *disclose*) and **it defends nothing**: see the correction below |
| **Cap records accepted per connection, not just per message** | The same adversary, amortising across many messages | **Adopted, and the ceiling is derived below** — 250/message with no per-connection ceiling is a cap on the wrong quantity |
| **The white list may be written only for connections *this node initiated*** | Shi §III-B's whitelist adversary, which inserts **itself** on an inbound connection and never sends a peerlist record at all | **Adopted — this is the rule that actually closes ②**, and the two rules above do not. See the second correction below |
| Stop disclosing entirely | Topology mapping | **Refused** — peer discovery on an open gossip network needs it; and PW-3a records that discoverability is *structurally* incompatible with clearnet node anonymity anyway, so paying liveness for a property that cannot be bought is a bad trade |

**Correction — the first version of this rule pointed the wrong way, and would
have shipped a countermeasure that defends nothing.** It said "restrict peerlist
**disclosure** to outbound-initiated exchanges," which changes what this node
*sends*. The attack does not consume what we send. Traced at the pin:
`peer_sync_idle_maker` (`net_node.inl:2063-2085`) iterates **every** handshaked
connection with no `m_is_income` filter, so the victim sends a timed-sync
*request* over the attacker's inbound connection; the attacker answers with a
response carrying 250 trash records; and the victim **accepts** them via
`handle_remote_peerlist` (`:1169`). **The poisoning channel is what we accept on
a connection the attacker opened, not what we disclose.** Restricting disclosure
leaves it fully open, and would additionally have cost peer discovery for
nothing.

The directional asymmetry is already established in that exact function, which
is what the rule should have followed: `set_peer_just_seen` at `:1175` is
guarded by `if(!context.m_is_income)` — whitelist *promotion* is already
outbound-only. **This rule extends the same guard to peerlist
*acceptance*.**

**Second correction — the same review question, asked once more, found a second
writer, and it is the one sub-attack ② actually uses.** The two rules above are
both scoped to *peerlist records*. **The white list has a writer that inserts no
record**, and the first version of this decision therefore closed ① while
leaving ② untouched — then PWD-I6 declared both closed.

The path, verified end to end:

- `handle_handshake` is **guarded to inbound connections only** — `if(!context.m_is_income)` drops
  and adds a host-fail (`net_node.inl:2700-2706`). Everything below it runs
  *exclusively* on connections the attacker opened.
- On a successful back-ping it writes the **counterparty itself** into the white
  list — `append_with_peer_white(pe)` (`net_node.inl:2766`) — **bypassing gray
  entirely**, gated only on the attacker's self-declared `my_port` and its own
  reachability.
- `pe.last_seen` is stamped `now` immediately above (`:2762-2764`).
- `evict_host_from_peerlist` (`net_peerlist.cpp:305-308`) filters on
  `is_same_host`, so occupancy is capped **per IP, at one** — and **not per
  subnet**; `is_host_allowed` rejects only loopback and local
  (`net_peerlist.h:282-292`), and subnet blocking is a manual operator ban list,
  not an automatic diversity cap.
- `trim_white_peerlist` (`net_peerlist.h:226-231`) erases
  `sorted_index.begin()` on the **`by_time`** index — **the oldest `last_seen`
  first**. Entries stamped `now` sort to the back; the honest peers seen longest
  ago are erased.

**That is Shi §III-B unmodified**: connect inbound → answer the back-ping → land
in white with a maximal timestamp → repeat until the 1000-entry cap
(`cryptonote_config.h:175`) trims the honest set out. The paper's cost — 1,000
IPs — is paid in **one inbound connection each**, and the per-connection record
ceiling above never applies, because no record is sent.

**The corrective rule is stated over the asset, not over a path**, which is why
it covers a writer the earlier wording could not reach.

**The inventory below is the third attempt, and the first two were short — the
reason is methodological and is recorded because it generalises.** The first
listed four entries, the second five; both enumerated **callers of
`append_with_peer_white`** rather than **writers of `m_peers_white`**, which are
different sets. Sweeping the accessor cannot see a path that writes the
container directly, and `peerlist_manager::init` does exactly that — through the
`by_addr` **index view** (`m_peers_white.get<by_addr>()`), so even a sweep of the
bare member name misses it unless index views are included. **Enumerate the
state, not the setter, and include its index views.**

So the honest structure is **two insertion paths**, one of which has five
callers:

| Writer | Direction | Under the rule |
| --- | --- | --- |
| `try_to_connect_and_handshake_with_new_peer:1353` | Outbound dial we chose | **Kept** — this is the rule's licensed case |
| `gray_peerlist_housekeeping:3135` → `set_peer_just_seen` | Outbound dial we chose, after `check_connection_and_handshake_with_peer` succeeds | **Kept** — it is the rule's existing implementation |
| `net_node.inl:1175` → `set_peer_just_seen` | Outbound timed-sync, already `!m_is_income`-guarded | **Kept** — unchanged |
| **`init():864-865`** — `m_command_line_peers` | **Neither: local operator configuration, before any connection exists** | **Kept as a named exemption** — see below |
| **`handle_handshake:2766`** | **Inbound, by construction** | **Changed: routed to `append_with_peer_gray`** |

**Insertion path 2 — `peerlist_manager::init`, the persisted restore**
(`net_peerlist.cpp:272-284`), which repopulates `m_peers_white` from the
on-disk store via `add_peers` and bypasses `append_with_peer_white` entirely.

**This one carries an obligation the other does not, and it is a real hazard
rather than a bookkeeping note.** The invariant is a property of *how an entry
got into the white list*, and the store does not record that. **Entries written
by the old inbound back-ping path survive an upgrade and would hold white-list
membership no outbound dial ever earned** — the fix would ship while the
violation persisted in every existing datadir, and nothing would signal it.

> **Ruled: the store-version bump drops the persisted peerlist wholesale, and
> the node re-bootstraps from seeds. No reclassification.**

**An earlier version of this ruling said white entries are "reclassified to
gray, anchor and gray unaffected", and cited #587 as precedent. Both halves were
wrong, and the second is what made the first look achievable.** `load_peers`
(`net_peerlist.cpp:79-85`) returns `{}` for **any** pre-current version, before
reading a single list — its own comment says *"A pre-current store is dropped
wholesale (the node re-bootstraps)."* #587 is precedent for **exactly that
mechanism**, not for a selective migration one list over. Selective
reclassification would need a **new backward-compatible reader for v7**, and
without one the ruling as written would have silently become a full peerlist
reset anyway — arriving as a surprise rather than as a decision.

**The drop is adopted rather than the reader, and pre-genesis is why.** Building
format-migration machinery on a persisted path, to preserve a peerlist across a
single upgrade, on a chain with no long-lived stores, is precisely the debt
[`15-deletion-and-debt`](../../.cursor/rules/15-deletion-and-debt.mdc) says not
to take on. **The invariant is then satisfied by construction — the list is
empty — rather than by a migration whose correctness would itself need
gating.**

**Conceded:** one cold bootstrap at upgrade, on the existing and already-tested
path. The discovery data that reclassification would have preserved is
re-acquired from seeds in the ordinary way.

**This is a persisted-state semantic change, so it takes a version-constant bump
under [`42-serialization-policy`](../../.cursor/rules/42-serialization-policy.mdc)** —
without one, an upgraded node cannot distinguish a pre-fix store from a post-fix
one, and the reclassification has no trigger to fire on. **P2P-3 owns the bump
and the migration; the rule is stated here because it is a property of the
invariant, not of the implementation.**

**The fourth row was missing from the first version of this table, and its
absence is the sharpest evidence for §1's third check that this round
produced.** The check's own operational form says *enumerate the asset's writers
and show each is covered* — **the enumeration is the load-bearing half** — and
the first enumeration listed four of five. The reviewer found the fifth by doing
exactly what the form prescribes. A rule stated over an asset is only as good as
the writer inventory behind it, and an inventory is a claim that must be
re-derived from the tree, never recalled.

**Ruling on the operator-configured writer: exempt, and the exemption is
narrow.** `--add-peer` entries are inserted by the node's **own operator, from
local configuration, before the network exists** — there is no remote party in
the path, so this writer is not a channel any adversary can reach, and the
invariant's purpose (deny a *remote* party the ability to insert itself) is
untouched. Requiring an outbound handshake first would also break the bootstrap
case the flag exists for. **The exemption is scoped to locally-configured input
and must not be widened to anything network-derived** — an operator-supplied
address is trusted because the operator supplied it, not because it was
supplied out-of-band.

**The rule is not a new mechanism — the tree already implements it on the gray
path, and that is the evidence this reroute costs nothing.**
`gray_peerlist_housekeeping` (`net_node.inl:3108-3138`, `once_a_time_seconds<60>`
at `net_node.h:621`) draws a random gray peer, **dials it**, and promotes to
white via `set_peer_just_seen` only if that outbound handshake succeeds —
evicting it from gray if it fails. So a back-ping-verified inbound peer keeps
its whole route to white-list membership; **only the free pass is removed**, and
it is replaced by the verification every other candidate already passes. A
back-ping proves *reachability*, which qualifies a peer for the **dial pool**,
not for the trusted list.

**Gray needs no equivalent change, and this was checked rather than assumed.**
`append_with_peer_gray` has **exactly one caller**, `merge_peerlist`
(`net_peerlist.h:246-256`) — the ingestion path the first rule already covers.
The asymmetry was real and confined to the white list.

**Conceded — this reroute has a real cost on the producer side, and an earlier
version of this paragraph understated it with a bound that is not one.**
Disclosure samples the white list only (`get_peerlist_head`), so a node
reachable *only* inbound stops being advertised to third parties until some peer
draws it from gray and dials it successfully.

That paragraph said the latency is "bounded by the housekeeping cadence — one
random draw per zone per 60 s — not open-ended." **The cadence bounds how often
*a* draw happens, not how long *a given entry* waits, and the difference is
large.** `get_random_gray_peer` selects uniformly at random from the gray list,
so for a list of `G` entries the wait for any particular entry is geometric with
`p = 1/G`: **expected `G` draws, i.e. `G` minutes — about 83 hours at the
`P2P_LOCAL_GRAY_PEERLIST_LIMIT` of 5,000 — with no upper bound at all.** And
`gray_peerlist_housekeeping` can skip a cycle entirely: it returns early when
`m_offline` or when `m_exclusive_peers` is non-empty, and `continue`s per zone
when the payload handler needs new sync connections or the zone has no
connector. **Producer-side latency is therefore unbounded, and is conceded as
unbounded.**

**This does not change the ruling, and the reason is asymmetry of consequence.**
The cost falls on *advertisement* of a node that is reachable only inbound; the
benefit is denying an adversary the ability to place itself in a victim's white
list at will. A slow-to-be-advertised honest listener is a liveness
inconvenience that resolves itself on the first successful outbound dial from
anyone; a freely-writable white list is an eclipse primitive. **Cluster B should
consider a prioritised gray draw for back-ping-verified entries** — it would
recover most of the latency without weakening the invariant, since the promotion
would still require the outbound dial. Recorded as input to PWD-B1, not decided
here.

**Zone scope:** this writer is `zone.m_can_pingback`-gated, so the defect and
the fix are **public-zone only**.

**This is a behavioural change to inherited code, not a documentation
correction**, and it changes white/gray composition and therefore dial
composition after a restart. **PWD-I4's sub-round must derive against the fixed
behaviour, not the current one** — the anchor finding recorded there means
persisted anchors yield one connection and the remainder refills from ordinary
draws, so white/gray composition is more load-bearing for the eclipse posture
than it appeared when that sub-round was scoped.

**The per-connection ceiling, derived rather than picked.** A cap without a
value is not a decision, and the security claim depends on the value: a ceiling
of 1000 still lets one connection cycle the entire white list.

> **One connection may contribute at most `P2P_DEFAULT_PEERS_IN_HANDSHAKE`
> (250) accepted records in total, counted across handshake *and* timed-sync
> for the lifetime of that connection.**

**The derivation this ceiling first carried was wrong, and the tree refutes it
directly.** It argued that 250 is already *the most a peer may disclose in one
message* and that **"a second disclosure from the same peer adds no discovery
value the first could not have supplied"** — the same peer's view, re-sent. Two
mechanisms make that false:

- **`get_peerlist_head` re-samples the whole white list on every call.** With
  `anonymize` set it takes `pick_depth = m_peers_white.size()`, shuffles with
  `crypto::random_device`, then resizes to `depth`
  (`net_peerlist.h:294-330`). Each call is a **fresh random 250-subset of up to
  1,000 entries**, not a repeat of the first.
- **Timed-sync explicitly filters what it already sent** —
  `if (!context.sent_addresses.insert(pe.adr).second) continue;`
  (`net_node.inl:2674-2681`). The protocol deliberately makes later responses
  carry *new* addresses, which is the opposite of the premise, and its existence
  is evidence the original designers expected repeat disclosures to be
  informative.

So a peer can honestly contribute up to its **whole white list** — 1,000 records
across four messages — and capping at 250 for the connection's lifetime **costs
real discovery**: at most a quarter of any one peer's view.

**The ceiling is kept, restated honestly as a policy choice with its cost
named.** 250 is the security-relevant quantity because it is the point beyond
which additional records are *amortisation over a single connection*, which is
precisely Shi §III-A's mechanism; the value **inherits the existing per-message
constant instead of minting a new one**, so it cannot drift away from the
per-message cap. What it is *not* is free: it trades a quarter-view of each peer
for a 20-connection floor on filling the graylist. **The steady-state discovery
cost is the falsifier's subject below**, and if a fleet run shows cold-start
discovery degrading past that trigger, the ceiling is the parameter to move.

Against the attack: the graylist holds 5000, so filling it **by peerlist
ingestion** now costs **20 distinct connections** rather than one connection
sending repeatedly — and each must be separately established, which is the cost
the paper's attack was designed to avoid paying.

**This ceiling does not price the white list, and an earlier version of this
paragraph claimed it did** — it read *"filling either now costs 4 and 20
distinct connections respectively."* The 4 was arithmetic on the wrong channel:
1000 ÷ 250. **Sub-attack ② inserts no peerlist records**, so no per-connection
record ceiling binds it; its cost is set by the *third* rule above, and it is
**1,000 distinct IPs each completing an outbound dial we chose to make** — not
250 records × 4 connections. The figure is corrected rather than recomputed
because the quantity it counted was never the one that bounds ②.

**Conceded.** Topology mapping by a patient participant. PW-3a's discoverability
leg means an adversary can enumerate candidates regardless; these changes raise
the *cost and rate*, and do not claim to close it. **The ceiling bounds
amortisation per connection; it does not bound an adversary willing to be
dialled many times.**

**And an earlier version named the wrong mechanism as that bound — the third
instance of this PR's own defect class, found by a reviewer applying §1's third
check to a paragraph I had only applied it to the *adopted rules*.** It said
"that is `has_too_many_connections`' job." That guard cannot do this job, in
three independent ways, all verified:

1. It counts **only `cntxt.m_is_income`** connections (`net_node.inl:3083-3104`).
2. Its **sole caller** is `is_host_limit` (`:241`), the **inbound admission**
   path — it is never consulted on an outbound dial.
3. It returns `false` immediately for any non-public zone (*"Unable to determine
   how many connections from host"*), which is PWC-E11's public-zone-only note.

**Under this decision's own corrected rules the adversary opens no inbound
connection at all** — records are accepted only on connections *we* initiate, so
the traffic that matters never passes the guard; and because the guard counts
**concurrent** connections, even sequential inbound reconnects from one host
reset the per-connection ceiling without ever tripping it. **A countermeasure
named for the residual, facing the opposite direction from the residual.**

**The real bound is outbound selection frequency**, which is a different lane's
question: how often the adversary can get itself drawn from white/gray and
dialled. **Routed to cluster B as a named mechanism rather than a named guard** —
PWD-B1 (rate limiting, currently absent) and the outbound churn/selection
decisions own it. This is a route with an owner and a mechanism, not a deferral:
if cluster B cannot bound outbound re-selection, this concession becomes an open
residual and PWD-I6's ② closure is re-argued.

**Falsifier.** Accepting records only on outbound-initiated connections, and
capping accepted records per connection, are expected to leave peer discovery
viable at the deployed out-degree. **Reopen if a fleet run shows median
time-to-`MIN_PROVISIONED_OUT_PEERS` on a cold node exceeding one hour** — the
Q12-D6a rig is the instrument.

**The threshold is absolute, and an earlier version made it a ratio it could not
resolve.** It read *"exceeding the current figure by more than 2×"* while never
stating the current figure, and Q12-D6a defines no such baseline — so a future
reader could not recognise the trigger without re-deriving the decision, which
is precisely what §0's fourth requirement forbids. **A ratio against an
unrecorded baseline is not a falsifier**; it reads like one because it contains a
number.

One hour is grounded in the **user-facing** failure rather than in a benchmark,
which is what makes it statable without a measurement: a node that cannot reach
its outbound floor within an hour of a cold start is a defect under
[`82-failure-mode-ux`](../../.cursor/rules/82-failure-mode-ux.mdc) *whatever*
the previous code did. **When Q12-D6a next runs it should record the measured
baseline**, at which point a tighter ratio trigger can replace this ceiling —
but the ceiling stands on its own until then, rather than deferring to a figure
that does not exist.

### PWD-I3 — tenure is recognised by address, never serialized, and ordered by `first_seen`

**RULED**, and it ratifies what the tree already does rather than inventing a
mechanism.

- **Recognition key is the address.** Outbound continuity already matches on
  `peer.adr == cntxt.m_remote_address`, with `peer_id` only a secondary
  public-zone check (PWC-D6) — **and that secondary check disappears entirely
  under PWD-I1's amendment**, which strengthens this ruling rather than
  disturbing it: continuity was already address-keyed, and removing the
  identifier leaves the address as the sole key it already effectively was. The address family was ruled out as an *admission*
  basis (§6.10 — absent on Tor, lying on clearnet); it is **not** ruled out as
  *continuity bookkeeping*, and those are different jobs.
- **Nothing about tenure reaches the wire** (PW-18). The anchor list is
  persisted and its KV map is never sent (PWC-D5).
- **`first_seen` is an ordering input, not a log value** — it is the container's
  `by_time` index, and `get_and_empty_anchor_peerlist` drains through it while
  the dial loop stops at the first success. **It therefore decides which anchor
  is tried first, and — given the dial path yields at most one anchor-backed
  connection (PWD-I4) — effectively which single anchor is kept.** An earlier
  draft said "which anchors take the two slots"; that inherited the 2-slot
  premise the same review withdrew.

| Option | Adversary / channel it answers | Verdict |
| --- | --- | --- |
| **Recognise tenure by address (`peer.adr`)** — status quo | The re-rolling adversary that discards an identity to shed a bad record, over reconnection | **Adopted.** It is the only candidate that survives a restart, which is the whole job: tenure that resets on reconnect is not tenure. Costs what §6.10 already concedes — absent on Tor, cheap to rotate on clearnet |
| Recognise by `peer_id` | The same adversary | **Refused.** `peer_id` is per-process random and never persisted (PWC-D4), so it cannot recognise anything *across* restarts — it would silently degrade to session-scoped bookkeeping while reading as tenure |
| Mint a durable node identity for tenure | Sybil-resistance-by-identity | **Refused — PW-19a**, and PW-20 records that `peer_id` was never a Sybil defence. It is an enumeration key; §1's first check disposes of it without costing |
| Carry no tenure at all | — | **Refused.** Anchors are the anti-eclipse seed: a node with no memory of who it trusted refills entirely from the current peerlist, which is the state Shi §III-C engineers |

**The constraint this decision must not lose (`DAEMON_RELAY_PRIVACY.md` §39, F-8).** `forget`-on-close
resets tallies at **connection** granularity, so the convergence condition is
`warm-up ≪ mean outbound connection lifetime` — strictly stronger than the
process-uptime form, and it subsumes it. Its consequence is sharper still: *an
adversary clears its record by reconnecting rather than by minting an
identity*, and **"if anchors give a standing re-dial claim, reconnection is
nearly free and the defence is nearly nothing."** Any tenure scheme that pins on
address while leaving re-dial free is therefore self-defeating.

**Conceded.** The persistence double-edge (§7): a pinned honest peer is the
defence, a pinned adversary is durable. Pinning resists *active re-rolling*; it
does nothing structural against a patient peer that behaved well enough to get
pinned — the §6.9 concession, not a new caveat.

**A finding recorded here but owned elsewhere — and it is *conditional*, which
an earlier draft of this paragraph got wrong.** The re-entry-cost half of
§12.10's two bounds is **transport-sensitive**: §33.5 states that *"on an
anonymity network key-minting is free, so that wait is the entire cost"*, and
F-8 shows the adversary reconnects rather than mints. So on Tor, both halves of
re-entry cost tend toward zero.

**What this does and does not follow from.** The **transport** default is ruled
(PW-3a: Tor recommended and installed) and **does not** by itself put the
network on Tor — a node with Tor installed and default-on still runs a clearnet
zone; that is dual-network, and its clearnet peers retain a non-free identity
cost. The effect would become *total* only under a **Tor-only propagation-graph
default** — and **that option has now been declined** (Rick, 2026-09-01,
recorded at `DAEMON_RELAY_PRIVACY.md` §91.2): the graph stays flexible and
N-ary, clearnet *and* Tor *and* I2P. An earlier draft here wrote "defaulting
the network onto Tor" as though the graph default had moved; it never did.

**This was a cost of the declined option, and the decline resolves it.** It
was recorded as the **second cost** of moving the graph default, beside that
section's own quantified first cost — `F′` process-wide at the worst zone,
`ANON_ZONE_TRANSIT_ASSUMPTION_MS = 1625` against clearnet's `50`, with no
clearnet graph to take the *min* over. With the graph left flexible, the
weakness **stops being network-wide and becomes per-zone**: clearnet retains
whatever re-entry cost address-keyed tenure provides. **PWD-I4's sub-round
therefore reasons about both regimes rather than being handed the worst one**,
which is a materially easier problem than the one this paragraph first
described. **No decision in this cluster reasons from it.**

**Falsifier.** **Reopen if measured mean outbound connection lifetime falls
below the warm-up any admission mechanism requires** — F-8's own condition,
already stated as a comparison a measurement can settle.

### PWD-I4 — `ρ` / `g_max`: **DEFERRED to its own round, with the blocker named**

**NOT RULED.** Deferred under
[`22-no-lazy-deferral`](../../.cursor/rules/22-no-lazy-deferral.mdc), which
requires a named blocker rather than a decision postponed for convenience.

**The blocker is the owning document's own assessment, not this round's
reluctance.** §7 calls Q-10 *"a real blocker (its own grounding, likely its own
design round)"*, and the relay document's ledger calls it **"the single largest
blocker in this document"** — it gates `ρ`, §12.11's selection tier, the
cooldown/eviction threshold and `ε_explore`. §7 also hands this round the test
that decides the matter: ***"a bound that depends on a parameter owned further
down is not a bound — it is a lower bound wearing a costume"***, and warns the
seal may move again to address-manager behaviour or seed-node trust.

**Why deferring is cheap here, which is why it is honest rather than evasive.**
`g_max` is a **node-local selection-layer policy parameter** — not a wire
quantity, not consensus, **not genesis-frozen**. A node can change its
outbound-selection discipline without anyone's agreement, so this does not fork
the chain and carries no genesis deadline. That is a materially different
deferral from anything with a freeze date.

**What the sub-round inherits, so it does not restart cold:**

- **Its first task is a re-location, not a derivation.** §7 names the churn
  coupling as the non-obvious constraint and cites `dandelionpp.cpp:144,160` —
  **that file no longer exists**; the logic is in
  `rust/shekyl-relay-privacy/src/conformance/selection.rs`.
- **The load-bearing question — and the answer is NOT the one the constants
  suggest.** An earlier draft here recorded "2 of 12 outbound slots are
  anchor-backed" from `ANCHOR_CONNECTIONS_COUNT = 2` against
  `P2P_DEFAULT_OUT_PEERS = 12`. **That figure is withdrawn: it does not survive
  reading the dial path.** Traced at the pin:
  `get_and_empty_anchor_peerlist` (`net_peerlist.h:504-522`) copies **every**
  persisted anchor into a caller-local vector and then **clears the
  container**; `make_new_connection_from_anchor_peerlist`
  (`net_node.inl:1438-1470`) `return true`s after the **first** successful
  dial; and only that one peer is re-inserted, by `append_with_peer_anchor` at
  `net_node.inl:1361` on successful handshake. The rest of the local vector
  goes out of scope. **So on a cold restart the node gets *at most* one
  anchor-backed connection — zero if every persisted anchor fails to
  handshake — and every other persisted anchor is silently destroyed either
  way**, because the container was cleared before any dial was attempted — the second loop iteration sees only the peer it just connected
  to, `is_peer_used` is true, and the loop ends.

  The anchor set does regrow, because every successful outbound connect calls
  the same re-insertion — but that means **post-restart "anchors" are mostly
  fresh draws, not the persisted trusted set the defence assumes.** §7's
  question was *"how much of the origin's stem-eligible outbound is
  anchor-backed versus fresh-drawable"*, and the honest answer is **at most 1
  of 12 at restart, decaying to a set repopulated from ordinary draws** — not
  2. The sub-round must **measure this rather than inherit a constant**; a
  bound of the form §7 wants (*"≥ k slots are anchor-backed and thus not
  re-rollable"*) has `k = 1` at best, and the pool it draws from is destroyed
  on first use.

  **Recorded as a defect of the inherited code, not a parameter choice.** It is
  the anti-eclipse defence being materially weaker than its constant advertises,
  which is precisely the direction that flatters the defence — and it was found
  only because a review challenged the figure rather than the reasoning.
- **Two documents describe complementary halves** — see PWD-I5.
- **The defence shape is pre-narrowed** (§6.10): behavioural floor plus
  guard-pinning; the address/subnet/ASN family is ruled out on both transports.
- **A design constraint, not a free property** (§6.10): the economic deterrent
  reaches the diffuse passive observer *only if stem-eligibility is gated on
  pinned tenure*.
- **The only `ρ` number in existence is disqualified** — a provisional `≈ 2 %`
  evaluated at `g = f`, which §13.5 calls *"a placeholder squared"*.
- **If persistence becomes a requirement, its bounding is part of the spec**
  (§33.6): bucketed counts rather than event logs, bounded retention, no peer
  identifiers at rest — specified *at the same time* as the requirement.
- **Two symbol collisions to pin before substituting numbers:** the D++ paper's
  `f` is the fraction supporting D++, not our adversary reach; its `d` is
  **total** degree, so `STEMS = 2` is `d = 4`.

**A second, independent reason the deferral is right — and one that did not
exist when it was taken.** If the eviction floor's re-entry-cost bound is
**transport-dependent** (§33.5: key-minting is free on an anonymity network;
F-8: the adversary reconnects rather than mints), then a `g_max` derived before
the default-transport question settles would be **derived against the wrong
transport**. Both postures are now settled — the **transport** default is Tor
(PW-3a) and the **propagation graph** stays flexible and N-ary (§91.2, ruled
2026-09-01) — so the sub-round inherits a *stable* target. What it must carry
is that re-entry cost is now a **per-zone** quantity rather than a single
network-wide one, and both regimes have to be reasoned about.

**An obligation the sub-round inherits from that, to be argued rather than
assumed.** §6.10 deters *"the budget-constrained passive observer, by
economics"* and explicitly does **not** defend against the unconstrained one.
If Tor drives re-entry cost toward zero, **the economic deterrent is precisely
the thing that evaporates.** The sub-round must state plainly whether the
eviction floor retains *any* cost term on Tor, or whether it degrades to pure
behavioural exclusion with no whitewash penalty. §54.4(a)'s *"inert →
degraded"* softening is why that is survivable rather than fatal — but it is a
survivability argument that must be **made**, not inherited.

**Reopening criterion (this is the deferral's falsifier).** The sub-round opens
when the parameter-ownership question is settled — i.e. when it can be shown
that `g_max` does **not** depend on address-manager behaviour or seed-node
trust, or those are brought into scope. **If a later cluster produces a decision
that depends on a numeric `g_max`, that dependency is itself a finding and this
deferral is void.**

### PWD-I5 — the Q-10 write-back *obligation* is specified now; its discharge is gated on PWD-I4

**RULED** as an obligation on whoever closes Q-10, discharging PW-26's
requirement that the document declaring a dependency records its discharge —
*"do not let this be a one-way read."*

**What is ruled here is the obligation and its content, not the write-back.**
An earlier heading read as though the closure had happened; it has not, and it
cannot yet. `DAEMON_RELAY_PRIVACY.md:37-40` still records `ρ` as
*underspecified, blocked on Q-10*, and **PWD-I4 defers `g_max`** — so the
discharge is gated on that sub-round. This PR's edit to that document resolves
the propagation-graph question in §91, which is a different open item.

**It is nonetheless ruled rather than deferred with PWD-I4, deliberately.** The
reconciliation below is decidable *now* and is exactly what a later closer would
otherwise have to rediscover — reading either source alone specifies the wrong
thing, silently. Deferring the obligation with the number would put the
reconciliation in the same box as the thing it exists to protect.

| Option | Adversary / channel it answers | Verdict |
| --- | --- | --- |
| **Specify the obligation and its reconciliation now; gate discharge on PWD-I4** | Not an adversary — the failure mode is a **silent mis-specification** by a future closer reading one source of two | **Adopted.** The reconciliation is decidable today and is exactly what would otherwise be rediscovered, in a case where either source alone specifies the wrong thing *without erroring* |
| Defer the whole row with PWD-I4 | The same | **Refused.** It files the reconciliation in the same box as the number the reconciliation exists to protect — the closer who needs it is the one who would not receive it |
| Record only "write the closure back", content unspecified | The same | **Refused — this is the PW-26 failure verbatim**, a dependency declared in one direction and never discharged: *"do not let this be a one-way read."* An obligation with no content is not one |

**The closure must carry this reconciliation, because reading either source
alone specifies the wrong thing and both failures are silent:**

- **§12.10** reframes the deliverable *away* from a pool-share `g`: *"bounding
  pool-share `g` was bounding the wrong quantity"*, replacing it with two
  bounds — eviction responsiveness × re-entry cost, and eclipse-resistance as
  conscription cost.
- **§7** says Q-10 terminates on **one number**, `g_max` = the *sustained,
  churn-resilient* outbound-selection share, with the chain
  `ρ ← δ ← W3(g)+W3c(g) ← g_max`.

**They reconcile: §7's `g_max` is precisely §12.10's *full-eclipse* regime —
the one regime of three where pool-share survives.** Observation is out of
scope and partial disruption is backstop-dissolved. A round reading only §12.10
would decline to specify `g_max` at all; a round reading only §7 would specify a
pool-share `g` across all three regimes.

**Two further staleness hazards the closure must not step in:**

1. **§12.11's body is superseded in part.** The Exploit tier is D++ §4.5
   version-checking, which the paper **tests and rejects** — at low `β` it
   *"actually increases the likelihood of getting deanonymized."* The live
   mechanism is **uniform random selection over the non-cooled admissible set;
   reputation gates admission, it never orders the draw** (§54.1). Consequently
   **`ε` has disappeared as a parameter** and the ossification finding is *moot
   rather than mitigated* — a closure that derives `ε_explore` is deriving a
   parameter that no longer exists.
2. **`ρ` is not mentioned in §12.10 at all**; its canonical statement is §13.5.
   And §13.5's own scope narrowing applies: after §14, *"the only `δ` left to
   price is the W3 residual."*

**Falsifier.** **Reopen if the relay lane rules that §12.10's two bounds
replace `g_max` rather than containing it** — that would falsify the
reconciliation above, and it is a ruling a future reader can recognise.

### PWD-I6 — the Shi et al. graylist and whitelist sub-attacks are closed by PWD-I2

**RULED — absorbed, not separately specified.** The census established that
sub-attack ③'s two arms are already answered (private-transaction arm
structurally inapplicable since RT-9 removed `--public-node`; D++ arm refused
because a double-spend is a no-drop offense), while **sub-attacks ① and ②
remained unaddressed**. **PWD-I2's three adopted rules close both** — its
outbound-only *acceptance* rule and per-connection ceiling remove the
graylist-filling channel at the point the attack actually uses, and its
**white-list writer invariant** removes ②'s channel.

**Correction — this row previously closed ② by the wrong rule, and contradicted
its own table doing it.** It said the per-connection ceiling "removes the
amortisation the whitelist attack needs." **Sub-attack ② needs no
amortisation**: it inserts itself once per IP over an inbound connection and
sends no peerlist record, so a ceiling counted in *records* never binds it. The
contradiction was visible **inside this row** — the disposition table below
**deferred** *PWC-D11, the back-ping gate to the white list*, to cluster B while
the prose closed ②, and PWC-D11 is precisely ②'s channel. **That table now rules
PWC-D11's destination**, which is what removed the contradiction; this paragraph
records the state it corrected, in the past tense, and the table is the current
disposition. A row cannot close a sub-attack while
deferring the mechanism that sub-attack uses. PWD-I2's third rule is what closes
it, and PWC-D11's disposition changes accordingly.

**No option table, and that is the honest disposition rather than an omission.**
The brief requires a wargame table per decision because a decision has an option
space; **this row makes no independent choice.** Its content is entirely *"are
sub-attacks ① and ② closed by rules ruled elsewhere, and which ones"* — a
verification, not a selection. The options, adversaries and verdicts live in
PWD-I2's table, which is where a reader must go to argue with them; reproducing
them here would be the restatement this row's next paragraph exists to forbid,
and would create a second copy to drift. **The one thing this row does decide —
that the closure is real — is falsifiable below.**

**This row points at those rules rather than restating them, deliberately.**
Prose restating a contract is a defect generator, and this sentence proved it:
an earlier version paraphrased PWD-I2, then survived the correction that turned
that rule from sender-side to receiver-side, leaving the word "disclosure"
stranded in a sentence that no longer parsed — **in the row a later reader would
use to decide whether ① is closed.** The rule is stated once, in PWD-I2; if the
two ever disagree, PWD-I2 is the contract and this is the stale copy.

**One residue is *not* closed and is recorded rather than absorbed.** The
double-spend no-drop guard is **inherited** — `f7fd209ed`, upstream Monero,
2024-03-07 — and carries the census's `inherited-defensive` class: it works, and
no Shekyl record has examined it. **A rewrite that re-derives the tx-ingest path
from the census would drop it silently.** Cluster B owns that as PWD-B7.

**Falsifier — one per sub-attack, because the two are now closed by different
rules and a single trigger would test only one of them.** The paper's own attack
is the test in both cases, and the Q12-D6a rig can run it.

- **①** — **Reopen if a fleet run reproduces graylist saturation under the
  outbound-only-acceptance rule.**
- **②** — **Reopen if a fleet run shows an inbound-only adversary occupying
  white-list entries under the white-list writer invariant.** The measured
  quantity is *white-list entries held by **network-derived** peers this node
  never dialled*, whose target value is **zero**: the invariant makes any
  non-zero reading a defect, not a threshold judgement. **"Network-derived" is
  load-bearing and excludes the two permitted non-dial paths** — operator
  `--add-peer` entries, which are placed in white before this node dials them,
  and not-yet-reclassified entries on a pre-bump store. Without that scoping the
  metric would report a violation for any fleet using `--add-peer`, i.e. it
  would falsify the ruling on nodes that are conforming to it.

**A third falsifier, on the producer side — and it exists because the reason
first given for omitting it was false.** PWD-I2's own falsifier measures the
**consumer** side — a cold node's time to `MIN_PROVISIONED_OUT_PEERS` — while
the reroute's conceded cost is on the **producer** side, where an inbound-only
listener waits to be advertised. An earlier version of this note declined to
extend the instrument on the grounds that producer-side latency was
*"analytically bounded by the 60 s housekeeping cadence."* **It is not bounded
at all**: the cadence governs how often *a* random draw occurs, not how long a
*given* gray entry waits, which is geometric with `p = 1/G` — expected `G`
minutes, ~83 hours at the 5,000 cap — and the housekeeping can skip cycles
entirely (PWD-I2 carries the derivation and the early-return conditions).

- **Producer side** — **Reopen if a fleet run shows median time-to-first-
  advertisement for an inbound-only reachable node exceeding one hour**, measured
  as the interval from its first accepted inbound handshake to its first
  appearance in a third party's disclosed peerlist. The Q12-D6a rig is the
  instrument. **This trigger is expected to fire**, which is why it is written as
  a measurement rather than a hope: cluster B's prioritised-gray-draw option is
  the intended remedy, and this falsifier is what tells it how much latency there
  is to recover.

---

## 3. Cluster I disposition — the census rows this cluster accounts for

Ten bucket-4 `PWC-D` rows. **Ruled / absorbed / deferred must sum to 10.**

| Row | Disposition | Where |
| --- | --- | --- |
| PWC-D1 (250-entry disclosure) | **Absorbed** | PWD-I2 |
| PWC-D2 (anonymised head) | **Ruled** — kept unchanged; it is a real defence, and PWD-I2 restricts *acceptance* rather than disclosure, so nothing in this cluster constrains it | PWD-I2 |
| PWC-D3 (1000/5000 caps) | **Absorbed** | PWD-I2 (the per-connection cap is the fix; the list caps are not) |
| PWC-D4 (`peer_id` per-process random) | **Ruled — and the verdict was reversed on amendment**: the field is removed from the wire entirely, not kept-but-ephemeral. An internal identifier is retained, never serialized | PWD-I1 |
| PWC-D5 (anchor keys; `first_seen` ordering) | **Ruled** | PWD-I3 |
| PWC-D6 (address-keyed continuity) | **Ruled** | PWD-I3 |
| PWC-D8 (dual-stack field parity structurally tested only) | **Deferred — named blocker: LV-3.** It is a *test-coverage* gap on the Rust/C++ parity surface, not an identity commitment; it lands when the read side migrates | LV-3 |
| PWC-D9 (`sanitize_peerlist` IPv4-only port-0) | **Deferred — named blocker: tor port-0 semantics disputed** (`tor_address::unknown()` is port 0), named as such by #587 rather than invented here | cluster B |
| PWC-D10 (cross-zone peerlist refusal) | **Ruled** — kept unchanged | PWD-I2 |
| PWC-D11 (back-ping gate to white list) | **Ruled — and the mechanism is now deleted, which supersedes the split this row first recorded.** PWD-I2 ruled the gate's *destination* (gray, not white); PWD-I1's consumer inventory then showed the gate's only job was the whitelist promotion PWD-I2 had just forbidden, so **the back-ping and `COMMAND_PING` are deleted** rather than retained-and-redirected. **PWD-B10** carries the deletion. *An earlier version of this cell left retention "still cluster B's" beside the deletion, giving two verdicts at once; deletion is the single outcome.* | PWD-I1, PWD-I2 → PWD-B10 |

**Sum check: 6 ruled + 2 absorbed + 2 deferred = 10.** ✅ *(PWC-D11 moved
deferred → ruled when the white-list writer invariant was adopted; the count of
rows is unchanged.)*
*(PWC-D11 moved absorbed → deferred in review: PWD-I1 leaves the back-ping to
cluster B, so PWD-I2 could not have absorbed it. The total is unchanged; the
claim about what this cluster ruled is not.)*

**PWC-D7** is bucket-2 (ratified by #587) and is excluded from the bucket-4
accounting, as are all `PWC-X` rows.

**Running total against the round's gate:** 10 of **46** bucket-4 rows
dispositioned. Clusters T (~16), B (~20) and A remain.

---

## 4. What cluster I does not decide

- **`ρ` / `g_max`** — PWD-I4, deferred with the blocker named.
- **~~Whether `peer_id` is deleted outright~~ — DECIDED 2026-09-02 by PWD-I1's
  amendment: it is removed from the wire.** This line previously deferred it to
  cluster B *"once self-detection and the back-ping have their own answers"* —
  the enumeration showed that ordering was backwards. Neither replacement needed
  the identifier to be settled first; each of the four jobs was answerable on its
  own, and it was the **deferral** that made the field look load-bearing. What
  genuinely remains with cluster B is the two replacements, now owned by named
  rows: **PWD-B9** (same-host outbound cap) and **PWD-B10** (the back-ping).
- **The inherited double-spend no-drop guard** — cluster B, PWD-B7.
- **Anything about the transport itself** — cluster T.

**Carried forward to cluster B, so it is inherited rather than re-derived.**
PWD-I2's per-connection cap turned on a defect class worth naming: *250 records
per message with no per-connection ceiling caps the wrong quantity*, because the
attack amortises across messages. **PWD-B1's rate limits face exactly that
question** — a limit that bounds per-message volume while the adversary's budget
is per-connection or per-epoch is a limit on the wrong variable, and it will
measure green while the attack runs. Check each proposed limit against the
quantity the adversary actually spends.

**Also carried forward: `network_config` is a dead struct, not one dead
constant** (PWC-F3 records the map; this is the fields). Enumerated at the pin,
**four of its eight fields are write-only** — their only occurrence outside the
struct definition is the assignment itself at `net_node.h:387-392`:
`handshake_interval`, `packet_max_size`, `config_id`, `send_peerlist_sz`. The
other four have real readers (`max_out_connection_count` 17,
`max_in_connection_count` 5, `ping_connection_timeout` 2, `connection_timeout`
2), so this is a **partial cleanup, not a whole-struct delete.**

Two things make it worse than ordinary dead weight, and both belong in the row:

- **Three of the five fields the KV map serializes are among the dead four**
  (`handshake_interval`, `packet_max_size`, `config_id`). The map that *looks
  like* a wire commitment is majority dead, which is exactly the review-cost
  hazard the census exists to price.
- **Two of the dead fields are dead *copies of live constants*, which makes
  them traps rather than merely inert.** The 60-second cadence is driven by
  `once_a_time_seconds<P2P_DEFAULT_HANDSHAKE_INTERVAL>` (`net_node.h:618`) — a
  **template argument from the constant**, not from the field — and
  `send_peerlist_sz`'s value is read directly from
  `P2P_DEFAULT_PEERS_IN_HANDSHAKE` at `net_node.inl:2655`. So an engineer who
  changed the cadence by editing `m_net_config.handshake_interval` would
  observe **no behavioural change and no compiler complaint**. A dead field
  holding a stale duplicate of a live value is worse than an empty one.

`config_id` is the provenance tell: an identifier for *which config set is in
force* only makes sense if configs are exchanged, and that machinery is not
wired here. What remains is the vocabulary of a negotiation that does not
happen.
