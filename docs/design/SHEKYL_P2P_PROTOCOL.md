# Shekyl P2P protocol — normative specification

**Status:** OPEN — **P2P-2 design round; cluster I (identity and Sybil
resistance) ratified and merged (#594); cluster T (transport) delivered for
ratification; clusters B and A not yet drafted.** Produced by the P2P-2
design round dispatched on
[`P2P_2_DISPATCH_BRIEF.md`](P2P_2_DISPATCH_BRIEF.md). Ratification is Rick's,
**per cluster**, on the relay-round convention; the umbrella chat reviews each
package first. **Nothing here is implemented — implementation is P2P-3.**

**Pinned:** `dev` @ `47bfa66c33000249b1402a4bb104ae20ab68b757`
(`git ls-remote origin dev`, 2026-09-01). Papers corpus at `shekyl-dev`
`4cabe8ef2`. Every claim below was read at these pins.

**Identifier family:** `PWD-` (P2P wire decision), registered at birth in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md).

**Section-reference convention.** `§N` **with no document named** is a section
of **this** document. A section of another document is always named —
`DAEMON_RELAY_PRIVACY.md §12.10`, `the census §5.2`, `the brief §3`. *Where a
bare `§6.x`/`§7`/`§12.x`/`§13.x`/`§33.x`/`§54.x`/`§91.x` appears in cluster I's
prose it is `DAEMON_RELAY_PRIVACY.md`'s* — those numbers do not exist here, and
this line is the resolution for a reader who arrives at a section directly
rather than reading forward.

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
- **`PER_BLOCK_CHECKPOINT`** was default-on (`set(PER_BLOCK_CHECKPOINT 1)`
  at its pin), but every consumer guarded on
  `blockchain_height < m_blocks_hash_check.size()` — with an empty hash corpus
  the fast check never fired, so the defence was compiled in and inert.
  *(The check's verdict was terminal: C2-R1a deleted the whole mechanism
  2026-09-02 — an inert inherited defence is not kept, it is ruled on.)*

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

**The check has three rungs, not two, and the third is the strongest** (named
2026-09-02 after its third instance):

> **Prefer a *binding* that makes the lie impossible to a *check* that detects
> it.**

- **Worst — accept the claim and verify it.** Verification needs identity;
  identity is forbidden; so every such mechanism grows a guard, and the guard
  grows a guard. `peer_id` + `is_same_host` is the shape.
- **Better — replace it with your own observation.** Nothing is claimed, so
  nothing can be forged: the **same-host cap** (no value exists to spoof) and
  the **`handshake_complete` flag** (this node watched its own handshake
  finish).
- **Best — when the value *must* come from the peer, bind it into the
  transcript** so a false one cannot produce a working session.
  **`network_id` as a Noise prologue** is the instance: today the peer asserts a
  UUID and we compare it (`net_node.inl:1085`, `:2691`); mixed into the
  handshake hash instead, a wrong network **fails to decrypt on the side that
  receives an authenticated field**. The check is not passed — it is
  *unnecessary*.

> **The rung is directional, and PWD-T1 pays for saying so.** A binding only
> removes the check on the side that verifies something authenticated under it.
> In `NN` that is the initiator alone: message 1 carries no keyed field, so the
> responder learns nothing from the prologue and needs a separate,
> non-cryptographic answer (PWD-T5's prefix). **"A binding replaces the check"
> is true per direction, never per protocol** — ask which side verifies, at
> which message, before claiming the check is gone.

**Why the third rung is worth separating from the second.** An observation
removes the peer from the loop, which is not always possible — some values are
irreducibly the peer's. A binding keeps the value on the wire and removes the
*lie* instead, converting a comparison anyone can pass into a computation only a
conforming peer can complete. **On the verifying side it also deletes the error
path**: there is no "wrong network" branch to get wrong, only a handshake that
does not complete.

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
why it is the one most easily skipped.

> **Sixth check — when a decision is already taken, both the argument for it
> and the argument against the alternative drift toward flattering it.**
>
> Named after PWD-T5, where the same eight bytes were mispriced **twice, from
> opposite sides**: PW-9 would have deleted the prefix for an anonymity
> property we cannot have, and T5's first draft kept it for a
> resource-exhaustion property it cannot have either. **The second error
> appeared inside the correction of the first.** The bias has a direction, and
> it does not care which way the argument runs — an overstated *hazard*
> justifies a ruling exactly as an overstated *benefit* does (PWD-B3a's first
> draft called an unknown command "unbounded" when the packet limit still
> bound it).
>
> **Mechanical form: name the adversary the property holds against, then ask
> whether an adaptive one is excluded by construction.** A value derived from
> public data cannot impose attacker work — that is a **non-property**, not a
> mitigation with a weak constant, and the two demand different responses:
> a weak constant invites tuning, a non-property demands re-routing.
>
> **It survives review because each argument is locally well-formed.** T5's
> first draft cited a real consumer at a real line and drew a plausible
> conclusion; nothing in the sentence was false, only its scope. So the check
> cannot be "read it again" — it has to be the question above, asked against
> the row's own adversary column.

**The seventh check — *a `file:line` citation has a dependency the diff does
not show, so it is verified after the merge or not at all*.** (Rick,
2026-09-04, naming it the third instance of the fifth check's family.)

> **A conflict-free merge proves the two branches did not edit the same lines.
> It proves nothing about whether one branch moved lines the other points at.**

**The instance:** C2-R1b's fork-choice work shifted `blockchain.cpp`, and
PWD-B3's citation for `m_current_block_cumul_weight_limit` — the whole argument
that a block cap cannot be static — came to point at unrelated code. **Neither
side of the merge had edited the citing document.** The symbol survived, so the
*claim* held and only the pointer broke, which is the failure mode that looks
like nothing: nothing turns red, and the citation still resolves to a real line
in a real file.

**So the ordering is the mechanism, not the diligence.** Verifying citations
*before* merging verifies an artifact that will not ship. Re-run them on the
**merged** tree, and check them **by content** — that the cited line contains
the symbol the claim rests on — because line-in-range is what a drifted
citation still satisfies. Where a citation is load-bearing, name the symbol
beside the line so the next drift is greppable rather than silent.

> **This is the fifth check's family, one artifact over.** There the frontier
> of an *enumeration* was narrower than the claim built on it; here the
> frontier of a *verification* is — it covered the pre-merge tree while the
> claim is about the merged one. Same shape in citations, in coverage
> inventories, and in sum checks, which is why they are stated together: **the
> frontier of a check is narrower than the claim it is taken to support.**

**Rider, because the pattern has now recurred inside its own fixes three
times:** correcting referring text tends to reproduce the defect in the
correction. A cell advertising 2026-09-04 currency against a 2026-09-03
verification is a stale-currency defect *inside the fix for a stale-currency
defect*; a sum check corrected from 9 to 8 kept a total that was already wrong;
a retired concept survived in the paragraph that retired it. **After correcting
a claim, re-read the correction as if it were the original text** — it is
subject to the same class it just repaired.

---


## 2. Cluster I — identity and Sybil resistance

Delivered first because **PWD-I5's cross-document obligation is scoped against
the relay lane**, so it carries the longest external latency and should run in
parallel with the remaining clusters rather than after them. *(It is the
**obligation** that is scoped there; there is no closure yet — the write-back is
gated on PWD-I4. An earlier wording said "closure", which is where PWD-I5's own
heading drifted from: the ordering rationale was written before the row's scope
was settled, and then the row was named to match the argument.)* (The *disposition* load runs
the other way — **cluster B carries all 28 remaining bucket-4 rows** to cluster
I's 10, because cluster A's only row cites `PWC-X5`, and `PWC-X` records carry
no bucket — so this ordering is about latency, not volume. *Corrected from
"~20" on 2026-09-03, with cluster A's zero verified rather than assumed.*)

### PWD-I1 — no peer identifier on the wire at all; the four jobs it served are replaced

**RULED — and amended 2026-09-02, reversing this row's original verdict.** The
transport carries **no peer identity, durable or ephemeral**: the specified
`basic_node_data` **has no `peer_id` field**, and `peerlist_entry` and
`anchor_peerlist_entry` **have no `id` field**.

> **Tense, deliberately: this row specifies a wire, it does not report one.**
> An earlier wording said the fields *"are removed"*, which is operation voice
> and reads as executed — and at the time of ratification the tree still carried
> every one of them (`p2p_protocol_defs.h:176`). **The rulings are landed; the
> wire is not yet changed.** P2P-3 performs the removals; the document's
> **status banner** (above §0) says so once, and this row says it again because
> a reader can arrive here directly.

**`m_peer_id` is removed entirely, and an earlier version of this ruling was
wrong to keep it.** It said a per-process identifier is *"retained internally for
connection tracking and rotation"*; **the tree does not support that.** Every
use is accounted for: generation (`net_node.inl:147`), the four self-comparisons
(`:1114`, `:1213`, `:1238`, `:2720`), wire emission (`:2153`), anonymity-zone
self-insertion into the gossiped list (`:2670`), the ping echo (`:2792`, deleted
with the back-ping), and a getter whose own comment says it exists *"so the
invariant in `init` has something a test can observe"* (`:2983`). **Connection
tracking already runs on `m_connection_id`** — 18 uses in `net_node.inl`. Once
the jobs below are replaced there is **no consumer left**, so retaining it would
instruct P2P-3 to preserve dead identity state: the `inherited-defensive`
failure committed forward rather than inherited.

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
| **6** | `net_node.inl:1636`, `:1688-1691` | **Outbound retry set** — `make_new_connection_from_peerlist` keys `tried_peers` on `peer.id` so a failed candidate is not re-tried within a pass | **Replaced by an address-keyed retry set.** The address is what a dial targets; the id was standing in for it |
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

**Job 5's consumers cross a subsystem boundary, and the first enumeration of it
stopped at the p2p layer.** `for_each_connection` (`net_node.inl:155-160`)
forwards `cntx.peer_id` as a **parameter** into every cryptonote-layer callback,
and two of them read it as the same boolean:

- `cryptonote_protocol_handler.inl:1725` — `if (!peer_id || context.m_is_income)`,
  excluding pre-handshake peers from **sync-search**.
- `:2659-2660` — `if (peer_id && …)`, excluding them from **fluffy-block relay**,
  with the tree's own comment: *"peer_id also filters out connections before
  handshake"*.

**With the field gone both read zero and exclude *every* peer** — sync-search and
block relay stop network-wide, in a subsystem the identity sweep never touched.
So the replacement is **not** merely a local flag: **`for_each_connection`'s
signature carries the value across the p2p/cryptonote boundary**, and migrating
job 5 means changing that signature to pass `handshake_complete` (or having the
callbacks read it from the context). P2P-3 owns the signature change; it is
named here because a local-flag ruling alone would not have implied it.

**Job 6 was found in the same review as job 5, on a third frontier: outbound
selection.** `tried_peers` is a set of `peerid_type`; with the field gone it has
no key and the loop would re-try a failed candidate in the same pass. **Its
replacement is the fourth check again** — the address is what a dial targets, so
keying the set on it is both the fix and the more honest expression of what the
set was always doing.

Jobs 1–4 are public-zone-gated; **jobs 5 and 6 are not** — they run on every
zone, so their replacements are not optional on any of them.

**Six jobs, found across four sweeps, and the rising count was itself the
record.** Identity, connection-state, outbound-selection and persisted-schema
are four different frontiers; each sweep saw one and could not see the next.

#### The complete inventory, enumerated by *type* rather than by name

**The count stopped rising when the sweep changed shape.** Every previous sweep
searched for the *name* `peer_id`; this one enumerates every declaration of the
**type** `peerid_type`, which is what carried the value across a subsystem
boundary invisibly. It is recorded here so a later reader can check completeness
instead of re-deriving it, and so P2P-3 has one list rather than six findings.

**Structs declaring it — five, all accounted for:**

| Declaration | Disposition |
| --- | --- |
| `peerlist_entry_base.id` (`p2p_protocol_defs.h:73`) | **Removed** — gossiped and persisted |
| `anchor_peerlist_entry_base.id` (`:97`) | **Removed** — persisted; PWD-I3 makes anchors address-keyed |
| `connection_entry_base.id` (`:118`) | **Already dead** — PWC-F2, zero callers tree-wide since `68ba2887c` (2020); dies with the dead-struct deletion, not with this decision |
| `basic_node_data.peer_id` (`:176`) | **Removed** — the wire field |
| `COMMAND_PING::response.peer_id` (`:283`) | **Removed with the command** (PWD-B10) |

**The cross-subsystem vector is an interface, not a function.**
`for_each_connection` and `for_connection` are declared on **`i_p2p_endpoint`**
(`net_node_common.h:65-66`, with the null implementation at `:103,107`), so the
`peerid_type` parameter is part of the **p2p↔cryptonote contract**. That is why
a sweep inside `net_node.inl` could not see the consumers.

**Consumers reached through it — 22 callbacks take the parameter; *three* read
it:**

| Site | Kind | Disposition |
| --- | --- | --- |
| `cryptonote_protocol_handler.inl:1723` | **Boolean** — excludes pre-handshake peers from sync-search | Migrate to `handshake_complete` |
| `:2657-2660` | **Boolean** — same, for fluffy-block relay (*"peer_id also filters out connections before handshake"*) | Migrate to `handshake_complete` |
| `:347` | **Display** — `print_connections`' peer column | Drop the column or show `connection_id` |
| `rpc_facts_ffi.h:315` / `.cpp:1050-1056` | **Display** — `get_connections` over RPC | Same: `connection_id` is already in the struct |

**The other 19 callbacks accept the parameter and ignore it**, which is the
useful part of the count: the interface change is largely mechanical, and the
parameter was already vestigial at most call sites. **P2P-3 changes the
`i_p2p_endpoint` signature once**; the three readers above are the only bodies
that need thought. **On anonymity zones the identifier does no work
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
- **The same-host cap costs a legitimate multi-node host.** Honest nodes sharing
  an IP compete for one per-host allowance, so at a cap of `1` two of them
  together receive a single outbound slot from any given peer. **The concession
  scales with whatever value PWD-B9 sets; it is stated against the invariant,
  not against a number this row does not own.** Real, small, and the same
  concession the white list already makes silently via
  `evict_host_from_peerlist`.
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
  the bound is the same one an adversary gets. **What cluster I rules is that the bound
  exists and is keyed on the address; the numeric cap is PWD-B9's, informed by
  PWD-I4's eclipse bound.** An earlier draft stated the cap four different ways
  across this document — fixed at one slot in the concession above, deferred to
  PWD-I4 here, assigned to PWD-B9 in the routing table, and called both "ruled"
  and "not decided here" in PWD-I2 — leaving P2P-3 with no unambiguous number.
  **One invariant, ruled here; one value, owned by PWD-B9.**
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
- **`anchor_peerlist_entry.id` is persisted too, and also loses its source**
  (`p2p_protocol_defs.h:97,102,108` — in both the KV map and the binary
  serializer), populated from the handshake id at `net_node.inl:1358` and read by
  the anchor overload of `is_peer_used`. **Removed with the others**, which
  PWD-I3 already makes safe: anchor recognition is address-keyed and *"nothing
  about tenure reaches the wire"*. An earlier sweep named only
  `peerlist_entry.id` — **persisted schema is the fourth frontier, and it was
  swept last.**
- **`peerlist_entry.id` is persisted**, so its removal is a stored-format change.
  It rides **the same rule-42 version bump** as PWD-I2's store reset —
  **one bump, and no migration on either side of it**, since the bump drops the
  store rather than converting it. That is what makes carrying both changes on
  one bump free: neither needs a reader for the old schema.

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
one and the drop has no trigger to fire on. **P2P-3 owns the bump. There is no
migration to own** — the bump *is* the operation, and its effect is a wholesale
reset of the persisted peerlist. The rule is stated here because it is a
property of the invariant, not of the implementation.

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

**The deletion of the back-ping creates a new gray writer, and it must be
bounded in this decision rather than downstream.** With the back-ping gone an
inbound peer's advertised `my_port` is unverified until housekeeping dials it,
and **gray is keyed by full address including port** with **no same-host
eviction** — `append_with_peer_gray` (`net_peerlist.h:398-427`) has none, unlike
`append_with_peer_white`. So one IP could reconnect with varying ports and fill
all 5,000 gray entries **without sending a single peerlist record**, bypassing
both rules above and falsifying PWD-I6.

> **Ruled here, value included: a host holds at most *one* gray entry, the same
> bound `evict_host_from_peerlist` already enforces on the white list.**

**These are two different quantities, and an earlier draft conflated them.**
*List occupancy per host* is settled here at **1**, by **inheriting the white
list's existing behaviour** rather than minting a number — the same derivation
discipline as the 250 ceiling above. *Outbound connection slots per host* is a
different bound, and **that** is the one PWD-B9 owns and PWD-I4 informs.

**Why 1 is the right occupancy value and not a placeholder.** Under the outbound
same-host cap only one entry per host can ever be *dialled*, so holding N entries
for one host is amplifier surface with **no discovery value** — the extra entries
can never become connections. Inheriting white's bound also means the two lists
cannot drift apart, and it settles the number this closure depends on: **a cap
without a value is not a decision**, and PWD-I6's ② closure would otherwise rest
on one.

**This closes a gap that predates the deletion rather than one the deletion
invented** — gray has always been unbounded per host, including via the
peerlist-record path; the reroute merely makes it reachable without records.
Bounding occupancy is preferred to re-introducing reachability validation
(which is the back-ping) because it is **address-based and local**: §1's fourth
check, and it needs nothing from the peer. **The two rules above bound records
per connection; this one bounds *entries per host*, which is the quantity the
record cap never constrained.**

**The promotion rule is not a new mechanism — the tree already implements it on
the gray path, and that is the evidence this reroute costs nothing.** *(The
**occupancy** bound above is new: P2P-3 adds `handle_handshake` as a second gray
writer and must add the per-host bound with it. What follows describes only the
existing promotion path, and is not a claim that the gray path needs no
change.)*
`gray_peerlist_housekeeping` (`net_node.inl:3108-3138`, `once_a_time_seconds<60>`
at `net_node.h:621`) draws a random gray peer, **dials it**, and promotes to
white via `set_peer_just_seen` only if that outbound handshake succeeds —
evicting it from gray if it fails. So an inbound peer keeps its whole route to
white-list membership; **only the free pass is removed**, and it is replaced by
the verification every other candidate already passes.

**Under the final ruling the peer is not verified at all when it enters gray** —
PWD-B10 deletes the back-ping, so its advertised port stands unchecked until
housekeeping dials it. That is the correct place for the check: **the outbound
dial is the verification**, and doing it lazily costs one failed dial where the
back-ping cost a whole extra connection and round trip to learn the same thing
eagerly. What qualifies a peer for the **dial pool** is being a candidate; what
qualifies it for the trusted list is a dial *we* made and *we* watched succeed.

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
consider an **oldest-first gray draw** in place of the uniform random one.**

**An earlier version proposed prioritising "back-ping-verified" entries, and
that class will not exist** once PWD-B10 deletes the back-ping; prioritising
*directly-inserted inbound* entries instead would prioritise exactly the
attacker-controlled unverified ports the occupancy bound above exists to
contain. **A remedy keyed on any signal the peer influences is an amplifier, not
a fix.**

Oldest-first uses **only local state** — insertion order, which no peer can
forge — and converts the unbounded geometric wait into a bounded FIFO one, since
housekeeping evicts an entry whose dial fails and the queue therefore drains.
Combined with the per-host occupancy bound, a flooder cannot hold the head of
the queue either. Recorded as input to **PWD-B1/PWD-B9**, which own the draw order and the cap's
value respectively. *(The per-host **invariant** is ruled above; only its number
and the draw order remain open.)*

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

> **One connection may contribute at most `P2P_MAX_PEERS_IN_HANDSHAKE`
> (250) accepted records in total, counted across handshake *and* timed-sync
> for the lifetime of that connection.**

**The constant is the *acceptance* one, and an earlier version named the
producer's.** `handle_remote_peerlist` enforces the per-message limit with
`P2P_MAX_PEERS_IN_HANDSHAKE` (`net_node.inl:2123`), while
`P2P_DEFAULT_PEERS_IN_HANDSHAKE` is what *this node discloses*
(`get_peerlist_head`'s depth, `send_peerlist_sz`). **They are both 250 today and
are independent constants** (`cryptonote_config.h:186-187`), so a ceiling
inheriting the producer default would silently stop matching the acceptance cap
the moment either moved. **If both survive the rewrite, a gate must assert they
are equal** — otherwise the inheritance this ceiling relies on is a coincidence,
not a derivation.

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
  basis (§6.10); it is **not** ruled out as *continuity bookkeeping*, and those
  are different jobs.

  **§6.10's "absent on Tor" does not apply to this mechanism, and an earlier
  draft repeated it here as though it did.** That phrase is about *inbound*
  anonymity peers, which carry `tor_address::unknown()`. Continuity here is
  **outbound** — this node chose the onion, so it has a perfectly good address
  key. The real concession on Tor is the one §33.5 and F-8 already state and
  which the rest of this row is built on: **onion keys are cheap to mint and the
  adversary reconnects rather than mints**, so the key exists but its
  *re-entry cost* tends to zero. Saying the key is absent would have made the
  mechanism look inapplicable when it is applicable and merely cheap to evade.
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

### PWD-I4 — `ρ` / `g_max`: **DEFERRED to its own round, with the blocker named, and scheduled**

> **Rule 22 requires three things, not one: the blocker, a target, and the
> reopening criterion.** An earlier version of this row named only the blocker.
> **Target: pre-genesis**, queued as its own `FOLLOWUPS.md` item so the deferral
> is tracked outside the document that made it — *"no genesis deadline" is not a
> schedule*. The sub-round must derive against the **fixed** anchor and
> white/gray behaviour (PWD-I1, PWD-I2), not the current tree.

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

**Conceded — and the shape of the concession is unusual, which is why it was
missing.** This row specifies the content of a closure it **cannot perform**,
so its correctness is not verifiable until Q-10 actually closes: the
reconciliation below is *this round's reading* of §12.10 and §7, and a reading
is exactly the thing that can be wrong. **If it is wrong, it is wrong in the
most expensive place** — handed forward as settled ground to a sub-round that
will not re-derive it, which is the failure this row exists to prevent,
arriving through the row itself. The mitigation is that both sources are
quoted verbatim rather than paraphrased, so a later closer can check the
reading against the text rather than trusting it.

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

**Conceded — this row's correctness is entirely borrowed.** It verifies rather
than selects, so it inherits PWD-I2's option space *and PWD-I2's risk*: if I2's
three rules are implemented **partially** — the acceptance rule without the
per-connection ceiling, say, or the white-list writer invariant without the
per-host gray bound — then ① or ② is open again and **this row still reads
closed**, because nothing in it observes the implementation. A verification row
cannot detect a partial implementation of the thing it verifies. That is the
price of pointing rather than restating, and it is worth paying for the reasons
the next paragraph gives — but it is a price, and PWD-B10's and PWD-B9's
FOLLOWUPS rows are where it is actually paid.

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
  and nothing else — an earlier version also exempted "not-yet-reclassified
  entries on a pre-bump store", which **cannot exist** now that the bump drops
  the store wholesale, and which would have made the falsifier appear to
  tolerate network-derived white entries the design says are impossible. Without
  the operator scoping the
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
| PWC-D4 (`peer_id` per-process random) | **Ruled — verdict reversed on amendment, twice.** The field is removed from the wire entirely, not kept-but-ephemeral; and `m_peer_id` itself is **removed**, not retained internally, because the enumeration found no non-wire consumer — connection tracking already runs on `m_connection_id` | PWD-I1 |
| PWC-D5 (anchor keys; `first_seen` ordering) | **Ruled** | PWD-I3 |
| PWC-D6 (address-keyed continuity) | **Ruled** | PWD-I3 |
| PWC-D8 (dual-stack field parity structurally tested only) | **Deferred — named blocker: LV-3.** It is a *test-coverage* gap on the Rust/C++ parity surface, not an identity commitment; it lands when the read side migrates | LV-3 |
| PWC-D9 (`sanitize_peerlist` IPv4-only port-0) | **Deferred — named blocker: tor port-0 semantics disputed** (`tor_address::unknown()` is port 0), named as such by #587 rather than invented here. **Owner: PWD-B11**, a row minted for it because "cluster B" is not an owner; target pre-genesis, queued in FOLLOWUPS | PWD-B11 |
| PWC-D10 (cross-zone peerlist refusal) | **Ruled** — kept unchanged | PWD-I2 |
| PWC-D11 (back-ping gate to white list) | **Ruled — and the mechanism is now deleted, which supersedes the split this row first recorded.** PWD-I2 ruled the gate's *destination* (gray, not white); PWD-I1's consumer inventory then showed the gate's only job was the whitelist promotion PWD-I2 had just forbidden, so **the back-ping and `COMMAND_PING` are deleted** rather than retained-and-redirected. **PWD-B10** carries the deletion. *An earlier version of this cell left retention "still cluster B's" beside the deletion, giving two verdicts at once; deletion is the single outcome.* | PWD-I1, PWD-I2 → PWD-B10 |

**Sum check: 6 ruled + 2 absorbed + 2 deferred = 10.** ✅

*Row-movement history, kept as history rather than as a second disposition:*
PWC-D11 began **deferred**, moved to **ruled** when PWD-I2's white-list writer
invariant was adopted, and is now ruled **via PWD-B10's deletion** of the
back-ping — the mechanism it asked about no longer exists. The row count never
changed. The table above is the disposition; this note is only how it got there.
*(PWC-D11 moved absorbed → deferred in review: PWD-I1 leaves the back-ping to
cluster B, so PWD-I2 could not have absorbed it. The total is unchanged; the
claim about what this cluster ruled is not.)*

**PWC-D7** is bucket-2 (ratified by #587) and is excluded from the bucket-4
accounting, as are all `PWC-X` rows.

**Running total as of cluster T:** **18 of 46** bucket-4 rows dispositioned —
cluster I's 10 plus cluster T's 8. **This is a historical figure; the
authoritative running total is the one at the end of the most recent
sub-round.** Two live totals in one document is how the off-by-one below went
unseen, so only one of them is ever current. As of cluster T, 28 rows remained
for cluster B — enumerated, not estimated: `PWC-A6`, `PWC-A6a`, `PWC-A7`, `PWC-B1`, `PWC-B2`, `PWC-B4`, `PWC-B5`,
`PWC-B6`, `PWC-B7`, `PWC-C1`, `PWC-C3`, `PWC-C5`, `PWC-C6`, `PWC-C7`,
`PWC-C8`, `PWC-E1`, `PWC-E2`, `PWC-E3`, `PWC-E4`, `PWC-E4a`, `PWC-E5`,
`PWC-E7`, `PWC-E8`, `PWC-E9`, `PWC-E11`, `PWC-E13`, `PWC-E14`, `PWC-F4`.

> **Corrected 2026-09-03, from 19.** The old figure inherited cluster T's
> off-by-one. The remainder is now **listed** rather than given as "~20",
> because a count with no enumeration behind it cannot be checked by a reader —
> and the two independent derivations (46 minus the dispositioned rows, and the
> census's own bucket-4 set) agree on these 28.

---

## 3.5 Cluster T — the transport, concretely

**Eight decisions.** Where cluster I removed things from the wire, T specifies
what replaces the framing they lived in. **This section is normative**: P2P-3
implements from it, so it is written in state voice ("the handshake is…") and
swept for stranded phrasing before first review rather than after — §1's fifth
check applied to the artifact class where a stale sentence is *implemented*
rather than merely read.

### PWD-T1 — the handshake is `Noise_NNhfs_25519+MLKEM768_ChaChaPoly_BLAKE2s`

**RULED.**

```
Noise_NNhfs:
  -> e, e1
  <- e, ee, ekem1
```

#### Wire sizes, term by term

**An earlier version gave 1216 and 1120 and was wrong in both**: it counted
tokens and omitted the AEAD tags Noise adds once a key exists, and omitted the
self-detection nonce this same row requires. **PWD-T6 turns these into hard
receive limits and PWD-T8 into KAT lengths, so an incomplete figure here is a
specification that rejects and mis-tests its own handshake.** The brief already
had it right — *"the second roughly `e` + `ekem1` + **tag**"*.

**The composition rule is Noise's, stated so each term is checkable rather than
asserted:** `EncryptAndHash` **only hashes** while no key is established, and
**encrypts and appends a 16-byte Poly1305 tag** once one is. In `NNhfs` the key
appears at `ee`, in message 2.

| Message 1 (initiator → responder) | Bytes |
| --- | --- |
| `e` — X25519 ephemeral, plaintext | 32 |
| `e1` — ML-KEM-768 encapsulation key (`ML_KEM_768_EK_LEN`), plaintext | 1184 |
| payload — the **self-detection nonce `N`** (below), plaintext: no key yet, so **no tag** | 32 |
| **total** | **1248** |

| Message 2 (responder → initiator) | Bytes |
| --- | --- |
| `e` — X25519 ephemeral, plaintext (written before `ee`) | 32 |
| `ekem1` — ML-KEM-768 ciphertext (`ML_KEM_768_CT_LEN`), **encrypted after `ee`** | 1088 |
| `ekem1` AEAD tag | 16 |
| empty payload, encrypted — tag only | 16 |
| **total** | **1152** |

Both totals are **sums of named terms derived from our own constants**
(`shekyl-crypto-pq/src/kem.rs:24,30`), never quoted from a benchmark — PW-3's
correction history is exactly why the terms are shown rather than the totals
alone. **A reader who disagrees with a total can now say which term is wrong**,
and PWD-T8's vector 1 pins both.

> **These three rows move together: the token layout here, PWD-T6's
> pre-handshake limit, and PWD-T8's vector 1. Changing any one without the
> others produces a node that rejects its own handshake.**

#### The prologue's byte encoding

`MixHash` consumes bytes, so a normative wire contract must say *which* bytes.

> **The prologue is exactly the 16 raw bytes of `network_id`, in RFC-4122 field
> order as stored. No length prefix, no delimiter, no text encoding.**

Without this, two conforming implementations can share a network id and derive
**different transcript hashes** — and the failure is the one PWD-T8's vector 3
makes indistinguishable from an attack, so it would present as "the other node
is on a different network" with no way to tell a bug from a stranger.

**Chaining-key derivation, and the order is the hybrid claim.** `ck` is
initialised from the protocol name, then:

1. `MixHash(prologue)` — **the prologue is `network_id`** (see below).
2. `MixKey(ECDH(e, re))` — the classical secret.
3. `MixKey(ML-KEM-768 shared secret)` — the post-quantum secret.

**Both are mixed, in that order, and the order is not cosmetic.** A session is
secure if *either* primitive holds: an adversary breaking X25519 (a CRQC) still
faces ML-KEM, and one breaking ML-KEM still faces X25519. **Mixing ECDH first
means the KEM secret is folded into a chaining key that already depends on the
classical exchange**, so a passive recorder cannot precompute against the KEM
alone. This is the `00-mission` hybrid-PQC commitment expressed in a transcript.

| Option | Adversary / channel | Verdict |
| --- | --- | --- |
| **`NNhfs` — ephemeral-only, hybrid** | The non-participant path observer (§1.5); a CRQC harvesting today for tomorrow | **Adopted.** `NN` is entailed by PW-19a: no static keys exist to authenticate with. `hfs` puts the KEM in the *same* handshake rather than a later upgrade, which is what "PQC from genesis" means |
| `NN` classical-only, PQC later | The same | **Refused — `00-mission` §1.** Harvest-now-decrypt-later is not a future threat for a chain whose traffic is archived by design |
| `XX`/`IK` with static keys | Would answer peer authentication | **Inapplicable, not declined** (§1.2). The `K`/`X` pre-messages assume the parties are not strangers; on open gossip they are |
| KEM-only, no ECDH | A CRQC | **Refused.** It trades a well-understood primitive for a young one and loses the hybrid property in the direction we are least able to re-fix later |

**The prologue carries `network_id`, and this is the third rung of §1's fourth
check — on the initiator's side only.** Today the peer *asserts* a UUID and the
node compares it at **two** sites: `net_node.inl:1085` (outbound, on the
response) and `:2691` (inbound, in `handle_handshake`). The prologue replaces
the **first**. The field leaves `basic_node_data` with the others.

> **The responder gets no key confirmation from `NN`, so the prologue cannot
> reject on its side. An earlier version of this row claimed it could.**

**Why, term by term, because the conclusion is not obvious from "it is bound":**
`MixHash(prologue)` moves `h` and **not `ck`**; `Split()` is `HKDF(ck, zerolen)`
and does not read `h`. So two nodes with **different** network ids derive
**identical transport keys** and differ only in `h`, which enters solely as AEAD
associated data during the handshake. Message 1 in `NN` carries no keyed field
(the key first exists at `ee`, in message 2), so:

- the **initiator** fails at message 2's first encrypted field, `ekem1`, whose
  tag was computed under the responder's `h`. It aborts. ✅
- the **responder** completes, `Split()`s, and has no failing operation to
  observe — now or later, because the transport keys match. ❌

**So the two-sided property is preserved by layering, not by the prologue
alone**, and the layers answer different adversaries:

| Layer | Side | Rejects | Against |
| --- | --- | --- | --- |
| **PWD-T5's 8-byte prefix, derived from `network_id`** | **Responder**, at byte 8, before the flight | A wrong-network peer that sends its own network's prefix | **Honest misconfiguration.** Unauthenticated and rewritable in transit — it is a filter, not a proof |
| **The prologue, bound into `h`** | **Initiator**, at message 2 | A response computed under a different network id | **The on-path rewriter.** Even if the prefix is corrected in flight, the honest initiator still aborts |

**That is the argument for keeping both**, and it is why PWD-T5's prefix is not
merely a cost optimisation — see the second job named there.

**Conceded, and it is capability-free.** An initiator that deliberately sends
the *correct* prefix with a *wrong* prologue holds a working session the
responder cannot distinguish. It gains nothing: `network_id` is public, so the
same party could simply use the right prologue and be indistinguishable from a
legitimate peer. The state is reachable and gainless, which is why it is
conceded rather than closed.

**And this is what `handshake_complete` means on each side.** The responder sets
it at `Split()`. An honest wrong-network peer never reaches that point — the
prefix rejected it eight bytes in. The deliberate divergent-`h` peer does reach
it, and is the conceded case above. Slot occupancy by peers that send a
well-formed flight and then nothing is **not** this row's — it is PWD-B1's rate
limiting and PWD-B9's per-host caps, where every unauthenticated-buffering
question is routed.

| Option | Adversary / channel | Verdict |
| --- | --- | --- |
| **Prologue (initiator-side) layered over PWD-T5's network-derived prefix (responder-side)** | Honest misconfiguration on both sides; an on-path rewriter against the initiator | **Adopted.** Two-sided coverage at zero additional wire bytes and zero additional round trips, reusing a mechanism this cluster already rules |
| Add a third flight, or defer responder completion to a key-confirming record | Would give the responder authenticated network identity | **Refused on cost against a gainless state.** It charges every honest connection a round trip — the one thing a p2p handshake budget cannot absorb at the Pi-4 floor (rule 76) — to close a case an adversary has no reason to enter. Deferring completion to the first transport record does not even work: those records decrypt correctly under a mismatched prologue |
| Bind `network_id` into the **key schedule** rather than the transcript hash — a network-qualified protocol name, or `MixKeyAndHash` | The same, cryptographically | **Refused, but safe — record it as the retreat.** It would make transport keys diverge by network, giving the responder a genuine failure. It is refused because a network-qualified protocol name breaks the Noise name form that PW-7a's read-not-depend posture assumes a future implementer can parse, and `psk`-style mixing changes message 1's token rules and therefore PWD-T1's byte tables. **Reopen this option, not the third flight, if the concession above ever stops being gainless** |
| Keep the inherited two-sided equality comparison | The same | **Refused.** It is a claim compared against a claim (§1's fourth check, worst rung), and it keeps a wire field for a property two cheaper mechanisms already hold |

**Falsifier — narrow, because the concession is what would break.** **Reopen if
any feature binds semantics to the handshake hash `h` or to a session value
exported from it** — channel binding, a session-scoped commitment, anything that
gives the divergent-`h` state a consequence — **or if responder-side
*authenticated* network identity is ever required.** Either event turns a
gainless reachable state into a capability, and the key-schedule option above is
the prepared answer.

**The self-detection nonce, inherited as a requirement from PWD-I1.** A random
`N` is emitted in message 1; a handshake arriving with an `N` this node recently
emitted **is** this node.

**"Recently" is not a duration, and specifying it as one would be the defect.**
A window shorter than a handshake round trip silently permits a self-edge, and
PWD-I1's falsifier says what that costs: an undetected self-connection is an
eligible stem candidate, so at `STEMS = 2` it halves effective stem width. A
number chosen for that window would be a guess whose failure is invisible.
**Scope the nonce to its outbound attempt instead:**

> **A nonce is inserted into its zone's set immediately before message 1 is
> written, and removed when that outbound attempt terminates — handshake
> complete, failed, or timed out — or when it matches, whichever comes first.**

**This covers detection by construction rather than by timing, and the reason is
an ordering property.** A self-connection is **one TCP connection**: this node's
outbound arm is the client and its own inbound listener is the server. The
responder must *read* message 1 to produce message 2, so **the inbound handler
sees `N` strictly before the outbound arm can complete.** There is no schedule
under which the attempt terminates first and the match is missed. The one edge
that looks like a race is benign: if the outbound times out while an inbound
read is still queued, the connection is already dead, and the stem-width hazard
needs a *live* edge.

**Two properties fall out, rather than needing rulings of their own.** The set
is bounded by in-flight outbound attempts, which `max_out_connection_count` and
the connect cadence already cap — so there is no size limit to choose and no
eviction policy to get wrong. And because `N` travels in the clear, **any peer
this node dials learns it**; attempt-scoped removal is what keeps the window in
which a dialed peer can replay `N` back at us equal to the attempt's own
lifetime, rather than to an arbitrary retention period. A within-zone replay
confirms only what the zone-scoping paragraph below already concedes.

> **`N` is 32 bytes of CSPRNG output, carried as message 1's payload, in the
> clear.**

**In the clear is correct, not a concession:** message 1 has no key yet, so
Noise cannot encrypt it, and `N` carries nothing secret — it is a value whose
*only* job is to be recognised by the node that emitted it. 32 bytes matches
`e`'s width so the flight introduces no novel field size, and makes collision
across any plausible emission window unreachable.

> **Nonce windows are per zone, and comparison is within-zone only.**

`handle_handshake:2719` already warns why: *"an attacker could connect to you on
clearnet and pass in a tor connection's peer id, and deduce the two are the same
if you reject it."* A nonce reproduces that oracle exactly unless zone-scoped —
**the drop is the confirmation.** On anonymity zones `m_our_address` comparison
(`net_node.inl:1291`, `:1697`) already answers self-detection without any wire
value, so the nonce is the clearnet mechanism specifically.

**Conceded.** Recently-emitted nonces are per-zone local state the identifier
did not need — small, bounded, and never on the wire, which is the direction
PW-18 wants. And `NN` gives **no peer authentication whatsoever**: the
counterparty is conceded (§1.5), and a MitM on a first contact is
indistinguishable from the peer. That is not a gap this transport can close
without prior knowledge, which PW-19a forbids.

**Falsifier — on stem width, not connection count, because the p2p symptom is
invisible.** An undetected self-connection is an eligible stem candidate
(`levin_notify.cpp:232-233` filters only on `!m_is_income` and height), and at
`STEMS = 2` a single self-edge halves effective stem width and leaves the
embargo to fire. **Reopen if measured effective stem width falls below `STEMS`
on a node whose connection count is nominal** — the relay lane's `stem_width()`
and `record_stem` are the instrument. A connection-count trigger would read
green throughout.

### PWD-T2 — PW-3 is retired; no padding band is pinned

**RULED — and this row deliberately does not re-derive anything.** PW-3 asked
for a padding band to hide handshake identity. **It is retired**, and the
argument is recorded rather than re-litigated:

- **The flight is already constant-size** — **1256 and 1160 bytes as an observer
  sees them**, from PWD-T1's 1248/1152 token layout plus PWD-T5's 8-byte prefix.
  This row is about what a *path observer* measures, so it must quote the wire
  totals and not the Noise-message ones. A band would relabel a constant.
- **Clearnet protocol identity is undefendable against active probing** (PW-3a).
  A passive defence cannot buy a property an active prober takes anyway.
- **Anonymity is Tor's** (§1.6), and Tor is the recommended and installed
  transport default.

**No option table, declared rather than omitted.** A retirement has no option
space: the question *"what padding band?"* is dissolved by the three facts
above, not answered by choosing among candidates. Manufacturing a table of
bands would imply one of them could be right. **The row that does carry an
option space is PWD-T5**, where the same eight bytes are decided on cost.

**Conceded, plainly:** on clearnet an observer learns that an IP speaks Shekyl.
That is a real disclosure, and PW-3a is the ruling that accepts it rather than
this row pretending otherwise.

**Falsifier.** **Reopen if the handshake ceases to be constant-size** — for
instance if a future token carries a variable-length field. The premise of the
retirement is the constancy, so the retirement dies with it.

### PWD-T3 — rekeying is BOLT-8-shaped: `ck', k' = HKDF(ck, k)`, per direction

**RULED**, carrying PW-8's ruling — **option (a)**, BOLT-8-style symmetric KDF
rotation — and the primary-source corrections that row records.

Each direction rekeys independently, deriving `ck', k' = HKDF(ck, k)` and
**resetting the nonce**; `sck` and `rck` are independent. **Zero bytes on the
wire**: both sides derive from state they already hold, so there is no rekey
message to forge, delay, or use as a marker.

**The interval is counted in *nonce increments*, not messages, and that
distinction is the correction PW-8 paid for at primary source.** BOLT-8 rotates
after **1,000 nonce increments**, which is **500 messages** in *its* framing
because each message there consumes two nonces — one for the encrypted length
prefix, one for the body. **The message-count equivalent is therefore a property
of our framing, not a number to copy**: a framing that spends one nonce per
message rotates at twice BOLT-8's message count for the same nonce budget.
Stating the interval in nonces makes it survive a framing change; stating it in
messages would silently halve or double the real budget when PWD-T6/PWD-B3 settle
the framing.

**Rotation inherits the hybrid-PQ root, which is why it does not weaken T1.**
Every rotated key descends from the ML-KEM-mixed `ck`, so harvest-now-decrypt-
later resistance and forward secrecy survive rotation rather than being reset by
it.

| Option | Adversary / channel | Verdict |
| --- | --- | --- |
| **Silent derived rekey, per direction** | A path observer correlating long-lived sessions; nonce exhaustion | **Adopted.** No wire event means no new observable and no new failure mode |
| Explicit rekey message | The same | **Refused.** It mints an observable that is *itself* a fingerprint, and an error path for a mechanism that cannot otherwise fail |
| No rekey | Nonce reuse under long sessions | **Refused.** Gossip sessions are long-lived by design; ChaChaPoly nonce space must not be a liveness limit |

**Conceded — and PCS is *ruled out on the merits*, not merely absent.** PW-8's
argument is stronger than "there is nothing to ratchet toward", and the ruling
rests on it: **PCS pays out only when an adversary obtains session keys, then
*loses* that capability, and the session still matters afterwards.** On an open
gossip network the dominant adversary never attacks the session at all — being a
peer is free, and every relay is a middle-man by construction, so stolen session
keys grant a view already available by dialling in. The adversary who *does*
hold keys (node owner, RCE, hypervisor) has **permanent** access, which PCS
cannot heal by definition. Recorded-ciphertext decryption is **forward secrecy's**
job, which option (a) provides. The property bought here is bounded key usage.

**Falsifier.** **Reopen if a session is specified that can outlive its rekey
interval without rekeying** — the interval's value is PWD-B3's, but the
mechanism's sufficiency is falsified by any such path existing.

### PWD-T4 — `e1` and `ekem1` are specified here, normatively

**RULED**, with `noise_hfs_spec` cited as **provenance only** — the semantics
are stated here so P2P-3 implements from this document rather than from a draft
that may move.

- **`e1` (initiator → responder, message 1, 1184 B)** carries the **ML-KEM-768
  encapsulation key** — the initiator's freshly generated KEM public key. It is
  hashed into the transcript when sent.
- **`ekem1` (responder → initiator, message 2, 1088 B)** carries the
  **ciphertext** produced by encapsulating to `e1`. The responder obtains the
  shared secret from encapsulation; the initiator obtains it by decapsulating
  with the private key it kept from message 1.
- **Mixing order is `ee` then the KEM secret**, per PWD-T1.
- **`e1` is written plaintext and hashed** — message 1 has no key, so
  `EncryptAndHash` degenerates to `MixHash`, and **no tag is emitted**.
- **`ekem1` is encrypted *and* hashed** — the key exists after `ee`, so
  `EncryptAndHash` applies in full and **appends a 16-byte Poly1305 tag**,
  which is a wire term and is counted in PWD-T1's message-2 total.
- **Transcript state**: each token is hashed **in the order written**, so
  message 2's hash covers `e` before `ekem1`'s ciphertext. **PWD-T8's vector 2
  pins the chaining key after each mix step precisely because this ordering is
  invisible in the message bytes** — two implementations can emit identical
  wire bytes and hold different transcript state.

| Option | Adversary / channel | Verdict |
| --- | --- | --- |
| **State the token semantics normatively here** | Not an adversary — the failure is a **silent implementation divergence** between two readings of a moving draft | **Adopted.** P2P-3 implements from a pinned document; `noise_hfs_spec` is provenance, not the contract |
| Incorporate `noise_hfs_spec` by reference | The same | **Refused.** The extension is unratified; a reference binds us to whatever it becomes, and the drift would be invisible until a KAT broke |
| Leave token layout to the implementation | The same | **Refused.** It is a wire format; leaving it out of the wire specification is where the swap below becomes possible |

**These are not interchangeable and the failure is silent if they are swapped.**
An implementation that sends the ciphertext where the encapsulation key belongs
produces a handshake that *completes* on one side and fails on the other, or —
worse with a lenient parser — completes with an unmixed secret. **Both lengths
are distinct (1184 vs 1088), so length is a usable discriminator in tests**, and
PWD-T8's vectors pin both directions.

**Conceded.** `hfs` is a Noise extension, not part of the ratified Noise spec.
That is a specification-stability risk, not a security one, and it is why the
semantics are written out here rather than incorporated by reference.

**Falsifier.** **Reopen if the `hfs` extension is ratified with different token
semantics** — a concrete, checkable future event.

### PWD-T5 — the 8-byte prefix stays, for two jobs, and neither is the fingerprint question PW-9 asked

**RULED**, and it **corrects PW-9's framing rather than answering its question.**

PW-9 (Survey A's L-1) priced `LEVIN_SIGNATURE` as a *scanning fingerprint* and
asked whether removing it was worth the anonymity gain. **Two things have moved
since.** PW-3a conceded that clearnet protocol identity is undefendable against
active probing, so removal buys less than that row assumed; and the prefix's
actual consumer was never named there — **epee compares the first 8 bytes as
they arrive, before a full header is buffered**
(`levin_protocol_handler_async.h:589,609`; `levin_protocol_handler.h:107,127`).
**That is cheap early rejection of unsolicited noise** — *not* a
resource-exhaustion defence, for the reason the concession below gives. PW-9 is
amended in the register accordingly.

**The prefix carries two jobs, and only the first was visible when this row was
first drafted:**

1. **Cheap rejection of non-adversarial noise** — port scanners, cross-protocol
   probes, misdirected clients, rejected at 8 bytes instead of at 1248 plus a
   decapsulation.
2. **Responder-side network separation.** PWD-T1's prologue binds `network_id`
   for the **initiator only**; `NN` gives the responder no key confirmation, so
   **this prefix is the responder's only network check.** It replaces the
   inbound half of the inherited comparison at `net_node.inl:2691`.

> **Job 2 is load-bearing, and job 1's falsifier must not be read as licence to
> delete the prefix.** If the measurement below fires, it retires the *cost*
> rationale; the network-separation job survives it and would have to be
> re-homed first. Deleting a mechanism because one of its jobs expired is the
> failure rule 16 names — enumerate the jobs, not the name.

**The derivation is pinned here, completely, because "derived from
`network_id`" is not a wire contract.** An earlier version of this row said
"the first 8 bytes of a domain-separated hash" and left the rest for
ratification. That is not a derivation — it names no function, no separator and
no output convention, so two conforming implementations can produce different
eight bytes and neither is wrong.

> **`prefix = cSHAKE256(S = "shekyl/p2p-wire-prefix-v1", X = network_id)[0..8]`**
>
> - **Function:** cSHAKE256 with customization, NIST SP 800-185 semantics.
>   Mechanism 1 in [`CRYPTO_DOMAIN_REGISTRY.tsv`](CRYPTO_DOMAIN_REGISTRY.tsv);
>   cSHAKE and not raw Keccak because the job is **separation**, not identity.
> - **Customization `S`:** the exact ASCII bytes `shekyl/p2p-wire-prefix-v1`,
>   no NUL, no length prefix — the registry's `shekyl/<thing>-v<n>` form.
> - **Input `X`:** the **16 raw `network_id` bytes, RFC-4122 field order as
>   stored** — the same bytes and the same order as the prologue, defined once
>   in *The prologue's byte encoding* above and not restated here.
> - **Output:** bytes `[0..8]` of the 32-byte digest, in digest order, no
>   re-ordering and no endian conversion.

**The three prefixes, computed rather than promised.** The `NETWORK_ID`
constants are frozen (`cryptonote_config.h:364`, `:496`, `:507`) and
`cshake256_32` exists in-tree, so this is a measurement:

| Network | `network_id` | Prefix |
| --- | --- | --- |
| mainnet | `556CA9708FF91F7A4069DAF3FC55BBBD` | `AFBCD4D1FAB98B6D` |
| testnet | `78CE055BBBDA7956B9C8A1A2EC1F7672` | `F0B352E8928F8D56` |
| stagenet | `2D219754A1BD79BA0540FDFB8DC8A4AE` | `5C2942C0F9F98A21` |

**Pairwise distinct — observed, not assumed.** Truncating a 32-byte digest to 8
bytes cannot *guarantee* distinctness by construction, so the claim "different
networks get different prefixes" is discharged by computing all three and
comparing them, with the comparison exercised against a known-identical pair so
it can be seen to fail. **P2P-3 carries this as a compile-time assertion over
the network table**, which is what keeps the property true if a `NETWORK_ID`
ever changes; **if one does pre-genesis, these three values re-derive** and
PWD-T8's vectors re-mint with them.

**The registry row is deliberately not added in this round.** The domain gate
requires a registered literal to have a defining file and a `const` site, and
P2P-2 implements nothing — a row now would fail CI for being honest about the
schedule. `shekyl/p2p-wire-prefix-v1` registers **at the P2P-3 call site**,
together with the mechanism-1 count-pin bump the gate requires; both halves are
in the FOLLOWUPS item so neither can be dropped as an implementation detail.

| Option | Adversary / channel | Verdict |
| --- | --- | --- |
| **Keep an 8-byte prefix, derived from `network_id`** | **Non-adversarial noise** — port scanners, cross-protocol probes, misdirected clients — **and, for job 2, honest cross-network dialling** | **Adopted, on those two only.** Rejection at 8 bytes rather than after a 1248-byte first flight and a KEM decapsulation, and the responder's network separation at the cheapest layer |
| Drop it; the fixed-size first flight is self-framing | The same | **Refused on cost, and now on job 2 as well.** A wrong prefix fails the initiator's AEAD anyway — but dropping it moves rejection of *unsolicited noise* from an 8-byte compare to a full flight plus asymmetric crypto, and leaves the **responder** with no network check at all (PWD-T1) |
| Keep the inherited fixed constant | — | **Refused.** It is a Monero-lineage value with no Shekyl meaning; deriving from `network_id` costs the same and does a second job |

**Conceded — and the first version of this row overclaimed the benefit, which
matters more than the cost it correctly named.**

**The prefix does *not* defend against an adaptive flooder, and this row
previously implied it did.** The value is derived from `network_id`, which is
public; **an attacker simply prepends the correct eight bytes** and reaches the
same buffering and KEM path at negligible extra cost. A deterministic,
publicly-derivable prefix **cannot** impose work on an adversary willing to
compute it — that is true of any such prefix, not a flaw in this one.

**So the adopted benefit is narrower than "DoS defence": it rejects
non-adversarial noise cheaply.** Port scanners, cross-protocol probes and
misdirected clients are a real and constant load on a public port, and they are
rejected at 8 bytes instead of at 1248 plus a decapsulation. That is worth
having; it is not resource-exhaustion protection.

> **Adaptive resource exhaustion is PWD-B1's (connection rate limiting) and
> PWD-B9's (per-host caps). Those impose cost on an attacker; a magic prefix
> never can.** Routed there rather than left implied here.

**And the cost is unchanged and still knowingly paid:** a stable per-network
prefix **is** a DPI fingerprint, accepted because PW-3a already concedes clearnet
protocol identity. **PW-9's original framing would have had us delete it for an
anonymity property we cannot have anyway; this row's first draft made the
opposite error and credited it with a security property it cannot have either.**

**Falsifier — and it reaches job 1 only.** **Reopen if measured
*non-adversarial* junk-connection cost with the prefix removed is within 2× of
cost with it present**, on the Q12-D6a rig. The adopted rationale is a cost
ratio **against unsolicited noise**, so that is the traffic the measurement must
use — **measuring it against an adaptive flooder would show no benefit and would
be testing a claim this row no longer makes.** **If it fires, the prefix does
not leave the wire**: job 2 is unaffected by any cost measurement, so the
outcome is a re-derived prefix, not a deleted one, unless PWD-T1 has by then
been given a responder-side check of its own.

### PWD-T6 — packet limits are derived, and the pre-handshake limit collapses

**RULED.** Three limits, each derived rather than inherited:

| Limit | Value | Derivation |
| --- | --- | --- |
| **Pre-handshake** | **exactly one first flight, plus its 8-byte prefix** — **1256 B** initiator, **1160 B** responder on the wire, from PWD-T1's **1248**/**1152** Noise-message tables plus PWD-T5's prefix | Before the handshake completes, the *only* legal message is the handshake, and it is fixed-size. Anything larger is not a slow peer, it is not a peer |
| **Post-handshake** | the largest legitimate message, from PWD-B3's per-command caps | Derived from what the protocol can legitimately send, not from a round number |
| **Post-decompression** | the plaintext ceiling, above the post-handshake limit | `compress.rs:64-68` states why: bounding the compressor's *input* by the wire limit would reject exactly the payloads compression exists to bring under it |

| Option | Adversary / channel | Verdict |
| --- | --- | --- |
| **Pre-handshake = exactly one first flight** | The pre-authentication memory exhauster — an unproven peer making this node buffer | **Adopted.** The only legal pre-handshake message is fixed-size, so any larger allowance is unearned buffer |
| Keep the inherited 256 KiB | The same | **Refused.** 256 KiB × concurrent junk connections is a memory amplifier with nothing legitimate on the other side of it |
| Post-handshake: derive from the largest legitimate message | The bandwidth/memory exhauster post-handshake | **Adopted**, terminating on PWD-B3's per-command caps |
| Post-handshake: keep 100 MB, or pick a round number | The same | **Refused.** An inherited round number is not a bound; it is a number that has not yet been questioned (§1's second check) |

**The pre-handshake collapse from 256 KiB is the substantive change.**
`LEVIN_INITIAL_MAX_PACKET_SIZE` is inherited at 256 KiB, which lets an unproven
peer make this node buffer a quarter-megabyte. **Under a fixed-size first flight
there is no reason for a single byte more.**

**The pre-handshake limit is stated over *wire* bytes, and the two numbers it
composes are owned by different rows.** PWD-T1 owns the Noise message sizes;
PWD-T5 owns the prefix. Stating only the Noise totals would leave every
conforming implementation rejecting its own first flight by eight bytes.
**These now move as four rows in lockstep — PWD-T1's tables, PWD-T5's prefix,
this limit, and PWD-T8's vector 1.**

**Two inherited constants disagree, and PWC-F3's disposition follows from this
row rather than waiting on anything.** `P2P_DEFAULT_PACKET_MAX_SIZE` (50 MB,
`cryptonote_config.h:185`) is **dead** — two sites, its definition and a write
into the never-sent `network_config` map (`net_node.h:388`), and
`packet_max_size` is **written and never read** anywhere in the tree — while the
live limit is `LEVIN_DEFAULT_MAX_PACKET_SIZE` (100 MB).

> **Ruled: `P2P_DEFAULT_PACKET_MAX_SIZE`, `network_config::packet_max_size`, and
> `network_config`'s KV serializer are deleted.** The struct stays as local
> config with its live fields (`max_out_connection_count`,
> `max_in_connection_count`, `connection_timeout`, `ping_connection_timeout`).

**Why this row can rule it, and why deferring it after this row could not.**
PWC-F3's hazard is a **2× disagreement between two candidate packet limits**;
before this row there was no ruling on which was authoritative, so the row had a
real dependency. This row supplies it — the limits above are the only enforced
ones — and once there is exactly one source, deleting the other is a deletion of
dead code (rule 15), not a derivation. **The KV serializer goes with it because
PWD-T1 removes the possibility of it ever acquiring a consumer**: the handshake
is a fixed-size Noise flight with no KV config exchange, so a serializer for a
never-sent local-config struct cannot become live. *An earlier version of this
row deferred PWC-F3 on the grounds that "it is a deletion, not a derivation" —
that is a reason to keep the two **legible**, which the paragraph break above
does, and not a blocker (rule 22).*

**Not ruled here:** `handshake_interval`, `config_id` and `send_peerlist_sz` are
also written-and-never-read on that struct, but they are cadence and peerlist
questions owned by PWD-B1/PWD-B2 and PWD-I2. Deleting them alongside would be
this row disposing of another row's subject.

**Conceded.** The post-handshake limit is stated as a derivation, not a number,
because its input is PWD-B3's per-command caps — **which are cluster B's.** This
row is honest that it terminates on another row rather than pinning a value it
does not own; `DAEMON_RELAY_PRIVACY.md` §7's *"a bound that depends on a
parameter owned further down is not a bound"* is the reason to say so plainly instead of inventing a figure.

**Falsifier.** **Reopen if any legitimate message is specified that exceeds the
derived post-handshake limit** — a message the protocol must send and the limit
forbids falsifies the derivation directly.

### PWD-T7 — compression survives, and it is safe here for a stated reason

**RULED.** zstd stays, before encryption, with its floor and ceiling unchanged
(`COMPRESSION_MIN_PAYLOAD = 256`, `ZSTD_COMPRESSION_LEVEL = 1`).

**Compress-then-encrypt is the CRIME/BREACH shape, and the reason it is safe
here is specific rather than general.** That attack needs **a secret and
attacker-influenced data compressed in the same context**, so the adversary can
observe ciphertext length while varying its own input. **p2p payloads are blocks
and transactions — public consensus data.** There is **no confidential value of
any kind** in a compression context, so there is nothing for a length oracle to
extract.

> **The invariant, stated so it can be checked rather than assumed: no message
> containing secret or otherwise confidential material — *of any lifetime* — is
> ever compressed.**

**"Per-connection" was an earlier and narrower wording, and the narrowing had no
justification behind it.** CRIME/BREACH turns on a secret being compressed
beside attacker-influenced data; **the secret's lifetime is irrelevant to the
attack**. A node-local static value or a reused token is as extractable as a
session key and is worth *more* once extracted, because it does not expire with
the connection. The invariant is scoped to **confidentiality**, not to lifetime.

That is true today because no such message exists. **It is written as an
invariant rather than an observation because the property is a fact about the
*message set*, and the message set is what future rounds change** — PWD-B3 and
cluster A both add or alter commands.

**And it is stated at the dispatch site, not only here, because an invariant
enforced by "a reviewer must check this section" is enforced by attention.**
`try_compress_message` (`rust/shekyl-levin/src/compress.rs`) now carries the
invariant, its reasoning, and the retreat in its own doc comment — **that is
where the decision is actually made**, by whoever adds the next message type,
and they are far more likely to read the function they are calling than the
design round that ruled it three clusters earlier.

**A doc comment is still not a gate**, and this round series has produced three
consecutive coverage claims narrower than believed, so the mechanical form is
queued rather than assumed. Its **named blocker: there is no message
classification to gate on** — nothing in the tree marks a command as
secret-carrying, so a check today would be a gate whose subject does not exist
(§1's discipline, and rule 47's). The classification lands with PWD-B3's command
table; the gate lands with it.

| Option | Adversary / channel | Verdict |
| --- | --- | --- |
| **Compress, then encrypt** | The length-observing path observer | **Adopted** under the invariant above. Block relay is the bandwidth case the chain actually has |
| Encrypt only | The same | **Refused.** It pays real bandwidth on every block for a leak that requires a secret we do not put in the payload |
| Compress, then pad to buckets | The same | **Refused as unnecessary here, and recorded as the retreat.** If the invariant above is ever broken, this is the position to move to rather than dropping compression |

**Conceded.** Compressed length still correlates with *content entropy*, so a
observer learns something coarse — a full block versus a single transaction —
which the noise/padding path (PWC-A9) masks where it applies and does not mask
elsewhere. This is arrival metadata, which §1.5 assigns to D++, taxed not
eliminated.

**Falsifier.** **Reopen if any message is specified that carries confidential
material of any kind** — the invariant's own trigger, recognisable by inspection of a
new command rather than by measurement.

### PWD-T8 — Shekyl mints its own KATs, and pins both handshake directions

**RULED.** There is no upstream oracle for this handshake: it is `NN` + `hfs`
with a Shekyl prologue and a Shekyl prefix. **The vectors are ours to mint**,
and the crate already carries the shape (`shekyl-levin/tests/oracle_kats.rs`,
`notify_kats.rs`, `payload_kats.rs`).

| Option | Adversary / channel | Verdict |
| --- | --- | --- |
| **Mint Shekyl's own vectors, pinning both directions and each mix step** | Not an adversary — **implementation drift and silent regression** | **Adopted.** No upstream oracle exists for `NN`+`hfs` with a Shekyl prologue and prefix, so there is nothing to differentially test against yet |
| Differential test against a second implementation (PW-7d) | A **shared misreading** of Noise, which self-minted vectors cannot catch | **Recorded, not decided.** It is the one thing our own vectors structurally cannot do; it becomes available when a second implementation exists, which is this row's falsifier |
| Rely on interop testing alone | The same | **Refused.** Two nodes built from one codebase agreeing proves the codebase self-consistent, not correct — `a-seal-is-not-coverage` in wire form |

The set, minimally — **six vectors**, and the rule they are built on is stated
after them because it governs every vector added later:

1. **Both handshake messages, byte-exact**, from pinned ephemerals — **1248 and
   1152 bytes**, per PWD-T1's term-by-term tables. **These are Noise message
   bytes and exclude PWD-T5's 8-byte prefix**; the wire allowance PWD-T6 states
   is 1256/1160, and a vector that conflates the two would pin the wrong
   number in the row that says it moves in lockstep with the other three.
   This also pins `e1`/`ekem1`
   **against being swapped** (PWD-T4), since their lengths differ, **and pins
   the tags**, which is the term the first draft of PWD-T1 omitted.
2. **The chaining key after each mix step**, so a wrong mixing *order* fails
   even when both secrets are present — the failure PWD-T1's ordering exists to
   prevent, which no message-level vector would catch.
3. **A prologue-mismatch vector** proving a wrong `network_id` fails
   **the initiator's** completion rather than being compared — and it is a
   **different kind of test from the others, which changes what it must
   assert.**

   > **This vector is initiator-side, and that is a property of `NN`, not a gap
   > in the vector.** Per PWD-T1, the responder derives identical transport keys
   > under a mismatched prologue, so there is no responder-side Noise failure to
   > pin. The responder's network rejection is PWD-T5's framing-layer prefix
   > compare — **vector 6 below**, which belongs to the framing surface rather
   > than to a handshake transcript, and is minted from the three prefixes
   > PWD-T5 pins. **A vector asserting responder-side
   > prologue rejection would be asserting a property the protocol does not
   > have, and would pass only against an implementation that had invented one.**

   A negative-path vector normally proves *an error branch behaves correctly*.
   This one proves **there is no error branch on the side it covers**: a wrong
   network does not reach a comparison that returns a "wrong network" result, it
   produces a transcript whose AEAD does not verify — the same failure as any
   corrupted byte.
   **A branch that cannot be reached is a branch that cannot be implemented
   wrong**, which is the whole reason PWD-T1 binds the value instead of checking
   it.

   > **So the assertion is *indistinguishability*, not a return code: a
   > wrong-`network_id` handshake must fail in the same undifferentiated way as
   > random bytes.**

   That is also a security property and not only a tidiness one. **If a
   wrong-network failure were distinguishable from a corrupted one, the
   difference would be an oracle** — a prober could separate "you are Shekyl on
   another network" from "you are not Shekyl", which is exactly the class of
   distinction PW-19a refuses to hand out. A vector asserting a specific error
   code would have *locked in* that oracle while appearing to test the feature.
4. **A suite/version-mismatch vector**, asserting the same indistinguishability
   as (3). **The protocol name is a binding too**, mixed into `ck` at
   initialisation — which is exactly why PWC-A3 can refuse version negotiation
   rather than specifying it. A peer speaking a different suite therefore fails
   the same way a wrong network does, and the vector must pin that it fails
   *identically*, not that it reports a version error.
5. **A rekey vector** — `ck'`/`k'` after one rekey in each direction.
6. **A framing-prefix vector**, pinning the **responder-side** network
   separation that vector 3 structurally cannot cover. It asserts both
   directions of the check: a connection opening with another network's prefix
   is **dropped at the framing layer, before any Noise processing**, and one
   opening with this network's prefix **proceeds to the handshake**. Its inputs
   are the three pinned values in PWD-T5 — mainnet `AFBCD4D1FAB98B6D`, testnet
   `F0B352E8928F8D56`, stagenet `5C2942C0F9F98A21` — so a cross-pair (dial
   mainnet with the testnet prefix) is a real, runnable case rather than a
   synthetic one.

   > **This vector asserts a *discriminated* early rejection, and that does not
   > violate the rule below.** The rule governs values moved into a **binding**;
   > the prefix is a **filter**, not a binding — it is unauthenticated, public,
   > and rewritable in transit, so it hands an adversary nothing it could not
   > compute. Discriminating there is the *point*: rejecting at eight bytes is
   > the entire benefit PWD-T5 adopts. **Without this paragraph the two rules
   > read as contradicting each other on the same page**, and the next reviewer
   > files that contradiction instead of the missing vector.

> **The rule the set is built on, stated generally because it will outlive these
> six vectors: for any value moved into a *binding*, the vector asserts
> *indistinguishability*, never a discriminated failure.**

**Otherwise the test reintroduces exactly what the binding removed.** The third
rung of §1's fourth check buys "there is no error path left to implement wrong";
a vector demanding an error code **requires** an implementation to build one,
and to make it distinguishable — quietly restoring the discrimination while
reading as a thorough negative-path test. **A test can put back what a design
decision took out, and this is the shape in which it does so.**

Two values are bound today — `network_id` (the prologue) and the protocol name
(the suite) — so the rule has two instances immediately. **Any future binding
inherits it without further argument**, which is the reason to state it as a
rule here rather than as a note on vector 3.

**PW-7d's differential-partner option is recorded, not decided.** Running a
second implementation as a cross-check is valuable and is *not* what this row
rules; it is noted so a later round does not read this as a rejection.

**Conceded.** Self-minted vectors pin *our* implementation to *our* reading of
the spec. They catch drift and regression; they do not catch a shared
misunderstanding of Noise. That is precisely what PW-7d's differential partner
would address, which is why it is recorded rather than dismissed.

**Falsifier.** **Reopen if an independent implementation of this handshake
exists** — at that point the differential option becomes available and the
self-minted set is no longer the strongest evidence obtainable.

### Cluster T disposition — the census rows this cluster accounts for

| Row | Disposition | Where |
| --- | --- | --- |
| PWC-A1 (`LEVIN_SIGNATURE` fixed 8 bytes) | **Ruled** — kept, re-derived from `network_id`, repriced to two jobs: cheap rejection of non-adversarial noise, and the responder's network separation | PWD-T5 |
| PWC-A2 (33-byte bucket header, field order) | **Deferred — named blocker: PWD-B3 owns per-command caps**, and the header's length field cannot be sized before them. Target pre-genesis, queued in FOLLOWUPS | PWD-B3 |
| PWC-A3 (one protocol version, never negotiated) | **Ruled** — the **protocol name** is mixed into `ck` at initialisation, so a suite mismatch fails on **both** sides; version negotiation is refused for the same reason PW-19a refuses identity: it is a claim, and the binding makes it unnecessary. *(The `network_id` prologue is the initiator-side binding and is a weaker instance — see PWD-T1.)* | PWD-T1 |
| PWC-A4 (256 KiB pre-handshake limit) | **Ruled** — collapses to one first flight | PWD-T6 |
| PWC-A5 (100 MB post-handshake, inherited) | **Ruled** — replaced by a derivation terminating on PWD-B3 | PWD-T6 |
| PWC-A9 (noise/fragment padding to `noise_size`) | **Absorbed** | PWD-T7 (the padded path is where the length leak is already masked) |
| PWC-A10 (zstd level 1, floor 256) | **Ruled** — kept, with the no-secret invariant stated | PWD-T7 |
| PWC-F3 (50 MB dead constant; never-sent `network_config` KV map) | **Ruled** — `P2P_DEFAULT_PACKET_MAX_SIZE`, `network_config::packet_max_size` and the struct's KV serializer are deleted; the struct keeps its live fields. Decidable *because* PWD-T6 names the authoritative limits; implementation is P2P-3 like every other ruling here, queued in FOLLOWUPS | PWD-T6 |

**Sum check: 6 ruled + 1 absorbed + 1 deferred = 8 rows.** ✅

> **Corrected 2026-09-03: this table has always held 8 rows, and the sum check
> claimed 9.** The original read *"6 ruled + 1 absorbed + 2 deferred = 9"* —
> arithmetically true and wrong about its subject, since the table held
> 5 ruled + 1 absorbed + 2 deferred = 8. **Ruling PWC-F3 then propagated the
> error rather than exposing it**: the ruled count went 6 → 7 and deferred
> 2 → 1, preserving a total that was already one too high. **A sum check that
> is internally consistent is not a check** — it verifies the total against its
> own addends, never against the rows. The pre-review sweep now compares each
> claimed count to the table above it, and cluster I's table is the control
> that shows the comparison discriminates rather than merely passing.

*PWC-F3 moved **deferred → ruled** in review: the recorded blocker — "it is a
deletion, not a derivation" — is a reason to keep the two legible, not a
dependency that prevents deciding (rule 22). The row count is unchanged; the
claim about what this cluster ruled is not.*

**Not decided here, and named so the boundary is legible:** per-command caps and
the rekey interval (PWD-B3), the `return_code` and unknown-flag questions
(PWD-B4/B5), and every behavioural cadence (cluster B). **PWD-T6's post-handshake
limit and PWD-T3's interval both terminate on cluster B** — that is a real
dependency, stated rather than papered over with a placeholder number.

## 3.6 Cluster B, first sub-round — unrecognised input, and the command table

**Three decisions: PWD-B3a, PWD-B6 and PWD-B3.** Cluster B carries **28** bucket-4 rows
across four validation surfaces, which is more than one review can hold at the
attention each row deserves (rule 19). It is therefore split into sub-rounds,
following the consensus lane's R1a/R1b/R1c precedent, and **this one goes
first because PWD-B3 is a hub rather than merely a blocker.**

> **Four already-ruled commitments terminate on PWD-B3**, one of them in a
> merged PR: PWD-T6's post-handshake limit, PWC-A2's deferral (the bucket
> header's length field cannot be sized before the caps it must express),
> PWD-B10's deletion of `COMMAND_PING` — which is *arm 3 of B3's own table* —
> and PWD-T7's compression gate, whose named blocker is that nothing in the
> tree classifies a command as confidentiality-bearing. **B3's command table is
> what resolves that classification.**

**PWD-B6 is in this sub-round because it decides B3's table membership, not
because it is convenient.** The two block-propagation commands have **byte-
identical request structs** — `block_complete_entry b; uint64_t
current_blockchain_height;`, same KV map (`cryptonote_protocol_defs.h:115-129`
and `:265-279`) — and inherited caps that differ by **32×** (128 MB vs 4 MB).
The cap is the *only* thing distinguishing the two paths, so deriving one
without deciding the other would set a limit for a command that may not exist,
exactly as it would have for `COMMAND_PING`.

### PWD-B3a — the unknown-input principle, ruled once for the whole cluster

**RULED, and stated at cluster scope deliberately.** The same question is asked
on two surfaces and today gets two different answers:

| Surface | Unrecognised input | Inherited behaviour |
| --- | --- | --- |
| Levin **flag bits** | bits outside the five defined | **preserved verbatim** through the codec (PWC-A6) |
| Levin **command ids** | any id not in the 13-arm switch | **`std::numeric_limits<size_t>::max()`** — **no *per-command* cap** (`src/cryptonote_basic/connection_context.cpp:68-71`). The global packet limit still binds: the reader takes `min(packet limit, hook(command))` (`rust/shekyl-levin/src/reader.rs:182-185`), so an unknown command is bounded by `DEFAULT_MAX_PACKET_SIZE`, not unbounded. *An earlier version of this row said "no cap at all", which overstates the hazard — the same flattering-error direction §1 warns about, pointed at a defect instead of a defence.* |

**One question, two answers, and neither was chosen.** That is the drift shape
that produced the 50 MB / 100 MB packet-limit pair PWD-T6 had to reconcile: two
rows deriving independently against the same underlying question.

> **Ruled: unrecognised input is rejected at ingress. A field this protocol
> does not define is not a field it forwards, stores, or sizes a buffer from.**

**The rule is scoped to the *dispatch* surface, and getting that wrong would
have deleted cover traffic.** `limit_for(head.command)` runs on **every** bucket
header as it arrives (`rust/shekyl-levin/src/reader.rs:315`), *before* any
flag-based classification — and **`noise_notify` emits `command = 0`** with
`BEGIN|END` (`rust/shekyl-levin/src/fragment.rs:47-58`), as does every fragment
carrier. A rejection keyed on "the id is not in the switch" therefore rejects
the white-noise and fragmentation paths **cluster T deliberately kept**, which
PWC-A9 records and PWD-T7's length-leak masking depends on.

> **So the discriminator is the flag class, not the id.** A bucket whose flags
> carry **neither `Q` nor `S`** is the noise/fragment class: it carries **no
> command at all** — the zero is a filler, not an identifier — and its bound is
> the framing bound (`noise_size`), never a command cap. A bucket that *does*
> carry `Q` or `S` is a dispatch, and **its command must be one this protocol
> defines**. The reassembled inner message is a dispatch too, and is checked the
> same way (`reader.rs:425`).

**This is the jobs-not-names rule again** (rule 16): "command id 0" has two jobs
— filler in a framing bucket, and a genuine id — and a check written against the
*field* rather than against the *job* silently takes out the first. **Carving
out the literal `0` would not have been the fix either**: it would admit a
`Q`-flagged bucket claiming command 0, which is a dispatch of an undefined
command and exactly what this rule exists to reject.

| Option | Adversary / channel | Verdict |
| --- | --- | --- |
| **Reject unrecognised input at ingress** | The peer probing for a permissive path — an unknown command id that falls back to the **global** packet limit instead of a bound sized for what it claims to be, or an undefined flag bit accepted as uninterpreted semantics | **Adopted.** It is the only answer that is the same on both surfaces, and it makes the *defined* set the specification rather than a subset of what is tolerated |
| Fall back to the global limit (today's command behaviour) | The same | **Refused.** `DEFAULT_MAX_PACKET_SIZE` is a *framing* bound, not a statement about what the message is — using it as the cap for an unknown command means the only thing sizing the buffer is how big a bucket may be, which is precisely the derivation PWD-T6 refused |
| Accept uninterpreted semantics (today's flag behaviour) | The same | **Refused.** The codec round-trips unknown bits, and **PWC-A6a records that no relay carries them today** — the relay path re-frames rather than forwarding a received header — so this is a *latent* permission, not a live forwarding path. Closing it now costs nothing; leaving it means `COMPRESSED` (0x10) proves the range is one **we allocate from**, and the next Shekyl extension collides with a bit some peer was already permitted to set |
| Ignore-and-drop the field, keep the message | The same | **Refused, and it is the subtle one.** It looks conservative and silently changes the message: a peer that sent `flags = REQUEST\|0x20` believes it sent something this node did not act on, and neither side can tell. **Silent divergence, which rule 71 forbids on the consensus surface and PW-18 dislikes everywhere** |
| Cap unknown commands at a per-command default | The resource exhauster | **Refused.** A default cap answers "how much of an unknown thing should I buffer", which is a question with no good answer; rejecting answers it with zero |

**Conceded.** This forecloses in-band extension without a version bump — a peer
cannot introduce a new command or flag and have old nodes tolerate it. **That is
intended**, and PWC-A3 already refuses version negotiation for the same reason:
tolerance is a claim about the future that the tolerating node cannot verify.
Extensions arrive by the same route consensus changes do.

**Falsifier.** **Reopen if any deployment scenario requires two Shekyl versions
with different command sets to interoperate on one network without a
coordinated cutover** — that is the property this ruling trades away, and it is
checkable against the release plan rather than against a benchmark.

> **PWD-B4 applies this rule; it does not re-derive it.** B4's remaining work is
> the *ingress check's* placement and its interaction with the framing rows
> (PWC-A6/A6a/A7), not the policy. Recorded here so the two sub-rounds cannot
> reach different answers.

### PWD-B6 — one block-propagation path, not two

**RULED: `NOTIFY_NEW_BLOCK` (2001) is deleted; `NOTIFY_NEW_FLUFFY_BLOCK` (2008)
is the sole block path.**

**The two commands are already one code path.** `handle_notify_new_block`
builds a fluffy request from its argument and **returns
`handle_notify_new_fluffy_block(...)`**
(`src/cryptonote_protocol/cryptonote_protocol_handler.inl:529`). 2001 is a wire
alias for 2008, not a second implementation, so deleting it removes a name —
not a behaviour.

> **An earlier version of this row argued from `pruned`, and that was wrong.**
> It claimed `block_complete_entry`'s peer-controlled `pruned` bool lets either
> shape travel on either command. **`pruned` selects the transaction
> *encoding*** — which branch of the KV map serializes `txs`
> (`cryptonote_protocol_defs.h:76-95`) — and the announce path passes
> **`allow_pruned=false`** (`cryptonote_protocol_handler.inl:616`), rejecting
> pruned entries outright. **Compactness is not a struct property at all**: a
> compact announce is one that sends a *subset* of `b.txs`, which no field
> records. The correction strengthens the ruling — the two ids were never
> distinguished by shape, so there is even less to preserve.

**So the 32× cap gap enforces nothing about the message.** It is two different
caps on one handler, reachable by choosing an id.

| Option | Adversary / channel | Verdict |
| --- | --- | --- |
| **Keep 2008 only** | The peer choosing the path with the weaker bound; and the bandwidth cost of full-block flood on a chain that has a compact path | **Adopted.** Shekyl is v3-from-genesis with **no fluffy transition to be compatible across** (rule 60) — 2001 exists only because Monero needed both during a rollout that is not our history |
| Keep 2001 only | The same | **Refused.** It is the *more* expensive path, and deleting the compact one to keep the verbose one inverts the reason both exist |
| Keep both, reconcile the caps | The same | **Refused.** Reconciled caps still leave two commands with one schema, so the choice of command carries no information and the receiver must handle both — cost with no property bought |

**Conceded — very little, and an earlier version of this row conceded
something that was not true.** It said deleting 2001 costs a missing-tx round
trip that the full-block path would have avoided. **It does not.** How much of
`b.txs` a sender includes is **sender policy, independent of the command id**,
and 2001 already dispatches into 2008's handler — so the round trip is a
property of what the sender chose to send, before and after this ruling alike.
*That concession was written under the `pruned`-based model this row has since
corrected, and it survived the correction.* What is actually given up is a wire
name; `NOTIFY_REQUEST_FLUFFY_MISSING_TX` (2009) is unchanged and still the
mechanism for whatever the sender omitted.

**Falsifier.** **Reopen if measured block-propagation latency on the compact
path exceeds the full-block path by more than one round-trip time at the
95th percentile**, on the Q12-D6a rig — a figure that would mean the missing-tx
fetch is not the bounded cost this ruling assumes.

### PWD-B3 — per-command caps, and the bound that is not a number

**RULED as a derivation with a named dynamic input, because the honest answer
is not a table of constants.**

**The inherited table, read at source** (`src/cryptonote_basic/connection_context.cpp:41-71`) —
13 arms, and after PWD-B10 and PWD-B6 it is **11**:

| Command | Inherited cap | Disposition |
| --- | --- | --- |
| `COMMAND_HANDSHAKE` (1001) | 65536 | Derived from `P2P_MAX_PEERS_IN_HANDSHAKE` (250) × one peerlist entry + `CORE_SYNC_DATA` |
| `COMMAND_TIMED_SYNC` (1002) | 65536 | Same derivation as 1001 |
| `COMMAND_PING` (1003) | 4096 | **Arm deleted** — PWD-B10 |
| `COMMAND_REQUEST_SUPPORT_FLAGS` (1007) | 4096 | A four-byte reply behind a 4 KiB cap; derive to the field |
| `NOTIFY_NEW_BLOCK` (2001) | 128 MB | **Arm deleted** — PWD-B6 |
| `NOTIFY_NEW_TRANSACTIONS` (2002) | 128 MB | **Not derivable yet — there is no relay batch bound.** See below |
| `NOTIFY_REQUEST_GET_OBJECTS` (2003) | 2 MB | A hash list; derives from its length bound |
| `NOTIFY_RESPONSE_GET_OBJECTS` (2004) | 128 MB | **Batch-bounded, not single-block** — see below |
| `NOTIFY_REQUEST_CHAIN` (2006) | 512 kB | A hash list; derives from its length bound |
| `NOTIFY_RESPONSE_CHAIN_ENTRY` (2007) | 4 MB | A hash list; derives from its length bound |
| `NOTIFY_NEW_FLUFFY_BLOCK` (2008) | 4 MB | **The dynamic one** — see below |
| `NOTIFY_REQUEST_FLUFFY_MISSING_TX` (2009) | 1 MB | An index list; derives from the block's tx count bound |
| `NOTIFY_GET_TXPOOL_COMPLEMENT` (2010) | 4 MB | A hash list; derives from the pool bound |

> **The block-carrying commands cannot take a static cap, and this is the
> finding, not a gap in the round.** A block's maximum weight is
> `m_current_block_cumul_weight_limit` — **dynamic, consensus-derived, and a
> function of chain state** (`src/cryptonote_core/blockchain.cpp:1846`, `median_weight = m_current_block_cumul_weight_limit / 2` — cited with its symbol so a line drift is detectable by grep). A static number is
> therefore either **too small**, rejecting a legitimate block during a growth
> phase and partitioning the node, or **too large**, in which case it is not a
> bound. The inherited 128 MB is the second.

**Ruled: the block-carrying cap is computed from the receiver's own consensus
state**, as a fixed multiple of its current weight limit, so it tracks the chain
rather than a release.

**The formula, written out, because "a fixed multiple of the weight limit" is
not one.** A `block_complete_entry` is **not** bounded by block weight alone: it
also carries `attestation_witness`, an opaque blob capped **independently of
`pruned` and of weight** at `ARCHIVAL_ATTESTATION_WITNESS_MAX_BYTES` =
`8 + ARCHIVAL_MAX_ATTESTATION_RECORDS × PQC_HYBRID_SINGLE_SIG_LEN` = **866,568
bytes** (`src/cryptonote_config.h:472-473`, bounded at the codec by
`archival_attestation_witness_within_transport_cap`).

> **`entry_max` = `margin` × `m_current_block_cumul_weight_limit`
> + `ARCHIVAL_ATTESTATION_WITNESS_MAX_BYTES` + KV encoding overhead.**
>
> - **2008** (one announce): `entry_max`.
> - **2004** (a batch): `n × entry_max` for the batch cardinality `n`.

**`margin` is the one term this round does not fix, and it is named as owed
rather than invented.** It exists to absorb the receiver being behind the tip,
so its value is a function of how fast the consensus weight limit can grow per
block — **a consensus parameter, and the consensus lane owns it.** Naming it as
a symbol with a stated job is the honest form; picking a number here would be
inventing a consensus constant from a p2p round.

> **The witness term dominates at batch size, and that is a design consequence,
> not a footnote.** At the inherited request bound of 100 blocks, the witness
> alone contributes 100 × 866,568 ≈ **86.7 MB** — so **PWD-T6's post-handshake
> limit is set primarily by the attestation witness, not by block weight.** Any
> future change to `ARCHIVAL_MAX_ATTESTATION_RECORDS` moves the p2p packet
> limit with it.

> **`NOTIFY_RESPONSE_GET_OBJECTS` (2004) takes a different bound from
> `NOTIFY_NEW_FLUFFY_BLOCK` (2008), because it is not a single block.** Its
> payload is `std::vector<block_complete_entry> blocks` plus a `missed_ids`
> list (`src/cryptonote_protocol/cryptonote_protocol_defs.h:173-190`) — a **sync batch**. A cap sized
> for one block plus a tip-lag margin either rejects legitimate multi-block
> sync responses or, if widened to fit a batch, hands the single-block announce
> path a batch-sized bound. *An earlier version of this table gave both
> commands the same disposition and would have done one or the other.*
>
> **Its bound is the batch this node asked for.** `NOTIFY_REQUEST_GET_OBJECTS`
> (2003) carries `std::vector<crypto::hash> blocks` (`src/cryptonote_protocol/cryptonote_protocol_defs.h:156-171`), so the
> receiver **already knows the cardinality it requested** — the cap is that
> count times the per-block bound, and it needs nothing from the peer.
> §1's fourth check again: the bound comes from this node's own record of what
> it sent, not from a claim in the response. **A response to a request this node
> did not make has a batch size of zero**, which the same rule rejects without a
> separate mechanism.

**Enforced in two layers, because the ingress seam cannot see per-connection
state — and it does not need to.** `BucketReader`'s hook is
`fn(u32) -> u64` (`rust/shekyl-levin/src/reader.rs:177-185`), command-only, and
the requested cardinality lives in per-connection handler state. Rather than
widen the framing seam to carry connection state — which would push protocol
policy into the framing crate, against `25-rust-architecture` — the bound
splits along the boundary that already exists:

| Layer | Bound | Why it fits there |
| --- | --- | --- |
| **Ingress** (`fn(u32) -> u64`) | `CURRENCY_PROTOCOL_MAX_OBJECT_REQUEST_COUNT × entry_max` — **100 × entry_max** (`src/cryptonote_protocol/cryptonote_protocol_handler.h:58`) | Depends only on the receiver's own consensus state and a compile-time constant, so it is expressible in the existing signature. Bounds the allocation before any handler runs |
| **Handler** (per connection) | the **exact** requested cardinality × `entry_max` | The request state is already there; this is a tightening, not the only bound, so nothing is unbounded if the handler check is reached late |

**The static layer is what makes the claim safe**; the per-request layer is what
makes it tight. *An earlier version of this row asserted only the tight bound,
which the framing seam cannot express — so it named a cap that nothing could
enforce at ingress.* The multiple absorbs the receiver being behind the tip;
it is a consensus-adjacent constant and is **named as owed to the consensus
lane**, not invented here.

| Option | Adversary / channel | Verdict |
| --- | --- | --- |
| **Derive from the receiver's own current weight limit × a fixed margin** | The oversize-block flooder, pre-validation | **Adopted.** The only form that is a real bound at every chain height, and it uses state the receiver already has and the peer cannot influence — §1's fourth check, observation over claim |
| A static ceiling picked to survive expected growth | The same | **Refused.** It is a number that has not yet been questioned (§1's second check); it becomes wrong in one direction or the other and gives no signal when it does |
| Keep 128 MB | The same | **Refused.** It is 32× the compact path's own inherited figure and bounds nothing a node would otherwise reject |

> **Two inputs this round does not have, and the ruling says so rather than
> implying a table of finished numbers.**
>
> **(a) `NOTIFY_NEW_TRANSACTIONS` (2002) has no batch bound to derive from.**
> `Zone::queue_fluff` appends every transaction to each peer's queue and
> `flush_fluff` releases the whole accumulated batch —
> `std::mem::take(&mut peer.queued)`, with no cardinality or byte cap
> (`rust/shekyl-relay/src/zone/mod.rs:814-847`, `:852-880`) — and the receive
> side checks no cardinality either. **So 2002's cap has no derivation input,
> and until one exists 2002 is not bounded below 2004.** *An earlier version of
> this table wrote "`CRYPTONOTE_MAX_TX_SIZE` × the relay batch bound" as though
> that bound existed.* Ruling it is cluster B's own work and belongs with the
> relay cadence rows (PWD-B1/PWD-B2), not here.
>
> **(b) The cardinality-derived batch bound exceeds the plaintext ceiling,
> which contradicts PWD-T6.** The consensus weight limit **floors** at
> `2 × get_min_block_weight` = **600,000 bytes**
> (`src/cryptonote_core/blockchain.cpp:6564-6567`; the median is clamped up to
> `full_reward_zone` at `:6543` before doubling). So even at `margin = 1`,
> `100 × (600,000 + 866,568)` = **146,656,800 bytes**, above
> `DECOMPRESSED_MAX_SIZE` = 128 MiB = **134,217,728**
> (`rust/shekyl-levin/src/compress.rs:29`). PWD-T6 requires the plaintext
> ceiling to sit **above** the post-handshake limit; this inverts it, so a
> conforming compressed 2004 could be legal on the wire and rejected after
> inflation.

**Ruled, because the contradiction forces the shape even though it does not
fix the number: `NOTIFY_RESPONSE_GET_OBJECTS` is bounded in BYTES, not by
cardinality alone.** The responder fills a byte budget and **truncates the
batch**, leaving the requester to ask for the remainder — which it already
must handle, since `missed_ids` exists. A cardinality bound multiplies two
independent worst cases (every block at maximum weight *and* maximum witness
simultaneously), producing a buffer no honest exchange ever fills, and here it
produces one the decompressor is required to reject.

> **The budget is chosen at or below the plaintext ceiling, so PWD-T6's
> ordering holds by construction rather than by arithmetic that has to be
> re-checked whenever a consensus constant moves.** The budget's value is
> **owed**, with the same discipline as `margin`: it is a bandwidth/latency
> trade for initial sync, and picking it needs the sync measurements this round
> does not have.

**What this discharges — and what it does NOT, which is the correction this
round owes:**

- **PWD-T6's post-handshake limit** takes its *shape* from this table — the
  maximum over it, which is `NOTIFY_RESPONSE_GET_OBJECTS`'s byte budget and
  **not** the single-block bound a reader would take from the more visible row.
  **Its value is not discharged**: the budget is owed, and 2002 is unbounded
  until (a) above is ruled, so "2004 is the maximum" is a claim about shape,
  not yet a proven ordering.
- **PWC-A2** (bucket header length field) is **not** sized by this round. It
  must express 2004's byte budget, and that budget does not have a value yet.
  *An earlier version of this bullet declared it sized; that was premature, and
  premature-clear is the more expensive direction — nobody re-checks a gate
  that says it is closed.*
- **PWD-T7's compression gate** gets its classification — **but from the
  *route*, not from this table, and the difference matters.** *An earlier
  version of this bullet said "every command in this table carries public
  consensus data", which is false: `COMMAND_HANDSHAKE` and
  `COMMAND_TIMED_SYNC` carry peerlists and support flags
  (`src/p2p/p2p_protocol_defs.h:172-250`) — peer metadata, not consensus data,
  and peerlist disclosure is a thing PWD-I2 deliberately controls.*

  **The set is empty because of what can reach the compressor, which is a
  narrower question than what is in the table.** All three call sites finalize
  as **notifications** — `levin_notify.cpp:437`, and
  `src/p2p/net_node.inl:2186` / `:2503`, both via `finalize_notify(command)`.
  **Every p2p command is an *invoke***: `COMMAND_HANDSHAKE`
  (`net_node.inl:1078`), `COMMAND_TIMED_SYNC` (`:1165`), `COMMAND_PING`
  (`:2581`) and `COMMAND_REQUEST_SUPPORT_FLAGS` (`:2623`) all go through
  `async_invoke_remote_command2`, so **they cannot reach the compressor at
  all** — structurally, not by convention. What remains is the cryptonote
  notify family, which carries blocks and transactions.

  > **So the confidentiality-bearing set is empty today, and the gate is a
  > check on the *routes into `try_compress_message`*, not on the command
  > table.** A gate written against the table would pass while a future
  > invoke-carried secret was quietly re-routed through a notify.

**Conceded, and it is a real cost.** A dynamic cap means two nodes at different
heights admit different maxima, so a node far behind the tip rejects a block a
synced node accepts. **That is correct behaviour** — it will fetch the
intervening chain first — but it makes "the limit" a per-node quantity rather
than a protocol constant, which every implementation must reproduce identically
or interoperate poorly.

**Falsifier.** **Reopen if a legitimate block is ever rejected by the derived
cap at any reachable chain state** — the same falsifier PWD-T6 carries, now
with a computable subject rather than a static number to compare against.

### Cluster B first sub-round disposition — the census rows this sub-round accounts for

| Row | Disposition | Where |
| --- | --- | --- |
| PWC-C7 (`get_max_bytes` unknown-command fallthrough to `size_t::max`) | **Ruled** — rejected at ingress, not defaulted | PWD-B3a, PWD-B3 |
| PWC-C3 (two block-propagation paths) | **Ruled** — 2001 deleted, 2008 is the sole path | PWD-B6 |
| PWC-A6 (codec round-trips unknown flag bits) | **Ruled** — the policy is set here; PWD-B4 places the check | PWD-B3a |
| PWC-A6a (no relay carries unknown bits today) | **Absorbed** | PWD-B3a (it is the reason the change is safe now) |

**Sum check: 3 ruled + 1 absorbed + 0 deferred = 4 rows.** ✅

**Running total as of cluster B's first sub-round — historical:** **22 of 46**
bucket-4 rows dispositioned — cluster I's 10 + cluster T's 8 + this
sub-round's 4. **The authoritative total is at the end of the most recent
sub-round**; only one is ever current. **24 rows remain**, all in cluster B's later sub-rounds:
`PWC-A7`, `PWC-B1`, `PWC-B2`, `PWC-B4`, `PWC-B5`, `PWC-B6`, `PWC-B7`,
`PWC-C1`, `PWC-C5`, `PWC-C6`, `PWC-C8`, `PWC-E1`, `PWC-E2`, `PWC-E3`,
`PWC-E4`, `PWC-E4a`, `PWC-E5`, `PWC-E7`, `PWC-E8`, `PWC-E9`, `PWC-E11`,
`PWC-E13`, `PWC-E14`, `PWC-F4`.

> **Every id is spelled in full deliberately.** A bare `B1` in this document
> reads as **PWD-B1**, a decision id, not `PWC-B1`, a census row — two live
> families whose short forms collide. An enumeration exists to be checked
> mechanically, and an ambiguous id cannot be.

## 3.7 Cluster B, second sub-round — cadence, rate, and the batch nobody bounded

**Three decisions: PWD-B1, PWD-B2, and PWD-B12 (minted here).** The
validation surface is **connection cadence and rate** (rule 19). It goes second
because **PWD-B12 is what PWC-A2 is re-blocked on**: PWD-B3 ruled the header
field must express the largest value the command table can produce, and
`NOTIFY_NEW_TRANSACTIONS` has no bound at all, so no maximum exists to size to.

> **A premise this round had to correct before costing anything.** Earlier
> grounding recorded *"no jitter anywhere"*. That is true of the **node-server
> idle makers** and false of the tree: the relay layer draws fluff delays from
> `FluffScheduler::memoryless()` — deliberately memoryless rather than the
> inherited Poisson, which was the F-4 defect — and jitters the noise cadence
> as `min + U(0, jitter)` (`rust/shekyl-relay/src/zone/mod.rs:315-320`,
> `:235`). **So this round is not introducing randomised timing to a tree that
> has none; it is asking why one layer has it and the layer above does not.**

### PWD-B12 — the fluff batch is unbounded, and the census could not see it

**RULED. Minted here rather than routed**, because "cluster B owns it" is not
an owner if no row names it (rule 22).

`Zone::queue_fluff` appends **every** transaction to each peer's queue, and
`flush_fluff` releases the whole accumulation — `std::mem::take(&mut
peer.queued)` — with no cardinality or byte cap
(`rust/shekyl-relay/src/zone/mod.rs:814-847`, `:852-880`). The receive side
checks no cardinality either.

> **Why no census row covers it, which is a finding about the instrument.**
> P2P-1's frontier was **the p2p wire and the connection management around
> it**. `queue_fluff`/`flush_fluff` are *relay-layer* code that decides what
> goes on that wire, so the bound sat one layer outside the enumeration — and
> a census cannot report the absence of something outside its own frontier.
> **This does not add a 47th row**: the completion gate stays at the census's
> 46, and this decision is recorded as reaching past it.

| Option | Adversary / channel | Verdict |
| --- | --- | --- |
| **Bound the batch in bytes at release, and emit the remainder in the next flush** | The pool-flooder, who makes a victim emit one enormous `NOTIFY_NEW_TRANSACTIONS` — and the path observer, for whom an unbounded batch is a size signal proportional to arrival rate | **Adopted.** A byte bound is what PWD-B3's cap needs as its input, and splitting across flushes costs latency rather than correctness. **Bytes, not count**, for the same reason PWD-B3 rejected cardinality: transactions vary in size, so a count bounds nothing |
| Bound by transaction count | The same | **Refused, but not because it bounds nothing.** `CRYPTONOTE_MAX_TX_SIZE` is 1 MB, so `n` transactions admit at most `n` MB — a **finite** bound, just a loose one that varies by a factor of thousands with the traffic mix. Bytes are adopted because they are **tighter and a direct input to PWD-B3's cap**, not because count is unbounded. *An earlier version of this cell said the bound would be nominal, which overstates the refused option — §1's sixth check, pointed at an alternative instead of at the adopted rule.* |
| Leave unbounded; the packet limit catches it | The same | **Refused.** That is the fallback PWD-B3a already refused one surface over: a framing bound is not a statement about what the message is, and here it would make the *relay's* behaviour depend on a *framing* constant it never reads |

**Bounding the release does not bound the queue, and the ruling has to say
both.** `peer.queued` is a bare `Vec<TxBlob>`: `queue_fluff` extends it
(`rust/shekyl-relay/src/zone/mod.rs:846`) and `flush_fluff` empties it
(`:868`), with **no bound at either end**. If transactions arrive faster than
one capped batch per flush interval, the remainder simply accumulates — **once
per destination peer** — so a release-side cap alone converts the flooder's
attack from an oversized message into memory exhaustion, which is worse
because it is invisible on the wire.

> **So PWD-B12 is two bounds, not one: a byte cap on what a flush *releases*,
> and a byte cap on what a zone *holds*, with admission refused at the second.**

**Admission is refused at the source, not at the destination queue**, and that
placement is the whole point. `queue_fluff` fans one arrival out to every
destination, so a single flooding source fills *N* queues; dropping at the
destination discards transactions that other peers may never see, while
refusing admission pushes the cost back onto the connection that caused it —
where **PWD-B1's token bucket is already charging it**. The two rows compose:
B1 makes the flood expensive per connection, B12 makes it bounded in memory.

**Conceded.** A bounded batch means a burst of transactions takes more than one
flush to propagate, which slightly lengthens the tail of propagation under
load. Refused admission is a real loss — a transaction this node never queued
is one it never relays — but it is bounded, attributable to the connection that
caused it, and preferable to unbounded growth that degrades the whole node. **That is the correct direction for D++ anyway** — the fluff delay is
already memoryless, so an extra flush is drawn from the same distribution
rather than adding a new observable.

**Falsifier.** **Reopen if the batch bound is reached during normal operation
at the design transaction rate** — that would mean the bound is shaping
ordinary traffic rather than catching a flood, and its value is wrong.

> **This is the input PWC-A2 needs.** With it, `NOTIFY_NEW_TRANSACTIONS` has a
> derivable cap and the "largest value the table can produce" question becomes
> answerable. **The value itself is still owed**, with `margin` and the
> response byte budget, in the FOLLOWUPS item PWD-B3 re-opened.

### PWD-B1 — rate limiting: adopted, and it is the mechanism PWD-T5 routed here

**RULED.** PWC-E2 records the absence against an enumerated frontier: **no
token bucket, no per-peer counter, no minimum interval** guards any of the four
invoke entry points — `handle_get_support_flags`, `handle_timed_sync`,
`handle_handshake`, `handle_ping` (`src/p2p/net_node.inl:2170`, `:2646`,
`:2695`, `:2794` **as of this round's pin**; PWC-E2 cites the same four at the
line numbers its own pin had, and the handlers are named here so the next
drift is greppable rather than silent).

**Two earlier rows routed their adaptive-adversary case here, and this row
carries only half of it — which is stated rather than glossed.** PWD-T5
conceded that a publicly-derivable prefix cannot impose attacker work and sent
adaptive exhaustion to PWD-B1/PWD-B9; PWD-B3a rejected unknown commands but an
adversary may send *known* ones at any rate.

> **PWD-B3a's half is carried here. PWD-T5's is not, because it is a different
> phase.** T5's flooder prepends the correct eight bytes and reaches "the same
> buffering and KEM path" — **before the handshake completes, and therefore
> before any of the four invoke entry points this bucket sits on.** A
> post-transport rate limit cannot bound a pre-transport cost.

**What does bound the pre-handshake phase today, and what does not — and the
first version of this paragraph named the wrong mechanism, in the wrong
direction.** PWD-T6 caps the pre-handshake allowance at exactly one flight
(1256/1160 B), so the *per-connection* buffer is bounded and small.

> **The decapsulation is forced by an *inbound* connection, so the bound that
> matters is the inbound one — and that is PWC-E11, not PWD-B9.** PWD-B9 is
> **outbound slot diversity** (`P2P_2_DISPATCH_BRIEF.md:502`), which says
> nothing about connections a peer opens *to us*. The inbound cap is
> `has_too_many_connections` (`src/p2p/net_node.inl:3089` **at this round's pin**; PWC-E11 cites `:3083-3105` from its own, and the symbol is named here so the drift is greppable), which filters
> on `cntxt.m_is_income` — and **returns permit for every non-public zone**, so
> **on Tor there is no inbound per-host cap at all.**

**So two gaps, not one.** Even on clearnet, a per-host *concurrency* cap does
not bound **churn** — connect, force one decapsulation, disconnect, repeat —
and on anonymity zones there is no per-host bound of either kind. That is
precisely PWD-T5's adversary, and neither PWD-T6 nor PWC-E11 reaches it.

> **Given its own owner rather than folded into PWD-B9.** Widening B9 informally
> would leave the brief, the index and this document disagreeing about what B9
> means, and a row that means different things in different documents is worse
> than a missing row. Queued in FOLLOWUPS as **pre-handshake admission rate**,
> citing PWC-E11 for the current state — with the anonymity-zone gap named,
> because a cap that exempts Tor is the kind of "bound" that reads as one
> without being one.

> **Open, and it is *unruled* rather than blocked** — no decision waits on
> another, so nothing licenses deferring it beyond this sub-round's surface.
> Recorded in FOLLOWUPS with PWC-E11 as the current state and the
> anonymity-zone exemption named.

| Option | Adversary / channel | Verdict |
| --- | --- | --- |
| **Per-connection token bucket charged at *dispatch*, before the request is decoded** | The adaptive flooder who sends well-formed, correctly-prefixed, known-command messages faster than they can be serviced — **and the one who sends malformed ones** | **Adopted.** It is the only mechanism here that imposes *cost* on the attacker rather than merely classifying it, which is what PWD-T5 could not do. Per-connection, so it needs no identity (PW-19a) |
| The same bucket, charged inside the handlers | The same | **Refused — it would not have bounded the work.** See the placement rule below |
| Global rate limit across all peers | The same | **Refused.** One peer's flood then throttles every honest peer — the attacker buys a shared outage with one connection |
| Rely on per-host connection caps (PWD-B9) | The same | **Refused as a substitute, kept as a complement.** B9 bounds how many *connections* a host gets; it says nothing about the rate on a connection it is entitled to |

**Conceded.** A token bucket adds per-connection state, and a peer that is
merely fast — a well-connected node during a burst — is throttled the same as
an attacker.

> **The charge happens at dispatch, before decoding, and the placement is
> load-bearing rather than an implementation note.**

`HANDLE_INVOKE_T2` tests `COMMAND::ID == command` and then calls
`buff_to_t_adapter`, which runs `strg.load_from_binary(in_buff, …)` **and**
`in_struct.load(strg)` *before* it invokes the handler
(`contrib/epee/include/storages/levin_abstract_invoke2.h:250-252`, `:152-171`).
A bucket charged inside `handle_timed_sync` and its siblings would therefore
leave **two** things unmetered:

- **the portable-storage parse itself**, which is the expensive part of
  servicing a flood and happens before any handler runs;
- **every malformed request**, which returns `-1` from the adapter and **never
  reaches a handler at all** — so an attacker who sends deliberate garbage pays
  nothing against the bucket while still making the victim parse it.

**The command id is already in hand at dispatch**, which is what makes the fix
free: the same `COMMAND::ID == command` test that selects the handler can
charge the bucket first. *An earlier version of this row placed the bucket on
"the four invoke entry points", meaning the handlers — bounding the cheap half
and calling it resource exhaustion protection.*

**Four parameters are owed, not one, because a bucket is not defined by its
refill rate.** Two conforming implementations given only a rate would diverge
on burst tolerance and on what a throttled peer experiences:

| Owed | Why it cannot be left to the implementer |
| --- | --- |
| **Refill rate** | the honest/attacker boundary; too tight and sync stalls, too loose and it is decoration |
| **Capacity, and the initial fill** | capacity *is* the burst allowance; a full-at-connect bucket and an empty one differ sharply for a peer that opens and immediately syncs |
| **Token cost per command** | a handshake and a timed-sync are not the same work — a flat cost prices the cheap one like the expensive one, and an attacker picks whichever is mispriced. **Charged on the command id at dispatch**, which is the only point where the id is known and no work has been done yet |
| **Action on exhaustion** | throttle, or drop the connection? The two produce **different wire-observable behaviour**, so leaving it open means peers disagree about whether a slow peer is a hostile one |

**Falsifier.** **Reopen if honest initial sync ever exhausts the bucket** —
concrete, observable at the sync path, and the failure that would mean the rate
was chosen against the wrong traffic.

### PWD-B2 — jitter, and the discriminator is observability

**RULED.** The five node-server idle makers are fixed-interval
(`src/p2p/net_node.h:618-622`) and the three protocol-handler timers likewise
(PWC-E4).

> **Ruled: a cadence a *path* observer can correlate across connections
> gets an independently drawn per-connection deadline; a cadence that is purely
> local scheduling stays a single fixed timer.**

**"Jitter the timer" would not have bought the property, and the distinction is
the whole ruling.** Timed-sync is driven by *one* shared idle maker that walks
every handshaked connection. Randomising **when that timer fires** still sends
to every connection **simultaneously** — an observer sees N connections light up
at the same instant, which is *perfect* cross-connection correlation with a
randomised offset. The fix is not a jittered shared timer; it is **per-connection
deadlines, drawn independently**.

> **And the re-draw discipline comes with it, because the relay lane already
> paid for getting it wrong.** `NoiseSchedule` keeps one deadline per channel,
> **each drawn once and re-drawn only when *that* channel fires**; a foreign
> wake must leave every other entry untouched, because re-drawing on a foreign
> wake resamples `min + U(0, jitter)` and keeps the minimum, **biasing the
> effective interval short** — "a privacy defect no count assertion and no
> goodness-of-fit grade can see" (`rust/shekyl-relay/src/zone/mod.rs:231-236`).
> **PWD-B2 adopts that rule verbatim**: a connection's deadline is re-drawn
> only when that connection's own sync fires.

**Timed-sync (60 s, to every handshaked connection at once) is the case that
matters.** A fixed network-wide period means every node's timed-sync traffic is
phase-locked to its own start time, and an observer watching two connections
can test whether they belong to the same node by comparing phase. **That is an
identity signal reconstructed from timing** — precisely the class PWD-I1 spent
the identity cluster removing from the wire, and it would survive the field's
deletion.

| Option | Adversary / channel | Verdict |
| --- | --- | --- |
| **Per-connection independently drawn deadlines for the observable cadences; purely local timers stay a single fixed timer** | The path observer correlating two connections by phase | **Adopted.** It targets the cadences that produce a cross-connection observable and leaves the ones that do not, so the change is small and each part is justified by its own adversary |
| Jitter the existing **shared** timer | The same | **Refused — it does not buy the property.** One timer walking every connection still sends to all of them at the same instant; the offset moves and the correlation does not |
| Jitter everything on a timer | The same | **Refused.** The idle-peer kick and the standby check produce no cross-connection signal; jittering them buys nothing and makes every timing test in the tree probabilistic |
| Leave all fixed | The same | **Refused.** It preserves a correlation the identity cluster just paid to remove — the wire field goes and the timing tell stays |

**Conceded — and it is the reason this row is small.** Jitter reduces phase
correlation; it does not eliminate traffic analysis, and against an observer
who watches long enough the *mean* is still a fingerprint. **The claim is
narrow deliberately** (§1's sixth check): this is not an anonymity mechanism,
it is the removal of one cheap correlation.

**The mechanism is not invented here — but "the relay lane's mechanism" is
two mechanisms, and the row has to say which.** That lane draws **memoryless**
delays for *fluff* and **bounded-uniform** `min + U(0, jitter)` for the *noise
cadence*, and they are not interchangeable.

> **Adopted: the bounded-uniform form, `min + U(0, jitter)` — the
> `NoiseCadence` *shape*, explicitly not its shipped values.**

**Bounded, not memoryless, and the reason is liveness rather than taste.**
Timed-sync is how a node learns it has fallen behind; an exponential draw is
unbounded above, so a node could go arbitrarily long without one. Fluff can
afford that — memorylessness is exactly what defeats timing inference on
propagation — but a liveness cadence cannot.

> **The window is derived under a fixed constraint: the mean stays at
> `P2P_DEFAULT_HANDSHAKE_INTERVAL` (60 s).** This row buys decorrelation, not a
> load change, and preserving the mean is what keeps the two separable.

**The mean constraint is necessary and *not* sufficient, and saying "any pair
satisfying it" would have admitted the status quo.** `min = 60 s, jitter = 0`
satisfies `min + jitter/2 = 60 s` exactly — and is the fixed phase this row
exists to remove. A sufficiently small window fails the falsifier below for the
same reason, less obviously.

> **So conformance is two conditions: the mean is preserved, *and* the window
> is non-zero and wide enough that measured phase correlation falls below the
> falsifier's threshold.** The second is a measurement, not an algebraic
> choice, which is why the split is owed rather than picked here — the trade is
> between worst-case staleness and how much phase separation the window
> actually buys.

> **Copying `NoiseCadence::shipped()` would be the wrong reading and is
> refused explicitly:** it is `3.333 s + U[0, 3.334 s]`, a mean of **5 s**
> (`rust/shekyl-relay-privacy/src/schedule.rs:741-753`), which would change
> timed-sync's frequency by 12× while claiming to change only its phase.

**Falsifier.** **Reopen if measured phase correlation between two connections
of the same node stays distinguishable after jitter** — the property is
directly measurable on the Q12-D6a rig, so this falsifier is expected to be
run, not merely stated.

### Cluster B second sub-round disposition

| Row | Disposition | Where |
| --- | --- | --- |
| PWC-E2 (no rate limit on the invoke entry points) | **Ruled** — per-connection token bucket | PWD-B1 |
| PWC-E1 (timed-sync fixed 60 s, no jitter) | **Ruled** — jittered; it is the observable case | PWD-B2 |
| PWC-E3 (five fixed, unjittered idle timers) | **Ruled** — jittered where observable | PWD-B2 |
| PWC-E4 (three protocol-handler timers, fixed) | **Ruled** — left fixed; no cross-connection observable | PWD-B2 |

**Sum check: 4 ruled + 0 absorbed + 0 deferred = 4 rows.** ✅

**Running total against the round's gate — authoritative:** **26 of 46**
bucket-4 rows dispositioned — cluster I's 10 + cluster T's 8 + sub-round 1's 4
+ this sub-round's 4. **20 rows remain**, all in cluster B: `PWC-A7`,
`PWC-B1`, `PWC-B2`, `PWC-B4`, `PWC-B5`, `PWC-B6`, `PWC-B7`, `PWC-C1`,
`PWC-C5`, `PWC-C6`, `PWC-C8`, `PWC-E4a`, `PWC-E5`, `PWC-E7`, `PWC-E8`,
`PWC-E9`, `PWC-E11`, `PWC-E13`, `PWC-E14`, `PWC-F4`.

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
