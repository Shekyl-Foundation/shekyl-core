# LV-3 — sockets and relay dispatch, and the connection object that lives there (P2P-3 slice 5)

**Status: DESIGN ROUND CLOSED 2026-09-21** — Rounds 1, 2 and 3 answered; **the
deliverable is the slice register at §6**, and implementation is deferred past
the alpha.9 freeze (§6.4). Pinned to `dev` `059aca264` for the round's original
anchors; **Rounds 2–3 and §2.10 are pinned to `f9e000f76`** and say so at each
block. **The deliverable of this round is a design, not code** — rule 20 is
explicit that migrating a subsystem is a planning activity with its own design
document, review cycle and test gates, never folded into feature work. Rule 26
cited explicitly. Owner:
[`P2P_3_IMPLEMENTATION_ROUND.md`](P2P_3_IMPLEMENTATION_ROUND.md) §4, **slice
5 — the LAST slice** (restructured 2026-09-21, §4.1 there).

**SCOPE NARROWED 2026-09-21 (steering).** *Records-was: "P2P-3 slice 1", and the
scope was the whole p2p surface.* **LV-3 is the `levin_notify` / `net_node`
seam — the socket layer and relay dispatch — and nothing else.** The peerlist,
admission policy, discovery policy and handshake state machine are **not Levin
work**; they are P2P-3 slices 1–4 and none of them waits on this one. The
boundary had been drawn **from a family name rather than from the work**, and a
"first slice" that contained all of them was the round, not a slice. §1's
first-slice argument is withdrawn at §1.

**Re-anchored 2026-09-22.** `dev` has moved 52 commits past this document's
pin, and **PR #821 deleted the stripe engine and the `pruning_seed` wire
field**. Every claim this document makes about that field is now a record of a
closed defect — see §2.8.8's banner. **The structural claims were re-verified
at `fdf17b729` and hold**: the peerlist is 874 lines with zero
connection-registry symbols, and no policy decision walks connections.

**One part of this round's scope is NOT deferred:** E1 tier-1's diagnostic half
and I8's remedy join the **alpha.9 cut** — see §2.10 and §2.9.4, and
[`P2P_3_IMPLEMENTATION_ROUND.md`](P2P_3_IMPLEMENTATION_ROUND.md) §7.4 for the
ruled scope.

---

## 0. The empirical case, before any argument

**PR #812 is at the maximum Rust reachable without a connection object, and
that is a measurement rather than a preference.** At the merge point it holds
**85 lines of shipped C++ (41 of them comments) against 409 lines of Rust.**

What remains in C++ is the `foreach_connection` walk, and it **cannot** move:
there is no connection object in Rust to walk. Exporting epee's context shape
across the FFI to make it movable is the port §0 forbids — it would carry
PWD-I8's category error into Rust intact.

So the seam's location is **checkable**, not asserted. Re-measure it at any
pin: the C++ that survives is exactly the code that needs a noun Rust does not
have.

**CORRECTION 2026-09-21 — what this measurement is ABOUT, which is narrower than
what it was used for.** It measured **admission**, where `foreach_connection` is
the blocker. It was then used to order **the whole round** — *"LV-3 must be slice
1"* — and **one decision's ceiling does not generalise to a round's ordering.**
Two things falsify the generalisation, and both are checkable
([`P2P_3_IMPLEMENTATION_ROUND.md`](P2P_3_IMPLEMENTATION_ROUND.md) §4.1):

- **The peerlist has no such ceiling.** 878 lines, zero socket or
  connection-registry symbols, does not include `net_node.h`.
- **§2.9.4's deletion removes admission's ceiling too**, because the walk was
  `has_too_many_connections` — after it goes, `is_host_limit` is a comparison
  against an atomic.

**So the measurement stands and its conclusion is re-scoped:** it establishes
where *admission's* seam was under the cap, not that this slice comes first. **It
comes last** (§4.1 there). *Still falsifiable in its own terms — if a later
measurement shows shipped C++ growing while the noun is missing, the seam moved.*

*(The converging-rows argument in §1 reached the same **first-slice** conclusion
from six consumers, and is withdrawn with it — see §1. Two derivations agreeing
on a wrong ordering is worth recording: both were about which decisions need the
noun, and neither was about which work is independent of it.)*

---

## 0.5 The guardrail, stated early because it decides everything else

> ### LV-3 IS NOT A PORT.

Scoped as *"move `net_node`'s connection handling to Rust"*, this slice would
faithfully reproduce `p2p_connection_context` — and **carry PWD-I8's category
error across the FFI boundary intact**, in a new language, with tests that pass
because they assert the reproduction.

That is rule 16's hardest form, and the project has already named it in its own
learnings: **"Rust interfaces shaped as projections over C++ semantics."** A
port is the failure mode, not the goal.

**The connection type is DESIGNED FROM THE RULINGS, not derived from the
structure it replaces.** The C++ is a **non-canonical reference** (Rick,
2026-09-19): where the two diverge, the divergence resolves **toward the spec,
never toward the C++**. A faithful reproduction of an inherited structure is a
finding to record, not a design to ship.

**Operational test for every field on the new type:** name the ruling it
serves. A field that exists because `p2p_connection_context` has one is a field
this round has failed to justify — delete it or find its ruling.

---

## 1. ~~Why this slice is first~~ — WITHDRAWN 2026-09-21; why the consumers still converge

**Nothing in Rust owns a connection.** `shekyl-levin` owns bytes;
`shekyl-peer-policy` owns stateless verdicts that C++ calls with values C++
walked itself. The connection lives in `net_node.inl`'s `foreach_connection`
lambda and epee's context.

**That absence is why the per-host cap became an address comparison inside a
loop — there was no object to hang a category on.** The missing noun has
**six** consumers (`P2P_3_IMPLEMENTATION_ROUND.md` §2): PWD-E1/E2, B1, B2,
B7's score, PWC-E5, and the failure-window row. *(Was seven — **PWD-I8 struck
2026-09-21 by §2.9.4**, whose remedy is a deletion plus a measurement and reads
no category. Counted from rows, not carried.)*

~~So this is not the cheapest slice. **It is the one the others are waiting
on.**~~ **WITHDRAWN 2026-09-21.** The conclusion does not follow from the
premise. **Six consumers needing the noun says the noun must exist before
THEY land — it says nothing about what else in the round is independent of
it**, and four of P2P-3's five slices are. Peerlist, admission, discovery and
handshake do not wait on a connection object; **this slice is where the cost
and the irreversibility are, so it goes last**, after four slices have
established the patterns and the differential harness
([`P2P_3_IMPLEMENTATION_ROUND.md`](P2P_3_IMPLEMENTATION_ROUND.md) §4.1).

**What survives, and it is the part worth keeping:** the six consumers are real,
they do converge on one noun, and **the noun must exist before any of them
lands**. That is an argument about *their* ordering relative to this slice, and
it is intact. It was never an argument about this slice's position in the
round — and reading it as one is what put a 2,189-line dispatch cutover in
front of an 878-line data structure with no dependencies.

---

## 2. The deliverable

**A connection as a typed, owned Rust object whose identity is — amended
2026-09-21 by §2.9.8 — the ENDPOINT WITH ITS PROVENANCE (Round 2's
claimed/observed split) plus the per-peer state that has nowhere else to
live.** *Records-was, until 2026-09-21: "whose identity is PWD-I8's category."
§2.9.4 struck I8 as a reader, so the category survives as **accounting** — a
derived projection for the operator and the rule-82 surface — and no longer as
the object's identity. The table below is therefore what the connection*
**reports**, *not what any admission decision reads:*

| Category | Meaning |
| --- | --- |
| **dialable and re-reachable** | a verified endpoint we could re-reach, by E1/E2's verifier |
| **connected but unreachable** | a peer we are talking to with no reachable endpoint behind it — **PWD-I7's two NAT'd daemons are this**, and naming it is what stops them contending for one address's slot |
| **overlay-addressed** | an anonymity-zone peer, whose address is `tor_address::unknown()` by construction and therefore carries no host identity at all |

### 2.1 Three constraints, each from a ruling

1. **Held per connection.** The category is a property of *this* connection to
   *this* peer, not of an address. That is the whole of PWD-I7's re-diagnosis:
   `is_same_host` failed because one quantity answered two questions.
2. **Ephemeral by construction.** P2P-2's ruled identity model is **fully
   ephemeral peer identity with no persistent wire identifiers** (PWD-I1
   deleted `peer_id` from the wire; PWD-E3 pins the nonce as per-connection and
   never persisted, because *"a nonce reused for two dials is `peer_id` with a
   shorter name"*). **The category must not become a persistent identifier by
   accident** — if it is stable across reconnects and observable, it is
   `peer_id` re-minted under a new name.
3. **Never on the wire.** The category is *our* classification of a peer, held
   locally. Publishing it is a co-residency oracle and a pre-handshake wire
   addition — both rejected in PWD-I7.

---

## 2.5 THE ROUND'S FIRST QUESTION — does the fix reach the wire?

**Ask this early, because the answer sets the schedule.** It is answerable at
the start of the round rather than discovered at the end of it.

> **Is the endpoint category entirely LOCALLY DERIVED, or does any part of it
> get SIGNALLED on the wire?**

**Everything sketched so far is locally derivable** from what a node already
observes: reachability class, admission accounting, eviction with a protection
set. Nothing in §2 requires a peer to *tell* us anything new.

| If the answer is… | Consequence for timing |
| --- | --- |
| **entirely local** | **PWD-I8 has NO genesis deadline.** Per-host admission is node-local policy — not consensus, not a wire rule, nothing depends on it — so the compiled default can move whenever I8 rules, before or after genesis. The round can take the time the eclipse analysis actually needs |
| **any wire-signalled part** | **that slice wants to land PRE-GENESIS** and the rest can follow. Coordinating an upgrade today means six seeds and two VMs; after genesis it is a network-wide coordination problem with third-party operators |

**So the cheapest moment for any wire-affecting piece is now, and the cheapest
moment for everything else is whenever it is ready.** Establishing which bucket
the design falls into is therefore the first thing the round does, not the
last.

*(Corollary worth stating: a design that is tempted toward signalling because
it is easier should be priced against this table. "Ask the peer" is cheap in a
round and expensive forever afterwards.)*

## 2.6 ROUND 1 — the endpoint question, ANSWERED

**Opened and answered 2026-09-21, pinned to `dev` `f9e000f76`.**

> **Answer: the category needs NO new wire field. It is derivable from the
> wire surface that already exists, plus what the socket already tells us.
> Therefore PWD-I8 has no genesis deadline on wire-compatibility grounds.**

**This was not obvious and is not "everything is local".** Part of the category
*does* travel on the wire — it already does, today, and has since before this
round. What follows is where each of the three categories comes from.

### 2.6.1 The claim already travels, and the acceptor already parses it

A node announces one of two things about itself in `basic_node_data.address`
(`p2p_protocol_defs.h`), and **which one is already the category signal**:

| Node's own state | What it announces | Anchor |
| --- | --- | --- |
| reachable **and** accepting inbound | a **port-only advert** — host zeroed, *"only the port is the claim"* | `net_node.inl:2390-2394` |
| dialer-only (unreachable, or `in-peers 0`) | the zone's **unknown-address sentinel** — `ipv4(0,0)`, `tor_address::unknown()`, `i2p_address::unknown()` | `net_node.inl:2399-2412` |

And the **accepting** side already turns that into the exact distinction I8
needs. `derive_advertised_endpoint` (`net_node.cpp:399-411`):

- returns `nullopt` when `advertised_port == 0`, commented **`// not dialable`**;
- otherwise combines the **observed** host — from our own socket, not from the
  peer — with the **claimed** port.

**So a two-state classification is already computed on every inbound
handshake.** I8 does not need to add it; it needs to *name* it, *own* it, and
hang it on an object.

### 2.6.2 Where each category comes from

| Category | Source | New wire? |
| --- | --- | --- |
| **overlay-addressed** | the **zone of the socket** — purely local, the peer is not consulted | **none** |
| **connected-but-unreachable** | the **existing sentinel** on the existing field; already parsed to `nullopt` | **none — already on the wire** |
| **dialable and re-reachable** | the existing port-only claim, **plus verification** | **none — see below** |

### 2.6.3 The gap is VERIFICATION, not signalling — and that is the whole answer

The third category is the only one that is not settled by what arrives. The
claim is **self-asserted**, which the code already knows: a derived endpoint
enters **GRAY**, with `last_seen = 0` and the comment *"an unverified claim has
never been 'seen'"* (`net_node.inl:2914`).

**Turning that claim into a verified category is PWD-E1/E2, which is already
ruled** — E1 **(c)** sources-propose-verifier-decides, E2 **(a)+(b)**. And
**E2(a)'s hairpin reuses the existing handshake nonce** (PWD-E3, per-connection
and never persisted), so it adds no field. A dial-back is an *action* over the
existing protocol, not a new message.

> **Conclusion for scheduling: no slice of PWD-I8 is wire-affecting, so none of
> it is cheaper before genesis than after.** The round can take the time the
> eclipse analysis in §3 actually needs. *(One caveat carried forward, not
> waved: E2(b) was written as a reuse of the back-ping, which PWD-B10 deleted,
> so it "must specify its own dial-back mechanism or be withdrawn". That
> mechanism is an action over existing messages — but if a future design of it
> reaches for a new field, this conclusion is void and the slice returns to the
> pre-genesis bucket.)*

### 2.6.4 The finding that falls out, and it is a REQUIREMENT not an observation

**A claim is not a category.** The wire carries what a peer *says* about its
own reachability, and that is an **attacker-controlled input**.

**So wherever the category affects admission, it must be VERIFIED rather than
CLAIMED** — otherwise a peer selects its own treatment by lying:

- if *connected-but-unreachable* peers are evicted first, a peer claims
  **dialable** to be protected;
- if they are protected, a peer claims **unreachable** to be protected.

**Either way the peer, not the node, decides.** That is §3.2's NAT-sorting trap
reached from the other side — and it means **§3's protection-set design and
this round's verification requirement are the same question**, not two. An
unverified category used for eviction ranking is strictly worse than no
category, because it hands the adversary the ranking function.

**Consequence for slice scope:** the connection object may hold an
**unverified** claim, but it must be **typed as unverified** — the two states
cannot share a representation, or a later consumer will read a claim as a
fact. That is the same discipline `GRAY` already applies to the peerlist, at a
different altitude.

## 2.7 The CLAIMED / OBSERVED split, and Round 2's question

**Sharper than "verified, not claimed" (Rick, 2026-09-21), and it is the
distinction the connection object should be built on.** The category has two
halves with different trust properties, and **every decision must be able to
say which half it reads:**

| Half | What it is | Trust |
| --- | --- | --- |
| **CLAIMED** | what the advert says — the port-only claim | **attacker-controlled, self-selected.** `last_seen = 0` on entry to GRAY is a **delay, not a defence** |
| **OBSERVED** | what we witnessed ourselves — *"I hold an established inbound connection from this socket"*, *"I dialled this endpoint and it answered"* | **a fact we own.** Not forgeable by the peer |

### 2.7.1 ROUND 2's QUESTION — which decisions read the CLAIMED half?

**This is what sets the dependency, and it is answerable early:**

| If… | Then |
| --- | --- |
| admission accounting and eviction are built **entirely on observed facts** | **I8 needs no verification, and PWD-E2 stays a PARALLEL slice** |
| **any** admission or eviction decision reads the claimed half | **E2 becomes a HARD DEPENDENCY** and the slice register reorders |

**Working hypothesis, recorded as a hypothesis and not an answer** (Rick): most
of what I8 needs is observable. **Whether a peer is *dialable* may not be
something admission needs to know at all** — that is a **peerlist-identity**
property, which is where the address key belongs and always did. *Admission
needs to know what admitting this connection COSTS US.* Round 2 answers this
explicitly rather than letting it be assumed.

### 2.7.2 The self-selection trap is not confined to eviction — with one correction

**Any benefit attached to a category invites claiming it**, including
benign-looking ones. So the requirement belongs in this round's
**requirements**, not its analysis.

**But the claim that the eclipse primitive is already free does not survive
contact with the code, and the reason is the good news.** Checked at
`f9e000f76`:

- a derived entry enters **GRAY**, and **`get_peerlist_head` reads the WHITE
  list only** (`net_node.inl:995`) — *"Gray is never disclosed to peers"*
  (`:2907`);
- **white is earned by an actual outbound dial** — `set_peer_just_seen` fires
  from the `COMMAND_HANDSHAKE` response handler (`:1283`) and the
  `COMMAND_TIMED_SYNC` response handler (`:1343`), i.e. **after we dialled and
  they answered**;
- so a **false** dialability claim buys **one wasted dial and eviction**, not
  peerlist placement. Gossip is contingent on an **observed** fact.

**The incentive to over-claim exists; the existing design already converts it
into a cost rather than a benefit.** I8 does not inherit a free eclipse
primitive — it inherits a working defence, and it must not break it.

### 2.7.3 The precedent is in the same file: GRAY/WHITE *is* the split

**The peerlist already implements exactly the discipline this round needs, at
the promotion boundary:** a **claim** enters gray, an **observation** promotes
it to white, and only white is disclosed. That is *claimed* and *observed* held
in different states with an explicit rule for crossing between them.

> **So I8 should COPY this, not invent it** — and the burden on any design that
> departs from it is to say why the peerlist's answer was wrong. The two states
> must not share a representation in the connection object either, or a later
> consumer reads a claim as a fact.

*(This is also the honest reason the category "needs naming, not inventing":
the code has been making this distinction correctly in one place, without a
name, and the unnamed version could not be reused by the six consumers in
§1.)*

### 2.7.4 The invariant, verified exhaustively — WHITE *is* a verified dialability claim

**Stronger than "gossip is contingent on an observation": there is no path by
which a claim reaches another node's view.** Every site checked at
`f9e000f76`:

| Direction | Site | Lands in |
| --- | --- | --- |
| gossip **in** from a peer | `merge_peerlist` → `append_with_peer_gray` (`net_peerlist.h:239`) | **gray** |
| derived advert from a handshake | `net_node.inl:2920`, `last_seen = 0` | **gray** |
| disclosure **out** | `get_peerlist_head` reads `m_peers_white` (`net_peerlist.h:285`) | **white only** |

And **all four gray→white promotions run after an outbound dial we made
ourselves**:

| Site | Trigger |
| --- | --- |
| `net_node.inl:1587` | `append_with_peer_white` after **our** handshake succeeds |
| `:1283` | `COMMAND_HANDSHAKE` **response** handler — a dial we initiated |
| `:1343` | `COMMAND_TIMED_SYNC` **response** handler — likewise |
| `:3313` | `gray_peerlist_housekeeping`, **only** in the `else` after `check_connection_and_handshake_with_peer` returns true; the failure branch **evicts** |

> **So a white entry's ADDRESS is not merely "observed" — it is a VERIFIED
> DIALABILITY CLAIM: *I dialled this peer and it answered*. The peerlist has
> been running PWD-E2's verification, for peers, all along — unnamed, at the
> promotion boundary.**

#### CORRECTION: the invariant holds per FIELD, not per RECORD

**An earlier writing of this section said *"there is no path by which a claim
reaches another node's view."* That is true of the ADDRESS and false of the
record.** Verified at `f9e000f76`:

- `peerlist_entry_base` carries `adr`, `last_seen` **and `pruning_seed`**, all
  three serialized (`p2p_protocol_defs.h`);
- the white append sets `pe_local.pruning_seed = con->m_pruning_seed`
  (`net_node.inl:1586`), and `m_pruning_seed` is **the peer's own claim** —
  `context.m_pruning_seed = hshd.pruning_seed`
  (`cryptonote_protocol_handler.inl:438`);
- validation at `:422-428` rejects only a **malformed** seed, not a **false**
  one.

**So a white entry is a MIXED-TRUST RECORD: a verified address carrying an
unverified `pruning_seed`, and the whole record is disclosed.** The claim rides
the verification into gossip.

> **The design consequence is the important part: VERIFICATION IS PER-FIELD,
> NOT PER-RECORD.** A category must not inherit trust from being adjacent to
> verified data.

**And one notch harder than that (Rick):** `peerlist_entry` is **a record whose
NAME implies a single trust level while carrying two.** A consumer holding the
struct has **nothing in the type** telling it that `adr` was *earned* and
`pruning_seed` was *asserted* — both are plain members, serialized side by side
in both forms (`p2p_protocol_defs.h:65` KV, `:71` VARINT).

> **So provenance belongs in the FIELD'S TYPE, not in a doc comment.** Where no
> check exists, encode the constraint in a type — that is what makes *"each
> field carries its own provenance"* **enforceable rather than remembered**, and
> it is the same discipline `DropVerdict` already applies to a classification
> byte. A `Claimed<T>` / `Observed<T>` distinction costs nothing at runtime and
> makes the mixed-trust record impossible to read wrongly by accident.

**The code already names the problem and then does it anyway:**
`cryptonote_protocol_handler.inl:426` logs *"peer **claim** unexpected pruning
seed"* — and `:438` assigns `context.m_pruning_seed = hshd.pruning_seed`
**unconditionally**. The check at `:421-430` tests **well-formedness** only
(`log_stripes` against the constant, stripe within range), so **any well-formed
seed a peer asserts is accepted as fact.**

*(This is the second time in this round that a claim about the code was
asserted from the mechanism and was wrong at a site nobody had opened. It is
recorded rather than repaired silently because the pattern is the finding.)*

*(This row's earlier draft asserted the weaker property from the mechanism
without checking every site. Recorded because it is this lane's recurring
failure shape — plausible from the mechanism, wrong at the code — and the
exhaustive version is the one the design can lean on.)*

### 2.7.5 CANDIDATE for Round 2 — third-party endpoint proposals, at zero new wire

**A candidate, not a conclusion.** PWD-E1's problem is circular: a node cannot
verify its own endpoint because it does not know what its endpoint *is*.
**But the network already verified it, from the other side.**

If some peer dialled us successfully, it promoted our derived entry to
**white** — and white is exactly what gets disclosed. **So every peerlist head
we receive is a set of third-party-verified dialable endpoints.** If our own
endpoint is among them, *somebody verified us*.

**This reuses `get_peerlist_head`'s existing disclosure and adds no wire.**

| Step | Mechanism | Status |
| --- | --- | --- |
| **propose** | our own port appears in a received peerlist head | existing disclosure, no new field |
| **decide** | dial the port-matching candidate; `detect_self_handshake` (`net_node.inl:1411`) matches our own in-flight nonce, within-zone and erase-on-match | existing machinery (PWD-E3) |

**That is exactly E1(c) — sources propose, a verifier decides** — with the
source being *the network's own verified state* rather than a router's claim
or an operator's flag.

**Why the negative signal is better than the one PWD-I7 proposed.** *"Nothing
matching our port has appeared across many received peerlists"* is **positively
grounded in the absence of anybody's successful dial**. The tier-1 heuristic
this row proposed earlier — *zero inbound in `T`* — is grounded in **our own
absence of observation**, which is weaker: it cannot distinguish "unreachable"
from "reachable but unpopular". **On PWD-I7's daemon B this would have
concluded unreachable correctly, and from the network's verified state rather
than from a timeout.**

**Three caveats to carry if Round 2 takes it up:**

1. **A NAT'd node cannot recognise its own endpoint**, since it does not know
   its WAN address. **Port-matching alone is suggestive, not proof** — which is
   precisely why it is a *proposal* and the hairpin is the *verifier*.
2. **It is a hairpin underneath**, so it inherits E2(a)'s **under-reporting**
   where routers do not support hairpin. Safe direction, and real.
3. **The candidate set is attacker-influenced** — a peer chooses which white
   entries it discloses, so it can offer a **port-matching decoy**. The hairpin
   defeats it: *a decoy cannot return our nonce.* **Another instance of §2.7's
   requirement — a claim proposes, an observation decides.**

### 2.7.6 A reason to prefer E2(a) beyond cost

**E2(a)'s hairpin reuses the existing handshake nonce, so it PRESERVES §2.6's
no-new-wire conclusion.** E2(b) must specify its own dial-back mechanism (the
back-ping it was written against was deleted by PWD-B10), and **if that reaches
for a new field the no-genesis-deadline conclusion is void**. So the round has a
reason to prefer the hairpin that is **structural, not merely cheaper**: it
keeps I8 out of the pre-genesis bucket.

### 2.7.7 RETRACTION — non-transitivity is not the defect; what survives is narrower

**Retracted 2026-09-22 (steering), and the retraction is mine to carry because
the framing was load-bearing:** calling the non-transitivity of a peerlist
advert a **defect** was wrong. **An advert has always meant *"I reached this,"*
never *"you can reach this,"* and that is the honest posture for zero-trust
gossip.** No stronger claim is available to anyone — so treating the weaker one
as a flaw **imports a guarantee the network was never offering.**

**What survives is sharper than what was retracted.** Both claims are
non-transitive; they differ in whether they are **predictive**:

| Hint | Non-transitive? | Predictive for the recipient? | Expected value |
| --- | --- | --- | --- |
| *"I reached this **listener** at this address"* | yes | **may hold** — the listener's reachability **outlives our session** | positive |
| *"I reached this daemon at its **NAT-mapped source port**"* | yes | **known not to hold** — the mapping is **bound to our connection** | negative |

**Same epistemic status, opposite expected value.** The peerlist is a **hint
mechanism**, and feeding it hints *known* to be false **degrades it without
lying about its semantics.** That is the whole objection, and it is a quality
argument rather than a truth argument.

**The code already draws exactly this line, which is why the objection lands
nowhere.** `derive_advertised_endpoint`
([`net_node.cpp:398-399`](../../src/p2p/net_node.cpp#L398)) takes **the observed
host and the claimed listen port as separate inputs**, and the call site's own
comment states the reasoning
([`net_node.inl:2872-2881`](../../src/p2p/net_node.inl#L2872)): *"only its PORT
is admissible: the host is the one this node OBSERVED on the socket … the
derived entry enters GRAY (white is earned by an actual outbound dial)."*
**The claimed port might be true; the observed source port is known not to be**
— and the observed source port is never advertised.

### 2.7.7a The claimed port is the ONLY field in the handshake whose truth value is resolved

**A property of the protocol worth naming, because nothing else in it has this
shape.** Everything else a peer asserts is **either taken on faith or never
checked**. The claimed listen port is:

**asserted** into gray → **tested** by an actual outbound dial → **promoted or
evicted.**

> **That is a complete claim-to-observation cycle, and it is the one place the
> protocol performs one at all.** §2.7's requirement — *a claim proposes, an
> observation decides* — is not an aspiration here. It is implemented, for
> exactly one field.

**What that makes port forwarding.** Not a special case the mechanism
*tolerates* — it is **the configuration the mechanism was built to communicate,
and the only one it can verify.** A port-forwarded node and a datacenter node
are **indistinguishable** to it, **correctly**, because **reachability is all it
claims to measure.** The white-list criterion is exactly *"there is a reachable
peer operating at this address"* — and nothing else. No identity, no class, no
quality.

**The consequence to carry into E1/E2, and it reframes what E1 is missing.**

> **The claimed port already has a working verifier. What E1 lacks is not
> verification — it is a way for the node to know what to claim.**

**One asymmetry to carry with it, because it is why §2.7.5's route degenerated.**
The verifier is **one-directional**: it resolves claims **about others**, from
our side, and its verdict does not return to the claimant. §2.10.3 showed the
obvious feedback route — spotting our own entry in a received peerlist head —
collapses at the default port. **E2's verification is not the hard half. E1's
proposal source is.**

> ***"Gap" is RETRACTED for the feedback half*** (2026-09-22). The absence of a
> feedback channel is **load-bearing, not missing** — §2.11 states the rule it
> serves. E1 has **one** gap (what to claim) and **one property** (no
> transmissible self-attestation).

### 2.7.8 THREE PORTS — the vocabulary, because conflating them is how this got muddled

| Port | What it is | Who can use it | Advertised? |
| --- | --- | --- | --- |
| **observed source port** | part of the 4-tuple; **distinguishes connections** | us, for this connection only | **never** |
| **claimed listen port** | what the peer says it listens on; goes in the advert; **may be true**, and **promotion resolves it** | anyone, if true | yes |
| **local bind port** | what we listen on | — | via our own advert |

**The consequence for admission, and it is the smallest possible change:**
admission counts **connections**, and **the 4-tuple already distinguishes them
at the socket layer.** So *"count connections, not hosts"* **needs no new
information at all** — only the **removal of a collapse**. That is why §2.9.4's
remedy is a deletion rather than a mechanism: the information admission needs
was never missing.

### 2.7.9 Divergent white lists are a PRIVACY PROPERTY, not an accepted cost

**Stated as a principle in its own right**, because it is what makes topology
inference expensive rather than free, and because the earlier framing treated
divergence as a tolerable side-effect of local verification.

**A globally consistent peerlist would mean any ONE node's view reveals the
whole topology.** Divergence means an observer must **aggregate many nodes** to
reconstruct it — and **each node's view is partly a function of its own dial
history, which is private and unreproducible.** An observer cannot recompute
what it did not watch.

**The inherited code already reasons this way at one site and not as a
principle:** `get_peerlist_head`'s `anonymize` path
([`net_peerlist.h:282`](../../src/p2p/net_peerlist.h#L282)) randomises which
white entries it returns specifically so a repeat query cannot be differenced,
citing Cao et al. **That is this principle applied to one query. The principle
is more general, and stating it is what stops a future "consistency"
optimisation from being read as an improvement.**

**Load-bearing consequence:** *any proposal that makes white lists converge
across nodes is a privacy regression*, and must be refused on that ground —
not traded against the sync or diagnostic convenience that motivates it.

## 2.8 ROUND 2 — the classification, and what it does and does not settle

**First pass by Rick, scrutinised here. The answer survives, with one consumer
added and one axis it does not cover.**

### 2.8.1 The classification

**Reads OBSERVED only:** admission (current connection count, the socket's
host, the zone — *what admitting costs us*); promotion (verification by
definition); disclosure of the **address**; PWD-B1's token bucket and B2's
jitter schedule (per-connection state); B7's score and PWC-E5's idle kick
(observed behaviour); the failure-window class (the outcome of an attempt we
made).

**Reads CLAIMED — three, not two:**

| Consumer | What it reads | Resolution | Bounded? |
| --- | --- | --- | --- |
| gray entry construction | claimed port, by design (`derive_advertised_endpoint`) | our dial succeeds or evicts | **yes — one dial** |
| outbound candidate selection | dials from gray, so acts on claims | same | **yes — one dial** |
| **block-request routing** *(added)* | `pruning_seed` at `cryptonote_protocol_handler.inl:1729`, `:1903` — *which peer has the block we want* | the request fails and is re-routed | **no — repeats until the peer is dropped for other reasons** |

**The third is a DIFFERENT CATEGORY OF EXPOSURE, not a third instance.** The
first two are the quarantine working as designed: a claim is a hypothesis, it
costs **one dial**, and an observation resolves it. **`pruning_seed` never
resolves.** `has_unpruned_block` (`:1903`) and the stripe test (`:1729`) read
the claim on **every routing decision, indefinitely**, and **no boundary ever
promotes or refutes it** — so the cost is not bounded by a dial, it is
**unbounded in time**.

**It is also a self-selection surface of exactly the Round 1 shape:** *a peer
chooses a seed that determines what it gets asked for.*

*(Not this slice's defect and not this slice's fix. Named so the round does not
inherit a clean-looking split that the code does not have.)*

### 2.8.2 REQUIREMENT — eviction and the protection set read OBSERVED only

**No exceptions.** Rank on connection age, on useful work we witnessed, on
whether **we** dialled it — facts the peer cannot assert. **The moment a
protection set reads dialability, the peer picks its own treatment.**

### 2.8.3 Provisional answer to Round 2

> **No admission or eviction decision needs the claimed half, so PWD-E2 stays
> a PARALLEL slice rather than a blocking dependency** — subject to §2.8.5.

### 2.8.4 The caveat that matters more than the answer

**Claimed-versus-observed is the TRUST axis. It does not settle the RELEVANCE
axis — and I8's original defect lives entirely inside the observed half.**

The per-host cap reads the **observed socket host**. Unforgeable. **Still the
wrong quantity.** So *"use observed facts"* is a constraint **the current
broken code already satisfies**, and a round that landed only that constraint
would have changed nothing.

> **So every decision owes TWO declarations, not one:**
>
> 1. **which half it reads** — stops the peer choosing its own treatment;
> 2. **what the quantity is a PROXY FOR** — which is what this round was opened
>    to fix.
>
> **The first is checkable and the second is a judgement, which is exactly why
> it would be easy to land the first and call it done.**

### 2.8.5 The one route from admission to the claimed half — Round 2 must RULE on it

**Named so the round tests it rather than discovers it:** *reserving inbound
capacity for dialable peers*, so the reachable core is not crowded out by
dialer-only nodes.

- It is a **plausible policy someone will propose**.
- It **reads dialability at admission time**, which would make **E2 blocking**
  and reorder the slice register.
- It is a **NAT-sorting instance in its own right** — second-class treatment
  **at the door** rather than at eviction, which is §3.2's trap moved earlier
  rather than avoided.

#### RULED 2026-09-21: REJECTED — and on mechanical grounds, not on the values argument

**The NAT-sorting objection is correct but it is a *values* argument.** There
is a **mechanical** one that does not need it, and the round should rest on
that:

1. **The cost is not one dial — it is a reservation held for the life of the
   connection.** Every other claimed consumer in §2.8.1 is bounded by an
   attempt that resolves it. This one grants the benefit **at admission** and
   holds it **indefinitely**.
2. **There is no later observation that can resolve it**, because *the
   reservation was already granted*. The Round 1 requirement — *a claim
   proposes, an observation decides* — **cannot be satisfied here**: the
   deciding moment is the door, and at the door nothing has been observed yet.
3. **Making it safe would require verifying dialability BEFORE admitting** —
   a hairpin or dial-back **inline in the accept path.** That is **a reflection
   primitive at the door**, which is precisely the amplifier concern that
   deferred PWD-E1/E2 in the first place.

> **So this is not merely an unattractive policy — it is the one surface where
> claimed-at-admission has NO bounded resolution.** Rejected.

**Reopening criteria (rule 21):** reopen if a dialability signal becomes
available at admission time **without** an inline network round-trip — for
instance if §2.7.5's third-party proposal matures into something a node already
holds *before* the connection arrives, in which case the fact would be observed
rather than claimed and this objection dissolves. *Note that such a signal
would still face the NAT-sorting objection on its own merits* — the mechanical
rejection here does not pre-clear the values question.

### 2.8.6 ROUND 2 CLOSES — *amended 2026-09-21, see §2.8.7*

> ~~**No admission or eviction decision reads the claimed half.**~~ **FALSE as
> written — withdrawn 2026-09-21.** The corrected statement is in §2.8.7. **PWD-E2
> stays a PARALLEL slice, and the slice register in
> [`P2P_3_IMPLEMENTATION_ROUND.md`](P2P_3_IMPLEMENTATION_ROUND.md) §4 STANDS** —
> that half is unaffected, because the sites §2.8.7 names are `pruning_seed`, a
> field already ruled retired, not an endpoint claim.

### 2.8.7 CORRECTION — one eviction site and one selection site DO read a claimed field

**The error was mine and it is the exact error §2.8.4 warned about:** the
checkable half looked like an answer, so the sweep that produced §2.8.6 asked
"does an admission or eviction decision read a claimed *endpoint*?" — and
stopped. `pruning_seed` is a claimed field on the same records, it is read by
both a selection decision and an eviction decision, and the sweep did not see it
because it was keyed to the wrong noun. Verified at `f9e000f76`, the pin this
document already carries:

**Site 1 — eviction.** `should_drop_connection`
([`cryptonote_protocol_handler.inl:1977`](../../src/cryptonote_protocol/cryptonote_protocol_handler.inl#L1977),
called at [`:1446`](../../src/cryptonote_protocol/cryptonote_protocol_handler.inl#L1446),
[`:1699`](../../src/cryptonote_protocol/cryptonote_protocol_handler.inl#L1699) and
[`:2116`](../../src/cryptonote_protocol/cryptonote_protocol_handler.inl#L2116))
branches on `context.m_pruning_seed` — handshake-supplied, validated for
well-formedness only ([`:421-430`](../../src/cryptonote_protocol/cryptonote_protocol_handler.inl#L421)),
**never observed**. Seed `0` → not dropped (`:1979`). Stripe equal to the needed
one → **not dropped** (`:1986-1989`). So a claimed attribute *protects a peer
from eviction*. *(A third branch at `:1992` also reads the seed but is gated on
`m_sync_pruned_blocks`, whose descriptor supplies no default and is therefore
`false` unless `--sync-pruned-blocks` is passed — and that flag is **already
deleted under `PDM-Q5`'s rejection**. It is dead at the default and inherits a
different ruling, so it is not counted among the live sites here.)*

**Site 2 — outbound dial preference.** `try_to_connect_and_handshake_with_new_peer`'s
candidate filter ([`net_node.inl:1832-1836`](../../src/p2p/net_node.inl#L1832))
sorts on the **gossiped** `pruning_seed` of a peerlist entry: matching stripe →
`filtered.insert(filtered.begin(), peer)`; seed `0` → `push_back`; mismatch →
**skipped entirely**. The white-list draw is then cubic-front-biased
([`:1359`](../../src/p2p/net_node.inl#L1359),
`res = x³ / (max²·16³)` with `x ~ U{0..16·max}`), so `P(index 0) ≈ max^(-1/3)` —
**≈ 0.37 at the 20-candidate white-list limit**. The gray draw is uniform
(`crypto::rand_idx`), so the front-insert buys nothing there: this is a
white-list effect, which is the list that matters.

**Direction of error — it favours the claimant at both sites.** Claim the needed
stripe and you are retained under eviction and moved to the front of the dial
queue. Claim nothing and you are merely not preferred. There is no site anywhere
that checks whether the peer actually serves the stripe it claimed before acting
on the claim. This is Round 1's shape in its purest form: **a claim that decides
rather than proposes.**

**It is not gated on anyone pruning.** `get_next_needed_pruning_stripe`
([`:2792`](../../src/cryptonote_protocol/cryptonote_protocol_handler.inl#L2792))
derives the needed stripe from **heights only** —
`get_pruning_stripe(want_height, blockchain_height, LOG_STRIPES)` returns `0`
**only** when `want_height + CRYPTONOTE_PRUNING_TIP_BLOCKS >= blockchain_height`
(`src/common/pruning.cpp:55-60` and `CRYPTONOTE_PRUNING_TIP_BLOCKS` = 5500 at
`cryptonote_config.h:344`, **both at `f9e000f76`; PR #821 deleted the file and
the constant, so these are historical and deliberately unlinked**). A node more
than 5500 blocks behind the tip computes a non-zero needed stripe **regardless of
its own seed**. Every node syncing from genesis on a chain longer than 5500
blocks is in that state for the whole sync — so the surface is live for every
node at least once, and again after any long outage. It is inert on testnet today
only because the chain is 7672 blocks long and the fleet is at the tip.

**The honest background is *absent*, not `0` — which makes the marker maximally
effective.** Measured on the six seeds 2026-09-21: `get_blockchain_pruning_seed()`
is `0` everywhere (§2.8.8), and `KV_SERIALIZE_OPT`
([`keyvalue_serialization.h:89-95`](../../contrib/epee/include/serialization/keyvalue_serialization.h#L89))
**skips the field on store when it equals the default**, so an archival node's
gossiped entries omit `pruning_seed` entirely. `sanitize_peerlist`
([`net_node.inl:2319`](../../src/p2p/net_node.inl#L2319)) accepts all eight
well-formed values. On an all-archival network, therefore, **advertising any
stripe is strictly better than advertising none** for reaching the front of a
syncing node's dial queue, and a marked entry has nothing honest to hide among.

**What §2.8.6 should have said, and does now:**

> **No admission or eviction decision reads a claimed *endpoint*.** One eviction
> decision and one outbound-selection decision read a claimed **`pruning_seed`**,
> in the claimant's favour, with no observation resolving it — and that field is
> already ruled retired (`PDM-Q7`).

**Ownership — this is not a new cluster-I row.** `PDM-Q7`
([`ARCHIVAL_PRUNED_DAEMON_MODE.md`](ARCHIVAL_PRUNED_DAEMON_MODE.md), RULED
2026-09-18) retires the wire slot, and [`FOLLOWUPS.md`](../FOLLOWUPS.md) already
carries the row under **`LV-` / `PWC-`**. What is *not* in Q7's disposition table
is the cell this correction fills: the table dispositions the **C++ engine**
symbols (die at `DRS-E*`), the **Rust receiver** (ignores non-zero), the **Rust
sender** (sends `0`) and the **RPC** fields (drop at the version bump). The **C++
receiver's preference behaviour** — `:1832` and `should_drop_connection` — is the
empty cell. Q7's ruling text names "complement-seeking peer selection" as part of
the engine's purpose, so the mechanism was seen; it was not dispositioned, and
`PDM-Q-S0` forbids a C++ landing before the cutover, so it cannot be quietly
fixed either.

**Two arms, for steering — neither built here.**

1. **Delete now** as a rule-16 migration of a claimed read: drop the `else if` at
   `:1834` and the stripe branches in `should_drop_connection`. Requires steering
   to name a C++ landing window in writing — `PDM-Q-S0`'s reopening criterion 1.
2. **Record the window.** Leave the code and write the exposure into Q7's table
   explicitly, so it is a dated known exposure rather than an empty cell.

**Falsifier for this correction:** a site that resolves a claimed `pruning_seed`
against observed behaviour before preferring or retaining the peer. `rg -n
'm_pruning_seed|peer\.pruning_seed' src/` returning a comparison against blocks
actually served would falsify "no observation resolves it."

> **OVERTAKEN 2026-09-22 — PR #821 deleted the stripe engine and the
> `pruning_seed` wire field outright.** **Every `file:line` in §2.8.7 and
> §2.9.3 below is at `f9e000f76` and DOES NOT resolve in the current tree** —
> the files mostly survive, so the links render, but the lines are now
> unrelated code. They are kept as the record of what was read, not as
> navigation.** (`dev` `fdf17b729`; 311 stripe sites →
> 4, all comments). **§2.8.7's two claimed-seed sites no longer exist**, so the
> defect it reports is closed by deletion rather than by design. The finding,
> the measurement below, and the correction to §2.8.6 are kept as the record:
> **§2.8.6's amended statement — *no admission or eviction decision reads a
> claimed endpoint* — is now true without qualification**, because the one
> counter-example was removed. *Re-verified at `fdf17b729`:
> `git grep -c should_drop_connection -- src/` returns 0.*

### 2.8.8 The fleet measurement behind §2.8.7 — `get_blockchain_pruning_seed()` is `0` on all six seeds

Run 2026-09-21 against the six testnet seeds (`skl-seedaus`, `skl-seedbrz`,
`skl-seedeu`, `skl-seedjp`, `skl-seeduse`, `skl-seedusw`). The RPC route is
closed — `prune_blockchain` is the only method that surfaces the getter, and the
fleet runs `restricted-rpc=1`, which refuses it (`-32601 Method not allowed in
restricted mode`, verified on `skl-seedeu`). So the seed was read where it is
stored: the LMDB `properties` table, whose key is written **only** by
`prune_worker` ([`db_lmdb.cpp:2363-2375`](../../src/blockchain_db/lmdb/db_lmdb.cpp#L2363)).

| | Result |
| --- | --- |
| `prune` directive in any `/etc/shekyl/*.conf` on any host | **none** (18 files) |
| `pruning_seed` key present in any LMDB (10 databases across 6 hosts) | **0 of 10** |
| **Positive control**, same instrument, `skl-seedeu`'s testnet LMDB | `properties` 38, `hf_versions` 36, `txpool_meta` 35, `output_amounts` 33, `txs_pruned` 9, `block_heights` 7 |

The control is the point: the instrument can find keys in these files, and finds
no `pruning_seed`. **The random-stripe path at
[`db_lmdb.cpp:2370`](../../src/blockchain_db/lmdb/db_lmdb.cpp#L2370) is not live
in production.** It is reachable only through `prune_blockchain()` /
`update_blockchain_pruning()`, both gated on `--prune-blockchain`
([`cryptonote_core.cpp:668`](../../src/cryptonote_core/cryptonote_core.cpp#L668);
descriptor default `false`, [`:171-175`](../../src/cryptonote_core/cryptonote_core.cpp#L171)),
or through the RPC the fleet refuses.

**What this does and does not settle.** It settles that the emitted values are
**uniform**, not scattered — so there is no assigned per-node tag on the wire
today, and the exposure is the eight unused marker values rather than a live
three-bit identifier. It does **not** reduce §2.8.7, which it strengthens: a
uniform-absent background is the best possible background for a marker.

**What Round 3 inherits, and it is the harder half:** §2.8.4's second
declaration — *what is the quantity a proxy for?* Rounds 1 and 2 settled the
**trust** axis, which is checkable. The **relevance** axis is a judgement, it is
where I8's original defect actually lives, and nothing established so far
constrains it.

## 2.9 ROUND 3 — the relevance axis, and the answer was already in another lane

**Opened and answered 2026-09-21.** Anchors at `f9e000f76`, this document's pin.

### 2.9.1 The question before the question

*"Is Q relevant to P?"* presumes you need a proxy. The first thing each decision
owes is **is P directly observable?** If it is, a proxy is not a bad choice, it
is an **unnecessary** one.

That bites immediately, because the per-host cap was doing **two** jobs:

| Job | Target property `P` | Observable? |
| --- | --- | --- |
| **Resource bound** — don't exhaust descriptors, memory, sockets | connection count, memory, fds | **YES, directly.** No proxy is needed at all |
| **Diversity** — don't let one party occupy enough of my peer set to determine what I see | **party identity** | **NO, by construction** — permissionless network, ephemeral identity, and PWD-I1 already deleted the only durable identifier |

**One half needed no proxy; the other had no observable target.** Different
failures, different fixes, and **the single quantity hid both.** That is why the
resource half's fix is a real ceiling rather than a better key.

### 2.9.2 When `P` is unobservable, the quantity is not a proxy for identity

This is the reframing, and it is the part worth keeping past this round.

You cannot measure *is this the same party*. You can measure **what it costs an
adversary to span the axis**. Bitcoin's netgroup diversity does not claim a /16
is one party — that claim would be **false**. It claims that requiring an
adversary to occupy many /16s **costs money**. The quantity is not an identity
proxy at all; it is a **cost-imposition axis**, which is a different thing with
a different test:

> **What does one unit of `Q` cost an adversary, and what does it cost an honest
> node?**

**The per-host cap, run through it:** an adversary buys a /24 for a few dollars a
month — roughly three cents per address, and **PWD-E4 already ruled this**. A
CGNAT subscriber **cannot obtain a second address at any price** — not
expensive, *impossible*. So the ratio is not unfavourable, it is **inverted**:
**the mechanism binds exactly the population that cannot evade it, and is free
for the population it was aimed at.**

**That is why no `k` works.** Tuning a constant cannot fix a ratio that points
the wrong way. The cap was never mistuned.

### 2.9.3 The measurement that settles it — the measured adversary is CAP-COMPLIANT AT 1

The relevance question for inbound admission **was already answered in the relay
lane**, and not as an argument — as a number.
[`DAEMON_RELAY_PRIVACY.md`](DAEMON_RELAY_PRIVACY.md) §6.5's
`simulate_transport_observation` measures the project's **primary** adversary: a
supernode opening cheap **inbound** edges to a fraction of honest nodes, running
the first-spy estimator at 512 nodes and 12 peers.

| supernode reach | clearnet first-spy π₀ | Tor/I2P |
| --- | --- | --- |
| dials 5 % | 0.0978 | **0.0000** |
| dials 10 % | 0.1760 | **0.0000** |
| dials 30 % | 0.4228 | **0.0000** |

**And the structural detail that decides I8 — verified in the simulation, not in
its prose.** `watched` is **one boolean per honest node**
([`transport.rs:118`](../../rust/shekyl-relay-privacy/src/conformance/transport.rs#L118),
consumed at [`:145`](../../rust/shekyl-relay-privacy/src/conformance/transport.rs#L145)):
the supernode opens **exactly one inbound edge per victim**. Each victim
therefore sees **one** connection from the adversary's address.

> **A per-host inbound cap of `1` admits that adversary in full.**

So the cap provides **zero** protection against the only *measured* inbound
adversary in the project. It is not weakly relevant to the diversity job — it is
**orthogonal to it**. And the defence that does exist lives in another lane
entirely: the transport gate
([`FluffReach::OutboundOnly`](../../rust/shekyl-relay/src/zone/mod.rs#L216),
enforced at [`zone/mod.rs:833`](../../rust/shekyl-relay/src/zone/mod.rs#L833))
plus the embargo, **both designed on the assumption that the observer sees
everything** — which is the correct posture, and one a door filter cannot
contribute to.

### 2.9.4 RULED 2026-09-21 — I8's remedy is a DELETION plus a MEASUREMENT, not a subsystem

1. **Delete the per-host inbound cap** (or set its default non-binding and
   deprecate). The justification is **three independent arms**: PWD-E4 ruled it
   buys no Sybil resistance; §2.9.2's ratio shows no `k` works; §2.9.3 shows the
   measured adversary is compliant at `1`. **It defends nothing.**
2. **Give `--in-peers` a REACHABLE default — the mechanism already exists.**
   `P` here is descriptors and memory — **directly observable**, so this is a
   **measurement at the rule-76 floor (Pi 4)**, not a ruling and not a guess.
   **No number is written here**, and it is not owed to the maintainer as a
   decision.

   **The mechanism's state is ALREADY RECORDED — cited, not rediscovered.**
   [`SHEKYL_P2P_PROTOCOL.md`](SHEKYL_P2P_PROTOCOL.md) PWD-I7's *Pricing context*
   already establishes it: `--in-peers` defaults to the sentinel `-1`
   (`net_node.cpp:181`, an `int64_t`), `set_max_in_peers` assigns it straight
   into a `uint32_t` (`p2p_protocol_defs.h:109`), it **resolves to
   `0xFFFFFFFF`**, and the accept-path comparison is unsigned against an
   unsigned counter. The same row already carries *"`--in-peers` does not
   resolve to an effectively unbounded ceiling"* as one of **its own
   falsifiers**. *(Recorded as a citation because I re-derived this from the
   tree before checking the register — the second time in this round. The
   register is the first place to look, not the last.)*

   **One measurement strengthens it:** the existing record names two hosts at
   `in-peers=128`; **all six seeds** carry `in-peers=128` / `out-peers=64`
   (verified 2026-09-21). The deployed ceiling is uniform.

   **What is new here is the consequence, not the fact** — three of them, and
   they make this arm **smaller**:

   - **No new mechanism is owed.** The ceiling is present, wired and checked.
     What is owed is a **measured value replacing an unreachable sentinel**.
   - **It is structurally the cut PR 812 already made next door**, where
     `max-connections-per-ip`'s `-1` became an explicit sentinel resolved in
     Rust by `shekyl_host_inbound_resolve_cap`. An implicit narrowing of a
     sentinel is the defect class rule 18 names, and **the Rust-side pattern
     for fixing it now exists** — so this should be resolved the same way
     rather than patched in C++. That pairing is the addition; the narrowing
     itself was known.
   - **It is why §2.9.5's blocker holds.** Nobody has observed a node reaching
     its inbound ceiling because **at the shipped default no node can**. The
     estate is the exception, and is therefore the place the discharge trigger
     could first fire.
3. **Do not build eviction.** See §2.9.5.
4. **Build the connection object anyway — for LV-3, not for I8.** The Rust
   migration needs it regardless. See §2.9.7, because this does change what the
   object *is*.

### 2.9.4a A SECOND, INDEPENDENT derivation — from the promotion boundary

**§2.9.3 reached the deletion from §6.5's measured adversary. This reaches it
from the peerlist's own promotion rule, and the two share no premise.**

**The proof.** Promotion to white requires a **successful outbound dial from us
to a claimed listen port**. Therefore an inbound flood from one IP produces **at
most one gray entry per host**, and each one costs the attacker a dial that
either

- **resolves to a real listener they control** — in which case they are an
  **ordinary peer occupying one white slot, priced at one host**; or
- **fails, and the entry is evicted.**

> **So the white list is already defended at the promotion boundary,
> independently of admission.** The per-IP inbound cap is **not protecting
> peerlist integrity at all.** It protects nothing but **slots** — and a total
> ceiling protects slots better, because it bounds the resource directly
> instead of keying on a proxy with an inverted ratio (§2.9.2).

**Verified at `dev` `fdf17b729`, not assumed — all four white-promotion sites
require an outbound dial:**

| Site | Path | Guard |
| --- | --- | --- |
| [`net_node.inl:1282`](../../src/p2p/net_node.inl#L1282) | `do_handshake_with_peer` | **we initiated** — the function exists only for dials we make |
| [`:1342`](../../src/p2p/net_node.inl#L1342) | timed sync | **explicit** — `if(!context.m_is_income)` |
| [`:1585`](../../src/p2p/net_node.inl#L1585) | outbound connect completion | the address is the one **we dialled** |
| [`:3283`](../../src/p2p/net_node.inl#L3283) | `gray_peerlist_housekeeping` | the gray **probe**, which dials out; the failing arm evicts |

**And the code supplies a third leg the proof does not need but gets anyway:
gray is never disclosed.** `get_peerlist_head` reads the **white list only**
([`net_peerlist.h:282`](../../src/p2p/net_peerlist.h#L282)), and
[`net_node.inl:994`](../../src/p2p/net_node.inl#L994) says so in those words.
**So an inbound flood's gray entries never reach any other node's view** — they
poison nothing but our own, for one dial each.

**Two independent derivations agreeing is a cross-check, not a restatement** —
the same kind that validated the constant fold in §7.2 of the round doc, where
a predicted simplification matched a landed one line for line. §2.9.3 could have
been wrong about the measured adversary and this argument would still hold;
this one could be wrong about promotion and §2.9.3 would still hold.

### 2.9.4b The admission argument in PROOF form, not posture form

**Sharpened 2026-09-22.** The reason to admit two connections from one IP on
different ports is **not** that they are probably benign. *"Don't assume
attack"* is a **posture, and postures erode under review.** The actual reason
is stronger and survives an adversarial reading:

> **No discriminator exists, and no consequence follows either way.**
>
> - **Neither case can reach the white list** — promotion needs our outbound
>   dial (§2.9.4a).
> - **Neither buys observation** the first-spy adversary does not already have
>   at **one** edge (§2.9.3: the measured supernode opens exactly one inbound
>   edge per victim and a cap of `1` admits it).
> - **Both are bounded by the same ceiling** — the resource bound, which is
>   what actually constrains them.

***"We can't tell, and it doesn't matter"* is a proof. *"Don't be paranoid"* is
a posture.** The first is what belongs in a ruling.

**The whole residual, stated so it is not mistaken for an open question:** once
the cap goes, the one thing genuinely unbounded is **resources** — which is the
ceiling's job, and a **measurement** (§2.9.4 arm 2), not a judgement. There is
no second residual.

### 2.9.4c THE FOUR-JOB WALK — what the cap could be doing, and what it is

**The closing disposition.** Rather than argue the cap is wrong, enumerate every
job it could plausibly be doing and check each against what the round
established. **Four jobs, and none of them survives.**

| Job | Disposition |
| --- | --- |
| **Peerlist integrity** | **Handled at the promotion boundary, independently and completely** (§2.9.4a). Inbound connections cannot reach white **by any path**. The cap contributes nothing |
| **Observation / first-spy** | **Orthogonal, not weak** (§2.9.3). The measured adversary opens **one inbound edge per victim**; a cap of `1` admits it in full |
| **Resource exhaustion** | **The only live job — and the correct bound is already there and switched off.** See below |
| **Crowd-out at capacity** | **Real, but cannot occur while the ceiling is unbounded** — there is nothing to fill. It becomes a question the moment a ceiling exists, and then the answer is a **margin policy, not a door refusal** — which is §2.9.5's deferred eviction row, with its blocker and trigger already named |

**The resource row is the one that decides it, and the structure is the
argument.** Verified at `dev` `fdf17b729`, `is_host_limit`
([`net_node.inl:231`](../../src/p2p/net_node.inl#L231)) is **seventeen lines
long and does exactly two things:**

```
line  4:  if (zone.m_current_number_of_in_peers >= …max_in_connection_count)   // the CEILING
line 10:  if (has_too_many_connections(address))                               // the per-host CAP
```

**The total ceiling is checked six lines above the per-host call, in the same
function, on the same inbound path** (`abstract_tcp_server2.inl:950`, guarded
`is_income`), **already zone-scoped, already at the door** — and **disabled**,
because `max_in_connection_count` is `UINT32_MAX` at the shipped default
(§2.9.4 arm 2).

> **So the per-host cap has been standing in for a check that exists, sits
> directly above it, and is switched off.** That is not a mistuned mechanism or
> a wrong key. It is a **redundant branch** substituting for a disabled correct
> one — and the deletion is therefore a *simplification*, not a removal of
> protection: **`is_host_limit` becomes the ceiling check and nothing else.**

**The whole residual, priced.** The cap makes single-address slot exhaustion
require **multiple addresses**. PWD-E4 prices that at a /24 — **about a dollar a
month**. Not zero. But it is the difference between **one address and 256**,
**paid for entirely by the population that cannot obtain a second address at any
price** (§2.9.2's inverted ratio, stated as a final quantity rather than a
principle).

**Why the structure is self-correcting, which is what makes the deletion safe
rather than merely justified.** An inbound flood **cannot promote** (§2.9.4a),
**cannot be gossiped** (gray is never disclosed), and **cannot be dialed back**
(we never dial an observed source port, §2.7.7). **Every connection it opens is
a leaf that terminates at the attacker and propagates nowhere.** The only thing
it can consume is **a slot** — and slots are a resource question with a resource
answer sitting unused six lines above the call.

### 2.9.5 The eviction deferral, stated as rule 22 requires

Rule 22 forbids lazy deferral and requires a **named blocker**, not a
disposition.

- **Named blocker:** eviction is only needed once the ceiling is actually
  **reached**, and **no node has been observed reaching one** — at the shipped
  default the ceiling is `UINT32_MAX` (arm 2), which no node can reach, so the
  absence of observations is a property of the default rather than evidence
  about load. Designing a protection set now means
  designing it against an adversary nobody has seen, which is precisely the
  inherited-defence error rule 16 names and §3.1 already warned about.
- **Discharge trigger / falsifier:** **a node at its `--in-peers` ceiling
  refusing an honest inbound peer.** Observable at the accept path, needs no new
  instrument, and cannot be reached until item 2 above lands — so the trigger is
  *created* by the measurement, in the right order.
- **What this is not:** not "we will get to it." The trigger is specific, the
  instrument exists, and the deferral **cannot rot** — it becomes reachable
  exactly when the ceiling does.

### 2.9.6 §3.1 and §3.2 CLOSE BY DISSOLUTION — and one constraint survives them

Both §3 questions presupposed **the admission→eviction trade**. With the door
keying on nothing and eviction unbuilt, the trade has no second term:

- **§3.1 (the admission→eviction trade) — DISSOLVED.** Nothing is moved, so
  there is no failure mode to relocate and no circularity to break. The
  recovery-asymmetry argument is retained as the **record of why the trade
  looked attractive**, not as a live claim.
- **§3.2 (the NAT-sorting trap) — DISSOLVED AS A QUESTION, RETAINED AS A
  CONSTRAINT.** With no protection set there is no ranking, so **there is
  nothing to sort**. But the mission-priority-2 refusal is *not* dissolved: it
  becomes a **standing constraint on any future eviction design**, recorded here
  so it survives the question closing. **A design that sorts survival by
  connectivity class is refused on priority 2, not traded against convenience** —
  and §2.9.5's discharge trigger is the moment that constraint becomes live
  again.

### 2.9.7 The trap in the framework, and the honest consequence

**Step 1 must come first and independently, or the whole framework is motivated
reasoning.** If you pick the quantity first and write the objective afterwards,
**any** quantity looks relevant — choose *"limit connections per address"* as
the objective and the per-host cap scores perfectly. The objective must be a
property you would defend **before** knowing what you will measure.

**And the consequence that makes the framework a test rather than a
ratification:** when no quantity has a favourable ratio, **the correct design is
not to make the decision.** A total ceiling and nothing at the door beats a bad
key at the door. Round 3 reached that answer for inbound admission — which is
the evidence it was testing rather than confirming.

**What the analysis bought over the CGNAT paragraph alone**, stated honestly
because it is less than it looks: it **separated the half that is a measurement
from the half that is a deletion**, so neither is mistaken for a ruling owed to
the maintainer. That is one paragraph's worth. §2.9.2's ratio test is recorded
for the decisions that still need it — as a tool, **not** as this round's
product.

### 2.9.8 What Round 3 does to LV-3's own identity — §5's first falsifier is PARTLY IN PLAY

This is the consequence that must not be left implicit, because
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) and §1 both assert that the
connection object's **identity IS PWD-I8's category**.

**Round 3 removes I8 as a reader of that category at admission, and §2.9.5
defers the only other reader.** So the assertion is now false as written.

§5's first falsifier — *"the category turns out to be derivable from E1/E2's
outputs alone, in which case LV-3 shrinks to wiring"* — is **partly**, not
wholly, satisfied:

| | Status after Round 3 |
| --- | --- |
| **The category as a decision input** | **gone** — no admission decision reads it, and eviction is deferred with a trigger |
| **The category as accounting** | **survives** — it is what an operator and a rule-82 surface read, and it is largely an **E1/E2-derived projection** |
| **Per-peer state (B1's bucket, B2's deadline, B7's score, PWC-E5's floor)** | **not E-derived at all.** A token bucket is not an endpoint fact |

**So LV-3 does NOT shrink to wiring, and its identity changes rather than
dissolving.** The object's identity is now **the endpoint with its provenance**
(Round 2's claimed/observed split) **plus the per-peer state that has nowhere
else to live**. The category rides along as a derived projection for accounting.

**Consumer recount, from rows rather than from the prior figure** (I8 struck):
PWD-E1/E2, PWD-B1, PWD-B2, PWD-B7's score, PWC-E5, the failure-window row —
**six consumers, not seven.** The missing-noun argument is unaffected in kind:
six places re-creating the same state is still the outcome the slice exists to
prevent.

**§1 and the index cell are corrected accordingly** — an index cell asserting an
identity nothing reads is exactly the drift rule 94 exists to catch.

## 2.10 E1 TIER-1 — taken into alpha.9, and it splits in half

**Ruled 2026-09-21 (steering):** tier 1 joins the alpha.9 cut — *"no wire, no
amplifier and no ruling owed,"* and it *"closes the operator-diagnostic gap that
started the lane."* This section records what that commits us to, because **only
one half of tier 1 as specified is actually ready.**

### 2.10.1 It is E1, not E2, and the reason is structural

[`P2P_3_IMPLEMENTATION_ROUND.md`](P2P_3_IMPLEMENTATION_ROUND.md) §4's candidate
row labels this **"E2 tier-1 self-classification."** That label is wrong, and
not by preference: **PWD-E2 is defined as *what verifies a candidate
endpoint*.** Tier 1 has **no verifier** — no dial, no nonce, no hairpin, no
round-trip of any kind. It reads the node's own state and reports it. **A
mechanism with no verification step cannot be E2 by definition**, so it is E1's
rung of the ladder. The register's label is corrected on that ground.

### 2.10.2 The split: a report needs no threshold, an ACTION does

The ladder specifies tier 1 as three things at once
([`SHEKYL_P2P_PROTOCOL.md`](SHEKYL_P2P_PROTOCOL.md) PWD-I8, *Sequencing*): a
node with zero inbound in `T` **classifies itself** probably-unreachable,
**stops advertising**, and **says so**. Those do not have the same readiness:

| Half | Needs | Status |
| --- | --- | --- |
| **Diagnostic — *says so*** | nothing. §2.9.1's test applies: the operator's `P` is *"is anyone dialing me"*, which is **directly observable**, so there is no proxy and therefore **no threshold to pick** | **READY — this is what alpha.9 takes** |
| **Action — *stops advertising*** | **`T`**, because an action with a consequence has to fire *somewhere* | **BLOCKED** |

**`T`'s blocker is named and is not ours.** `T` is owed to **PWD-E8**, which is
DEFERRED on an external blocker chain: *"the remaining links — fleet runs it,
stressed, `T` measured admissibly — stay owed from the Q12-D6a rig"*
([`SHEKYL_P2P_PROTOCOL.md`](SHEKYL_P2P_PROTOCOL.md) §0.5 E8). So the action half
is not deferred by preference; **it is blocked on a measurement another row
owns**, which is what rule 22 requires a deferral to name.

**Writing the report as a state rather than a classification is what removes the
threshold.** *"Probably-unreachable"* is a verdict and needs a line to cross.
*"Inbound connections: 0. Uptime: 6h. Advertising 203.0.113.9:11021"* is an
observation, and the operator crosses the line. **The diagnostic half therefore
owes no number at all** — which is the whole reason it can land in alpha.9 while
the rest of tier 1 cannot.

### 2.10.3 Do NOT "improve" tier 1 into §2.7.5's signal — it degenerates

§2.7.5 argued that the peerlist-head port-match is a **better** signal than
*zero inbound in `T`*, because it is grounded in somebody's successful dial
rather than in our own absence of observation. **As an endpoint-verification
signal that is right.** As a **standalone diagnostic it collapses**, and the
reason is a constant:

`P2P_DEFAULT_PORT` is **one compiled value per network** —
[`11021` mainnet](../../src/cryptonote_config.h#L362),
[`12021` testnet](../../src/cryptonote_config.h#L496). Essentially every node
runs it. So *"our own port appears in a received peerlist head"* is **trivially
true for every node**, because every peerlist head is full of entries carrying
that port. The signal discriminates **only** for a node on a non-default port —
which is not the population tier 1 exists to serve.

**Recorded because the failure mode is a later reader following §2.7.5 and
replacing a working signal with a non-discriminating one.** §2.7.5's proposal is
sound where it was aimed: as a **proposal** whose **verifier is the hairpin**
([`detect_self_handshake`](../../src/p2p/net_node.inl#L1411)), where the nonce
resolves the ambiguity that port-matching cannot. It is not a diagnostic, and
the two uses must not be conflated.

### 2.10.4 The rule-82 shape already exists — and it belongs to the OTHER operator

**Do not mint a shape.** PWD-I7 already proposes one
([`SHEKYL_P2P_PROTOCOL.md`](SHEKYL_P2P_PROTOCOL.md), *"Proposed (not built): the
rule-82 local diagnosis"*): *N* distinct public-zone peers each reaching
connected-then-destroyed without a completed handshake and none returning a
network-id mismatch → one warning naming the pattern and its two usual causes.

**But that is a different operator's problem, and noticing so is what makes the
two complementary rather than duplicative:**

| | Whose node | What it observes | Answers |
| --- | --- | --- | --- |
| **PWD-I7's proposal** | the **dialing** node, being refused | connect succeeds, handshake never completes, across *N* distinct peers | *why can't I join?* |
| **E1 tier 1** | the **unreachable** node, being nobody's peer | zero inbound, with a published endpoint | *why is nobody joining me?* |

**And the cap deletion is what makes I7's side safe to build.** I7 declines to
build it with an explicit reason — *"inferring a remote cause in a log line is
how a wrong diagnosis becomes folklore"* — and that reason is **correct today**:
the dominant cause of that signature is a per-host cap which §2.9.4 has just
ruled defends nothing, so a warning naming it would point at a cause that is
real but **wrong by design**. After the deletion, plus a measured `--in-peers`
ceiling, the same signature means *that peer is genuinely full* — an honest
thing to tell an operator, inferred from a legitimate cause. **Its blocker
narrows from a folklore objection to a number (`N`)**, and it stays deferred on
that.

### 2.10.5 What the diagnostic half owes, as one row

| | |
| --- | --- |
| **Operator's question** | *Is anyone able to reach me?* |
| **Observation that answers it** | inbound connection count, alongside uptime and the endpoint actually being advertised — all three, because any one alone is unreadable |
| **Where it surfaces** | the periodic operator log line is the **load-bearing** surface. `get_info` is *not* sufficient on its own: the fleet runs `restricted-rpc=1`, and the methods that report peer structure are refused under it (verified 2026-09-21 — `sync_info` returns `-32601`). A surface an operator cannot query on the deployment we actually run is not a surface |
| **What the operator does next** | check port-forwarding / the advertised endpoint, or switch to the Tor bootstrap path — the same two remedies I7's proposal names, which is why they should read consistently |
| **What it must NOT do** | classify, threshold, stop advertising, or infer anything about a remote peer. All four are the deferred half |

**Falsifier (rule 21).** The diagnostic half is wrong, and should be re-cut, if
**a node with healthy inbound reports the same state as an unreachable one** —
which would mean the observation set is too small to discriminate and a
threshold was doing the work after all.

## 2.11 THE ROUND'S CLOSING RULE — peers supply hypotheses; only your own dials supply facts

**Stated 2026-09-22 (steering). This is the round's most portable result**, and
everything above is an instance of it.

### 2.11.1 Learning is free; TRANSMITTING is what breaks the design

The earlier framing — that a node cannot *find out* whether it is reachable —
was the wrong invariant, and calling it a gap was the wrong word.

> **Learning a fact about yourself breaks nothing. Being able to transmit it
> does.**

The design's guarantee is **not** that you never find out. It is that **no
self-originated claim is ever accepted without independent verification.** A
node that discovers it is unreachable and stops advertising **has not cheated —
it has less to say, not more**, and the network is strictly better off.

**What would break it** is a node able to present **evidence** of its own
reachability that a third party accepts **without dialing**. That is a
**credential**. Credentials are **transferable**. And a transferable attestation
about a node is **durable identity arriving through the back door** — precisely
the shape cluster I deleted `peer_id` to prevent.

### 2.11.2 The rule

> **A node may learn any fact about itself. No node may transmit a fact about
> itself that another accepts without its own verification.**

### 2.11.3 The portable form

> **Peers supply hypotheses; only your own dials supply facts.**
>
> **Gray is the hypothesis space. White is the fact space. The dial is the only
> operator that moves anything between them.**

**This is why divergent white lists are correct rather than tolerated**
(§2.7.9): **each node's fact space is built from its own observations, and there
is no shared one to converge on.** Convergence would not be an optimisation of
a distributed fact — it would be the substitution of someone else's hypothesis
for your own fact.

### 2.11.4 It re-ranks E2(a) against E2(b) on ARCHITECTURE, not cost

**Both survive the rule**, and that is worth stating before separating them —
both terminate in **something we observe ourselves**:

| | Terminates in | Transmissible? |
| --- | --- | --- |
| **E2(a) hairpin** | **our own nonce** coming back | **no** |
| **E2(b) dial-back** | **a connection arriving at our own socket** | **no** |

So neither produces a credential. **What separates them is who has to act:**

- **(a) needs no other party to act.**
- **(b) requires a peer to do something on our behalf** — and ***"a peer can be
  induced to dial an address"* is simultaneously the amplifier surface and a
  peer-graph steering primitive.**

> **So (a) wins on the architecture, not only on the nonce reuse §2.7.6 gave
> it.** That is a stronger basis, because a cost argument expires when someone
> finds a cheaper dial-back and an architectural one does not — the same
> distinction §5.1 of the round doc draws for Noise `NN`.

### 2.11.5 §2.7.5 died for the RIGHT reason

§2.10.3 rejected the peerlist-head candidate because `P2P_DEFAULT_PORT` makes
the signal degenerate. **True, and not the deepest objection.**

Reading your own endpoint out of a gossiped white list is **receiving someone
else's fact about you.** It would have been **the wrong shape even if it
worked**, because it makes **another node's verification the source of your
self-knowledge** — which inverts §2.11.2 without transmitting anything, by
*importing* rather than *exporting* an unverified self-fact.

**Recorded because a detection failure invites a fix and a shape failure does
not.** Someone who reads only §2.10.3 will reasonably propose making ports
distinctive so the signal works again. §2.11.3 says not to.

## 3. Two adversarial questions the round must ANSWER, not assume

> **BOTH CLOSED 2026-09-21 by §2.9.6 — dissolved with the admission→eviction
> trade, §3.2's priority-2 refusal retained as a standing constraint on any
> future eviction design. Retained below as the record of the questions and why
> they looked live.**

### 3.1 The admission→eviction trade

Separating admission from eviction **moves** the failure mode:

| | Failure mode | Status |
| --- | --- | --- |
| **Today (door)** | honest nodes **cannot join** | **certain, and observed** — PWD-I7's testnet pair |
| **After (eviction)** | an attacker **may be able to choose who gets evicted** | the **eclipse precondition** |

**Bitcoin's inbound eviction protection set is cited for its SHAPE, not
borrowed as a defence.** An inherited defence overstates its constant: Bitcoin's
set was designed against Bitcoin's adversary and topology, and importing it
because it exists is the error rule 16 names. **Argue the trade against a named
adversary with a named channel; do not assert it.**

The argument to beat: *an unappealable door refusal has no recovery; an
eviction preference does.* That asymmetry is the case for the trade — but it is
a claim about **recovery**, and it is only true if the evicted peer can in fact
re-enter. Whether it can is a property of the eviction policy, so the argument
is **conditional on the design it is being used to justify**. That circularity
must be broken explicitly, not glossed.

### 3.2 The NAT-sorting trap

**If the protection set is reachability-ranked — protect dialable peers, evict
non-dialable ones first — then NAT'd nodes are structurally second-class and an
observer learns something from who survives.**

That is [`DAEMON_RELAY_PRIVACY.md`](DAEMON_RELAY_PRIVACY.md) §80.4's
hardware-sorted anonymity **one axis over**: NAT-sorted connectivity. And
§80.4's resolution is the precedent worth copying — it **provisioned the
guarantee at the floor so the sorting disappears**, rather than accepting a
graceful gradient.

**The binding constraint:** the category must **inform admission accounting
without becoming an eviction ranking.** A design that satisfies the first by
implementing the second has reintroduced the defect it was built to remove, in
a channel that is harder to observe. The mission hierarchy is explicit here —
**privacy is the product, and the same guarantees for everyone, never a
setting** — so a design that sorts survival by connectivity class is refused on
priority 2, not traded against convenience.

---

## 4. Also answered in-round

- **Does cluster T land through LV-3's seam or beside it?**
  (`P2P_3_IMPLEMENTATION_ROUND.md` §5.) T5 and T7 are **NO BUILD REQUIRED —
  "rules the status quo"**, and noise wraps Levin rather than displacing it, so
  LV-1/LV-2 are not sunk cost. The question is which seam T's remaining work
  crosses.
- **What the C++ keeps.** The seam, not the subsystem. Scope fence: **do not
  expand LV-3 into the surrounding C++ beyond the seam** — that is a separate
  planning activity, and folding it in is what rule 20 forbids.

---

## 5. Falsifier (rule 21)

This slice is **wrong as scoped**, and should be re-cut, if:

- **the category turns out to be derivable from E1/E2's outputs alone**, in
  which case it is a consumer of cluster E rather than a noun of its own and
  LV-3 shrinks to wiring; or
- **a connection object can be built that satisfies §2.1's three constraints
  without any of the six consumers needing it** — which would mean the
  missing-noun argument in §1 is wrong and this is not slice 1.

**Reopening criterion if the round closes without implementation:** reopen if
any of the six consumers lands its own private connection state in the
meantime. That is the missing noun being re-created in six places, which is
the outcome this slice exists to prevent.

---

## 6. THE ROUND'S CLOSING DELIVERABLE — LV-3's own slice register

**Added 2026-09-21 on steering's ruling.** LV-3's implementation is **deferred
past the alpha.9 freeze**, and the round closes with **this register** rather
than with a plan.

### 6.1 Why a register, and why it has to be checkable

Steering's reason, and it is the right one: *"if `pruning_seed` will be gone
before LV-3 starts, that's a statement about LV-3's distance. It argues for the
slice register being the round's deliverable rather than a plan — a round that
can't start for a while should close with something checkable, so it doesn't
decay into a document about intentions the way P2P-3 did."*

**That failure mode is not hypothetical here — it is this round's own
parent's.** [`P2P_3_IMPLEMENTATION_ROUND.md`](P2P_3_IMPLEMENTATION_ROUND.md) §0
records it: P2P-3 was nominated, never opened, and eight PRs built parts of the
round while the deliverable claimed nothing was implemented. **A round that
closes on intentions is indistinguishable from a round that never closed.**

So every row below carries **what it inherits** and **what greens when it
lands** — a command that can be run against the tree, not a description. **The
checkable part of this register is the ORDERING**, because that is the part that
rots: a row whose inheritance has quietly stopped being true is a row that will
be re-planned on arrival.

### 6.2 The register moved — it is the ROUND's, not this slice's

**Restructured 2026-09-21.** The five-row register that stood here was **P2P-3's
register wearing LV-3's name** — which is the same boundary error §1 withdraws,
one level up: a slice's closing deliverable cannot be the round's plan.

> **The register now lives at
> [`P2P_3_IMPLEMENTATION_ROUND.md`](P2P_3_IMPLEMENTATION_ROUND.md) §4.2**, with
> five slices in dependency order and LV-3 as **slice 5**. Each row carries what
> it inherits and a command that greens when it lands.

*Records-was: rows `L1`…`L5` here named the object, the ownership transfer,
per-peer state, the score, and the failure-class carry — a decomposition of
**this slice's internals** presented as the round's ordering. The internals are
still the right decomposition of slice 5 and are recorded as §6.2.1; what was
wrong was calling them the round.*

#### 6.2.1 Slice 5's internal order, and what it inherits

| Step | What | Note |
| --- | --- | --- |
| **a** | The `Connection` type — the endpoint with Round 2's claimed/observed provenance, direction, zone, established-at | `Claimed<T>` / `Observed<T>` distinct in the type, per §2.7.4 |
| **b** | Ownership transfer — the Rust object becomes authoritative; `p2p_connection_context` becomes a handle | |
| **c** | The connection registry, **including its own count** | see the inheritance below |
| **d** | Relay dispatch — `levin_notify`'s 2,189 lines | the bulk, and the irreversible part |

**What slice 5 inherits from slices 1–4, and it is the reason it goes last:**
the peerlist's differential harness, admission's ceiling, discovery's candidate
selection and the handshake phases are all **already in Rust and already
tested** before the sockets move. **The big-bang lands against established
patterns rather than defining them.**

**And one concrete inheritance worth naming**, because it is invisible from
`levin_notify`: admission's ceiling is compared against an atomic that a
**once-per-second `foreach_connection` recount** maintains
([`net_node.inl:1112`](../../src/p2p/net_node.inl#L1112)). **A Rust connection
registry should own its own count** rather than inherit a sleeping recount
thread, so step **c** is where `:1112` dies. *(The one-second staleness is
separately a rule-76 measurement input for `--in-peers` —
[`P2P_3_IMPLEMENTATION_ROUND.md`](P2P_3_IMPLEMENTATION_ROUND.md) §7.4 item 2 —
not a design question for this slice.)*

### 6.3 This slice's falsifiers (rule 21)

**Slice 5 is mis-scoped, and must be re-cut rather than followed, if:**

1. **Any of slices 1–4 turns out to need the connection object.** That would
   mean §4.1's inversion is wrong and the ordering goes back. Check per slice
   against its own file set — the peerlist's check is
   `grep -cE 'foreach_connection|m_net_server|connection_context|socket' src/p2p/net_peerlist.*`
   returning **0**, which it does at `f9e000f76`.
2. **A consumer landed its own private connection state** while slice 5 waited —
   §5's reopening criterion, now with a register to check it against. The
   missing noun re-created in one of six places means the ordering **below** it
   is wrong, not merely late.
3. **`levin_notify` stops being the dispatch seam** — if relay dispatch moves
   or is displaced by cluster T's work (§4 and
   [`P2P_3_IMPLEMENTATION_ROUND.md`](P2P_3_IMPLEMENTATION_ROUND.md) §5, still
   open), then this slice's 2,189-line core is not where it is assumed to be.

**Each of the first two is a command. The third is why cluster T's sequencing
is still named as open** rather than quietly assumed.

### 6.4 ROUND CLOSES

> **LV-3's design round is CLOSED 2026-09-21.** Rounds 1, 2 and 3 are answered
> (§2.6, §2.8.6 as amended by §2.8.7, §2.9). Identity is settled (§2.9.8): the
> endpoint's provenance plus the per-peer state with nowhere else to live.
> **Scope is the `levin_notify` / `net_node` seam, and this is P2P-3's slice
> 5 — the last one.** The round's deliverable is the register at
> [`P2P_3_IMPLEMENTATION_ROUND.md`](P2P_3_IMPLEMENTATION_ROUND.md) §4.2;
> **P2P-3 slice 1 (the peerlist) is what lands first, and it is not blocked on
> this document at all.** Slice 5's gate is PR **#818**'s merge, plus slices
> 1–4.

**What is NOT closed, and is named so it cannot be read as closed:** cluster
T's sequencing against this seam (§4 and
[`P2P_3_IMPLEMENTATION_ROUND.md`](P2P_3_IMPLEMENTATION_ROUND.md) §5), which is
P2P-3's to answer and not a slice's.
