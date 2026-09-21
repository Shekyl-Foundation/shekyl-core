# LV-3 — the connection as a typed, owned Rust object (P2P-3 slice 1)

**Status:** DESIGN ROUND OPEN 2026-09-21. Pinned to `dev` `059aca264`; every
`file:line` was read at that SHA. **The deliverable of this round is a design,
not code** — rule 20 is explicit that migrating a subsystem is a planning
activity with its own design document, review cycle and test gates, never
folded into feature work. Rule 26 cited explicitly. Owner:
[`P2P_3_IMPLEMENTATION_ROUND.md`](P2P_3_IMPLEMENTATION_ROUND.md) §4, slice 1.

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
have. *That is the case for this slice, and it is falsifiable — if a later
measurement shows shipped C++ growing while the noun is still missing, this
slice was scoped wrong.*

*(The converging-rows argument in §1 reaches the same conclusion from seven
consumers. Two independent derivations, one empirical and one structural.)*

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

## 1. Why this slice is first — the structural case

**Nothing in Rust owns a connection.** `shekyl-levin` owns bytes;
`shekyl-peer-policy` owns stateless verdicts that C++ calls with values C++
walked itself. The connection lives in `net_node.inl`'s `foreach_connection`
lambda and epee's context.

**That absence is why the per-host cap became an address comparison inside a
loop — there was no object to hang a category on.** The missing noun has
**seven** consumers (`P2P_3_IMPLEMENTATION_ROUND.md` §2): PWD-I8, E1/E2, B1,
B2, B7's score, PWC-E5, and the failure-window row.

So this is not the cheapest slice. **It is the one the others are waiting on.**

---

## 2. The deliverable

**A connection as a typed, owned Rust object whose identity is PWD-I8's
category** — *what this endpoint **is***:

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
name, and the unnamed version could not be reused by the seven consumers in
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

### 2.8.6 ROUND 2 CLOSES

> **No admission or eviction decision reads the claimed half. PWD-E2 stays a
> PARALLEL slice, and the slice register in
> [`P2P_3_IMPLEMENTATION_ROUND.md`](P2P_3_IMPLEMENTATION_ROUND.md) §4 STANDS.**

**What Round 3 inherits, and it is the harder half:** §2.8.4's second
declaration — *what is the quantity a proxy for?* Rounds 1 and 2 settled the
**trust** axis, which is checkable. The **relevance** axis is a judgement, it is
where I8's original defect actually lives, and nothing established so far
constrains it.

## 3. Two adversarial questions the round must ANSWER, not assume

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
  without any of the seven consumers needing it** — which would mean the
  missing-noun argument in §1 is wrong and this is not slice 1.

**Reopening criterion if the round closes without implementation:** reopen if
any of the seven consumers lands its own private connection state in the
meantime. That is the missing noun being re-created in seven places, which is
the outcome this slice exists to prevent.
