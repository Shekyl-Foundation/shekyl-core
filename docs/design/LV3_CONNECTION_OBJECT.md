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
