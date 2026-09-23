# P2P-3 slice 1 — peerlist brief

**Status:** DRAFT for steering review, 2026-09-23. Owed before slice 1's first
increment per [`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
and [`P2P_3_IMPLEMENTATION_ROUND.md`](P2P_3_IMPLEMENTATION_ROUND.md) §4.4. This
brief rules nothing: it states what slice 1 builds, what it must treat as
already decided, and what "done" means. Ratification is Rick's.

**Pinned:** `dev` @ `d8ebfd18c11bef38ab04e5763828c22e7ff00c49` (verified against
`git ls-remote origin dev` at 2026-09-23; local and remote agree). Every
citation below resolves at this sha. Re-verify before the first increment
opens — `net_node.inl` anchors have moved twice in this round already.

---

## 0. The correction this brief applies to its own mandate

§4.4 argues for the type contract from a **process failure**: a rule in prose
has to be re-derived by every lane, this round watched a deletion scope be
understated three times, and a constraint survived nine turns unverified
because it was written nowhere a check could find it. That argument is true and
it is not the strongest one available.

**The stronger argument is in the tree.** Grounding slice 1 at the pin found
that **the C++ already holds the contract, by convention, at every site**:

| Site | What it already does |
| --- | --- |
| [`net_peerlist.h:347`](../../src/p2p/net_peerlist.h#L347) | `append_with_peer_white` is the **sole** function that inserts or replaces into white ([`:360`](../../src/p2p/net_peerlist.h#L360), [`:368`](../../src/p2p/net_peerlist.h#L368)). Every other touch of `m_peers_white` erases or reads |
| [`net_node.inl:1588`](../../src/p2p/net_node.inl#L1588) | promotes only inside `try_to_connect_and_handshake_with_new_peer` ([`:1521`](../../src/p2p/net_node.inl#L1521)) — an **outbound dial** |
| [`net_node.inl:1285`](../../src/p2p/net_node.inl#L1285) | promotes inside `if(!just_take_peerlist)` ([`:1273`](../../src/p2p/net_node.inl#L1273)) — so a seed probe does not promote |
| [`net_node.inl:1345`](../../src/p2p/net_node.inl#L1345) | guarded `if(!context.m_is_income)` — **an inbound peer is never promoted** |
| [`net_node.inl:3447`](../../src/p2p/net_node.inl#L3447) | promotes only after `check_connection_and_handshake_with_peer` succeeds — a dial |
| [`net_peerlist.h:419`](../../src/p2p/net_peerlist.h#L419) | `append_operator_candidate` puts `--add-peer` in **gray**, and refuses to write a synthetic `last_seen` because *"recording an observation it never made is the exact category error this change exists to remove"* |
| [`net_node.inl:3008`](../../src/p2p/net_node.inl#L3008) | `connect_to_peerlist` — the `--add-exclusive-node` / `--add-priority-node` path ([`:1991`](../../src/p2p/net_node.inl#L1991), [`:2006`](../../src/p2p/net_node.inl#L2006)) — **dials** rather than asserting, so those operator peers reach white only through [`:1588`](../../src/p2p/net_node.inl#L1588) and only on success |
| [`net_peerlist.cpp:306`](../../src/p2p/net_peerlist.cpp#L306) | the save path has **no white member to write even by accident**, so *"a file cannot carry a trust assertion its loader is required to ignore"* |

**The operator surface is enumerated, not sampled.** There are three ways an
operator names a peer — `--add-peer`, `--add-exclusive-node`,
`--add-priority-node` — and `grep -n 'm_exclusive_peers\|m_priority_peers\|m_command_line_peers' src/p2p/net_node.inl`
accounts for every one. The first lands in gray as a candidate; the other two
are dialed. **None asserts a fact.**

Eight independent local decisions. **Every one of them is correct.** Slice 1 is
therefore not repairing a defect, and the brief must not be written as though
it were — a lane that believes it is fixing broken code ports differently, and
worse, than one that knows it is preserving a working invariant.

> **The contract exists because eight correct decisions do not make the ninth
> correct.** Each site above states the rule again, in its own words, and each
> one could have been written the other way by someone with no access to the
> other seven. The type is what removes the requirement that the ninth author
> reach the same conclusion unaided.

Two of those sites, [`:419`](../../src/p2p/net_peerlist.h#L419) and
[`net_peerlist.cpp:306`](../../src/p2p/net_peerlist.cpp#L306), already *argue*
for the type in their own comments — the second explicitly contrasts an
invariant with "a convention, not an invariant" and closes the hole by removing
a struct member. **That is §4.4's instruction already carried out once, in
C++.** Slice 1 generalises a move the codebase has made, rather than importing
one.

---

## 1. Preconditions, verified at the pin rather than inherited

| Register claim | State at `d8ebfd18c` |
| --- | --- |
| §4.2 row 1's opening gate: `rg -n 'pruning_seed' src/p2p/net_peerlist.*` returns nothing | **MET.** The only hit is [`net_peerlist.cpp:84`](../../src/p2p/net_peerlist.cpp#L84), a comment recording why the archive version is 9. The field is gone; the three received-seed sites the register names no longer exist |
| 874 lines | **EXACT.** `net_peerlist.h` 545 + `net_peerlist.cpp` 329 |
| No `net_node` / socket / connection dependency | **HOLDS.** The dependency runs the other way |
| Greenfield — no peerlist crate in `rust/` | **HOLDS.** `shekyl-peer-policy` exists and is the natural neighbour (it already owns the inbound ceiling), but it holds no peerlist |

The register's row-1 gate is **already green at the pin**, which means slice 1
opens without a blocking predecessor. That is a change from when the row was
written and it is worth stating, because the row reads as though the gate were
still pending.

---

## 2. The deliverable

A new crate under `rust/` owning the peerlist as data, with no socket, no
connection context and no dependency on the C++ node. It is reached from C++
through `shekyl-ffi` like every other Rust owner.

### 2.1 The type contract — §4.4, restated only where grounding changed it

1. **Gray and white are different types**, not one type with a flag.
2. **The observed type has no public constructor except from a completed dial
   result.** A lane that wants to promote without dialing must find it cannot
   write the code.

Grounding adds one clause §4.4 does not have, and it comes from
[`net_node.inl:1273`](../../src/p2p/net_node.inl#L1273) and
[`:1588`](../../src/p2p/net_node.inl#L1588):

3. **A dial that completes is not sufficient — the dial must have been made for
   the purpose.** The seed path dials, handshakes, takes the peerlist and closes
   ([`:1576`](../../src/p2p/net_node.inl#L1576)), and is excluded from promotion
   at *both* points. So the observed type's constructor takes a dial result that
   is **distinguishable from a peerlist-harvest probe**, or the seed path
   silently acquires promotion rights the C++ deliberately denies it.

§4.4's table says a **handshake transcript** is not a dial result. The seed path
is the concrete instance: it produces a completed handshake and must still not
promote.

### 2.2 Persistence is a fact-to-hypothesis demotion, and the type gets it free

The predicted simplification is real and it is **larger** than predicted.

The store carries **one list**. Archive v8 deleted the anchor and white lists
outright — [`net_peerlist.cpp:82`](../../src/p2p/net_peerlist.cpp#L82) records
that *"the stream carries one list where it carried three"*. The load path
reads only gray ([`:156`](../../src/p2p/net_peerlist.cpp#L156)); the save path
joins two gray ranges ([`:163`](../../src/p2p/net_peerlist.cpp#L163)); and
`get_peerlist(peerlist_types&)` copies **both live lists into `peers.gray`**
([`:315-318`](../../src/p2p/net_peerlist.cpp#L315)).

So a restart demotes every fact to a hypothesis. That is not a lossy port
detail to be preserved for compatibility — **it is what the type contract
implies.** A reloaded entry has no dial behind it, this process made no
observation of it, and therefore it cannot be the observed type. The
consequence for slice 1:

> **The store round-trips the hypothesis type only. The observed type needs no
> deserialization path, and its constructor needs no escape hatch for the
> loader.** The format shrinks because the type refuses to represent what the
> file cannot justify.

State this as a consequence of the contract, not as a port of the C++. The C++
arrived at it by deleting a struct member after finding a convention
insufficient; the Rust arrives at it by the observed type having no
constructor the loader can reach.

### 2.3 The FFI seam is where the contract can leak

§4.4 names this and grounding does not soften it: a `u16` crossing as a port
carries no provenance, and a claimed port and an observed one are the same
sixteen bits. The marshaling names which kind it is **on both sides**, and the
C++ side's naming is part of slice 1, not a follow-up — the seam is the only
place where the Rust type system stops holding and the only place the eighth
author will be working.

---

## 3. Invariants

- **One promotion gate.** Exactly one constructor of the observed type, as
  `append_with_peer_white` is today's single insert point. Verifiable by grep.
- **Inbound never promotes.** [`:1345`](../../src/p2p/net_node.inl#L1345)'s
  `!m_is_income` guard becomes a property of the type rather than of that line.
- **Operator input is a slot policy, not a trust claim.**
  [`net_peerlist.h:419`](../../src/p2p/net_peerlist.h#L419)'s distinction
  survives: `--add-peer` outranks a gossiped candidate for a *place in the
  pool* and earns white by a dial like anything else. The Rust must keep these
  two as separate operations; collapsing them is the likeliest way to lose the
  invariant while keeping the tests green.
- **No synthetic observation.** No path writes a `last_seen` this node did not
  observe.
- **The persisted file cannot assert trust.** Structural, per §2.2.

---

## 4. Increments

| # | Content | Greens when |
| --- | --- | --- |
| 1 | The two types, the dial-result constructor, the gray store and its format. No FFI | the crate builds and its own tests pass, **and** `git diff dev..HEAD --stat -- src/ contrib/` is empty — the row asserts the C++ is untouched rather than assuming it (rule 47) |
| 2 | The differential harness: both implementations over one input sequence, compared on gray/white membership | the harness agrees on a generated sequence including promotions, demotions, trims and a save/load round trip |
| 3 | The FFI seam and the C++ call-through, provenance named on both sides | `append_with_peer_white` has no remaining C++ caller |

Increment 1 lands no behaviour change **by construction**, which is what makes
increment 2's harness meaningful: it compares a live C++ peerlist against a
Rust one that nothing yet consults.

---

## 5. Completion gate — two falsifiers, and they check different things

§4.4 names a falsifier and §4.2 names a green command. **They are not the same
check and the brief must not let one stand for the other.**

1. **Membership oracle (runtime).** §4.2's row: a differential harness runs both
   implementations over one input sequence and agrees on gray/white membership.
   This catches a *behavioural* divergence — a promotion that happens in one and
   not the other.
2. **Constructor reachability (type).** §4.4's falsifier: slice 1 fails if its
   first PR introduces a peerlist entry type with a public constructor reachable
   without a dial result, or a single type carrying a `bool verified` flag. This
   is a property of the source, not of a run, and **no amount of passing
   membership comparison establishes it.**

A membership oracle over a type that permits an unearned promotion passes right
up until a lane writes the promotion. Falsifier 2 carries increment 1;
falsifier 1 carries increment 2.

**Rule 47:** both gates assert their own subject. The harness fails if it finds
no sequence to run; the type check fails if it cannot locate the constructor it
is asserting about.

---

## 5a. Reversion clause

**The contract reopens if a legitimate promotion path is found that is neither
a dial nor reducible to one.** Not "if promotion becomes inconvenient" — the
inconvenience is the mechanism working.

Where to expect a candidate, and why each is not one today:

- **Cluster T's Noise handshake.** §4.4 names it as the example of something
  that *looks* like a dial result and is not: a transcript proves a session,
  not that this node reached that address on its own initiative. If cluster T
  lands a handshake the **dialer** completes, that is already a dial and needs
  no exception — the clause fires only if a peer-initiated transcript is argued
  to establish reachability.
- **A relay that succeeds.** §4.4's second row. Successful relay proves the
  path carried bytes, is a different
  claim from reachability on our own dial.
- **An operator assertion.** The strongest real candidate, and the C++ already
  rejected it at [`net_peerlist.h:419`](../../src/p2p/net_peerlist.h#L419).
  Reopening would mean ruling that an operator may assert reachability the node
  has not observed — a ruling, not a convenience, and it belongs to steering.

**Falsify this clause** by a promotion path that is dial-backed in substance
but cannot be expressed through the constructor. That is a defect in the
constructor's signature, not grounds to widen the type — fix the signature.

---

## 6. Scope fences

- **No admission policy.** The ceiling is slice 2.
- **No discovery policy.** Seed handling and dial-candidate selection are slice
  3; slice 1 only refuses to promote what slice 3 will dial.
- **No connection object.** Slice 5.
- **No `--in-peers` number, no cap number, no refusal-window number.**
- **The failure cache stays where it is.** `record_addr_success` /
  `add_host_fail` are not peerlist state and do not move in this slice.
- **`m_peers_white`'s eviction and trim paths port as they are.** They are not
  promotion and the contract says nothing about them.

---

## 7. What this brief does not do

It does not design the store format's bytes, choose the crate name, or rule on
whether the peerlist lands beside `shekyl-peer-policy` or in its own crate —
those are the first increment's, and the register's row does not constrain them.

It does not re-open §4.2's ordering. The sequence was confirmed on 2026-09-23
after the LV-2b measurement round and three corrections did not move it.

It does not claim the C++ is wrong. §0 exists because the opposite is true, and
a brief that got this backwards would produce a port that treats seven
deliberate decisions as accidents.
