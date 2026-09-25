# P2P-3 slice 1 — the peerlist

**Status:** **REVISED 2026-09-25 (connector partition; white target is diversity).** Lists are partitioned
by connector, derived from the address type. Gray is drawn when white falls
below that target, not on a fixed minute. The peerlist moves into Rust. The C++ is a
quarry: evidence for the invariant, and a list of behaviors the Rust model
drops.

Owed before slice 1's first increment
([`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc),
[`P2P_3_IMPLEMENTATION_ROUND.md`](P2P_3_IMPLEMENTATION_ROUND.md) §4.4).
Quarry lines below were read on this branch at `81746913c`. Re-read them
before the first increment; `net_node.inl` has moved during this round.

---

## 0. What this slice moves

Rust owns the peerlist: the gray list, the white list, the one door between
them, the 24-hour demotion, disclosure, and the file. At the end of the slice
`peerlist_manager` is gone from `src/p2p`. The dial and the socket stay in C++
until later slices. They report an outcome. They do not insert, replace, or
erase list entries.

---

## 1. The two lists

**Partition (ruled 2026-09-25).** Every gray and white entry belongs to
exactly one connector. The connector is the partition key of both lists,
derived from the address type through the transport layer's declaration
([`P2P_TRANSPORT_LAYER.md`](P2P_TRANSPORT_LAYER.md) D7). It is not a stored
tag. Gray and white caps (`P2P_LOCAL_GRAY_PEERLIST_LIMIT` 5000 and
`P2P_LOCAL_WHITE_PEERLIST_LIMIT` 1000, `cryptonote_config.h:176-177`) and
the random-draw eviction apply within each connector's lists.

**Gray** is every address that arrived and has not been confirmed by the door
in §2. Gossip, a peerlist a neighbor sent, an inbound peer, a peer's
advertisement, `--add-peer`, `--add-exclusive-node`, `--add-priority-node`,
and every address reloaded from disk land here. An incoming address is added
only to gray.

**White** is an address this node has confirmed. No identity, no reputation,
no claim about who is there.

Only white is sent when another peer asks for a peerlist. The sample is a
uniform draw from white. Gray is never in that message.

Three properties fall out of the door.

- White lists diverge across nodes. Each one is built from that node's own
  confirmed dials.
- Another node cannot place itself on this node's white list. An inbound
  session, a transcript, a relay, or an address a peer named is gray.
- A restart does not restore white. The file is a set of addresses, loaded
  into gray with no rank.

---

## 2. The door

**Admit (ruled 2026-09-25).** An entry learned over a session is admitted
only if its connector is the session's connector. One foreign entry rejects
the peer's whole list (`net_node.inl:2376-2383`). `--add-peer` routes to its
connector by address type. An address whose type no local connector serves
is not admitted. Promotion, the 24-hour demotion (`EXPIRATION_PERIOD`), and
§3's Foundation-seed exception operate within one connector.

An address moves from gray to white only when both of these happened, in
order:

1. This node drew it uniformly from gray.
2. This node dialed that address, and the handshake confirmed.

Nothing else writes white. A dial of an address that was not that draw does
not. `--add-peer` does not. An incoming peer does not. A finished handshake
with a harvest probe does not, except the one case in §3.

The other direction is demotion. A white address with no additional contact
for `EXPIRATION_PERIOD` (24 hours) returns to gray. Additional contact is a
confirmed handshake, or a later successful exchange, on a connection this node
opened to that address. It moves the clock forward. Contact that arrived
inbound does not. One failed redial does not demote; the clock does.

**White's target is draw diversity (ruled 2026-09-25).** Outbound
connections are drawn uniformly from white, so a small white list is a
small set of hosts an attacker can dominate. The target is enough
distinct candidates that no attacker-held fraction dominates the draws.
Slices 1 and 3 derive it. It is not "twice the out-degree", and it is
not today's 1,000 cap. Headroom means refill starts before white is
short of that target, so a collapse is not the moment the node first
probes stale gray entries. The threshold is set against the diversity
target. No number is written here.

**The refill trigger is one deadline for the list.** Slice 1 holds the
earliest expiry among white's entries. When that deadline fires, slice
1 re-counts and reports below target if it is. That is one timer for
the list, not one per entry. Evaluating expiry when the list is next
used still decides whether an entry has demoted. The deadline only
makes sure the decline is noticed before the next dial. In steady
state every outbound slot is full and nothing draws from white, so
"noticed on next use" would wait until a connection is already lost.
Slice 1 does not dial. The pace of the promotion dials is slice 3's: a
bounded rate, derived, with jittered spacing. The inherited 60-second
housekeeping timer did both the trigger and the pace, and it is not
kept.

White shrinks by that demotion, by capacity eviction, and by removal
for misbehaviour. Dandelion++ does not remove white entries. It chooses
which existing outbound connections carry stem traffic, and it changes
that choice each epoch.

Capacity eviction is a draw, not a sort. Over the gray cap, drop a random
gray address. Over the white cap, demote a random white address to gray. The
caps move with the crate and are not re-derived
(`src/cryptonote_config.h:176-177`). An `admit` of an address the operator
just named evicts some other gray address when gray is at cap, so the named
address is the one that stays. That is the whole of the `--add-peer` privilege.
It is not a white-list write, and it is not a bias on the draw.

---

## 3. The Foundation seeds are the exception

**Seeds are declared per connector (ruled 2026-09-25).** The exception below
operates inside the connector that owns those addresses.

The hardcoded Foundation seed fleet is six literal addresses
(`src/p2p/net_node.inl:731`, the array at `:738`). A confirmed handshake with
one of those addresses writes white even though the address was not drawn
from gray.

That exception is the fleet, not the word "seed". `--seed-node`, `--add-peer`,
and a peerlist taken from a seed are not it. Addresses a seed returns are
incoming, and they are admitted to gray.

The fleet is not loaded onto white. Startup does not treat those six as
already confirmed. The handshake is still required. Today's seed dial passes
`just_take_peerlist` and returns before any white write
(`src/p2p/net_node.inl:1947`, `src/p2p/net_node.inl:1576`). For this fleet,
that refusal is dropped. For every other harvest, it stands.

---

## 4. The types

**Both lists are partitioned by connector, derived from the address type
(ruled 2026-09-25).** There is no tag field. A stored tag could disagree
with the address.

```rust
struct Gray {
    address: NetworkAddress,
}

struct White {
    address: NetworkAddress,
    last_observed: SystemTime, // when THIS process last confirmed it
}

const EXPIRATION_PERIOD: Duration = Duration::from_hours(24);
```

White has one clock, `last_observed`. The C++ field is `last_seen`
(`src/p2p/p2p_protocol_defs.h:67`). Rust keeps one name. The clock answers
"has this white address gone 24 hours without contact?" It is not a sort key,
not a load rank, and not a field on gray.

The C++ stamps `last_seen` and never reads it back as an age. White eviction
is the capacity trim at `src/p2p/net_peerlist.h:215`. `EXPIRATION_PERIOD` is
new. It is not a setting.

Gray carries no timestamp. A gossiped `last_seen` is ignored at admit.

---

## 5. Draws

**A dial draws from the list of the connector it will dial through (ruled
2026-09-25).** Which connector to dial is slice 3. The peerlist never hands
one network's address to another network's connector.

Storage order is not a priority. Neither list is sorted by `last_observed`,
by arrival, or by which list an address used to inhabit. Reload admits every
stored address to gray, unordered. Former white addresses are not drawn
first.

The peerlist offers uniform draws and no ordered walk:

| Operation | Effect |
| --- | --- |
| `draw_gray()` | One uniform gray address, remembered as an outstanding draw |
| `draw_white()` | One uniform white address. Used to re-contact, which can refresh the clock. Not a promotion |
| `disclose(n)` | `n` distinct white addresses, uniform, order randomized. Gray is absent. `last_observed` is absent |

`handshake_confirmed(address)` is the only writer of `White`, and only in
three cases. The address is an outstanding gray draw: move it to white and
set `last_observed`. The address is in the Foundation fleet: same write. The
address is already white and the connection is one this node opened: move
`last_observed` forward. Every other caller leaves white unchanged. A failed
outstanding draw drops that address from gray. A failed redial of a white
address leaves it white.

C++ disclosure walks white newest-first and then shuffles
(`src/p2p/net_peerlist.h:302`, `:312`). Both callers pass the anonymize flag
(`src/p2p/net_node.inl:2820`, `:2937`), so the sample that goes out is already
a shuffle of the whole white list, truncated. The dial path never became a
draw: it sorts candidates by `last_seen`
(`src/p2p/net_node.inl:1811-1813`) and picks with a bias toward the front of
that order (`src/p2p/net_node.inl:1849`). Rust has no time-ordered walk for
either caller. The property PWD-I2 kept is the one `disclose` has to keep: two
answers cannot be lined up to infer which address was confirmed more recently.

---

## 6. Operations beside the door

| Operation | Effect |
| --- | --- |
| `admit_gray(address)` | Insert into gray. Does not touch a white entry at that address. This is the incoming path, the gossip path, `--add-peer`, exclusive, priority, and load |
| `bootstrap_harvested(addresses)` | `admit_gray` for each returned address. The dialed harvest peer is not promoted by this call |
| expiry | `now - last_observed >= EXPIRATION_PERIOD` moves that white address to gray and does not copy the clock across |

`--add-exclusive-node` and `--add-priority-node` are gray admits. Today
`connect_to_peerlist` (`src/p2p/net_node.inl:3008`) dials them straight onto
white. A successful dial on that path writes white only when the address was
an outstanding gray draw, or is in the Foundation fleet.

---

## 7. Persistence

**Reload (ruled 2026-09-25).** The connector is derived again at load. A
loaded address whose type no local connector serves is dropped. No tag is
stored.

The file is an unordered set of addresses. Archive v8 already deleted the
anchor and white lists (`src/p2p/net_peerlist.cpp:82`); the save path copies
both live lists into the one gray list (`src/p2p/net_peerlist.cpp:306`,
`src/p2p/net_peerlist.cpp:318`); load reads that list
(`src/p2p/net_peerlist.cpp:156`).

`White` has no `Deserialize` and no loader escape hatch. `last_observed` is
not in the file. A stored timestamp would let load rebuild a white entry
without a draw and a handshake. Restart therefore puts every address on gray.
How long the process was down does not matter; a wall clock would answer the
duration and would still not be the door in §2.

Dropping `last_seen` from the stored entry is a format change. The version
constant bumps (rule 42). The loader already drops a pre-current file
wholesale.

A node boots with gray only. It draws from gray until white exists, and it
dials the Foundation fleet under §3. How many dials run at once is the
outbound cap, owned outside this slice (`P2P_DEFAULT_OUT_PEERS`).

---

## 8. C++ behaviors this slice does not keep

| Behavior | Where | Rust |
| --- | --- | --- |
| Promote from a bare address and stamp now | `set_peer_just_seen`, `src/p2p/net_peerlist.h:334` | No such function. White is written only by `handshake_confirmed` under §5 |
| Two white writes on one kept outbound dial | `src/p2p/net_node.inl:1285` and `src/p2p/net_node.inl:1588` | One call, and only if that address was the gray draw or a Foundation seed |
| `trust_last_seen` | `append_with_peer_white`, `src/p2p/net_peerlist.h:347` | No flag. The clock moves only on contact this node initiated |
| Gossiped `last_seen` stored on gray insert | `src/p2p/net_peerlist.h:239`, `src/p2p/net_peerlist.h:405` | Ignored. Gray has no clock |
| Time order as a rank | `by_time` at `src/p2p/net_peerlist.h:184`; the dial sort at `src/p2p/net_node.inl:1811-1813` | Uniform draws. Load is unordered |
| White list never expires on age | trim is capacity only, `src/p2p/net_peerlist.h:215` | `EXPIRATION_PERIOD` demotes to gray |
| Foundation seed handshake does not promote | `src/p2p/net_node.inl:1947`, `src/p2p/net_node.inl:1576` | §3. This fleet confirms onto white |
| `--add-peer` kept off the trim front by a synthetic absence of `last_seen` | `src/p2p/net_peerlist.h:444` | The named address is admitted to gray and is not the one a full list drops. The draw is still uniform |

`append_with_peer_white(const peerlist_entry&)` accepts any entry. Porting
that signature is the hole §5 closes.

---

## 9. What the quarry is actually for

These C++ outcomes match the lists. The functions that produce them are not
the API.

- `--add-peer` is gray (`src/p2p/net_node.inl:1004`, `src/p2p/net_peerlist.h:419`).
- An inbound advertisement is gray (`src/p2p/net_node.inl:2918-2925`).
- A received peerlist is merged into gray (`src/p2p/net_peerlist.h:239`).
- Inbound timed sync does not write white (`src/p2p/net_node.inl:1345`).
- The file cannot represent white (`src/p2p/net_peerlist.cpp:310`).

A reachability probe that answers does write white today
(`src/p2p/net_node.inl:3447`), including when the handshake was the
harvest-shaped `just_take_peerlist` path (`src/p2p/net_node.inl:1619`). Rust
writes white there only when that address was the outstanding gray draw.

The stripe field the register used to inherit is already gone from the
peerlist. `src/p2p/net_peerlist.h:367` keeps the previous `last_seen`. `:414`
is `return true` at the end of `append_with_peer_gray`
(`src/p2p/net_peerlist.h:414`). Neither is work for this slice.

`pruning_seed` is not a term this design uses. Where that spelling still
appears in code, including comments and tests that name it in order to ignore
it, the implementation PR this brief describes deletes it. This document does
not. The deletion is not a predecessor: the field is already absent, and the
slice opens without it.

---

## 10. The seam until the dial moves

Until slices 3 and 5 move the dial into Rust, C++ reports outcomes and does
not choose the list:

- `draw_gray` / `draw_white` / `disclose`
- `handshake_confirmed(address)` / `draw_failed(address)`
- `admit_gray` / `bootstrap_harvested`

A `u16` named on both sides of the FFI is not the mitigation. The port carries
no provenance either way. The residual lie is a C++ caller invoking
`handshake_confirmed` for an address the peerlist did not draw and that is not
in the Foundation fleet. `handshake_confirmed` refuses that address. The
function cannot be talked into a third door.

---

## 11. Falsifiers

They check different things. Neither stands for the other.

1. **Constructor reachability (source).** `White` has no public constructor.
   The only call is inside `handshake_confirmed`, and that function promotes
   only an outstanding gray draw or a Foundation-fleet address. There is no
   `bool` on either type, and no `last_seen` beside `last_observed`. There is
   no ordered iterator. The check fails if it cannot find the constructor it
   is asserting about (rule 47).
2. **No entry crosses connectors (ruled 2026-09-25).** On admit, on
   disclosure, on eviction, and on reload, including the whole-list
   rejection when one foreign entry arrives. If a future network shares
   address syntax with another, so its connector cannot be derived from the
   address type, the connector becomes a stored field, validated against the
   address at admit, and D7 reopens on the same event.
3. **Model sequences (runtime).** Draw-then-confirm promotes; confirm of an
   undrawn ordinary address does not; a Foundation seed confirm does; incoming
   and `--add-peer` stay gray; expiry returns white to gray; contact this node
   opened moves the clock; inbound contact does not; reload is gray only and
   does not draw former white first; `disclose` is a sample of white and
   carries no clock; a failed draw drops gray; a failed redial leaves white.
   The harness fails if it has no sequence (rule 47).
4. **The C++ list is gone, and so is the old spelling.** `rg -n 'm_peers_white|peerlist_manager' src/p2p`
   returns nothing. `rg -n pruning_seed src rust tests` returns nothing,
   comments included. A gate that allowlists the word in a comment or a
   negative test has not finished.

A harness that requires Rust membership to match the C++ is the wrong oracle.
§8 is a list of intentional divergences.

---

## 12. Reversion

The contract reopens only for a third way onto white: not a gray draw this
node dialed and confirmed, and not a confirmed handshake with the Foundation
fleet. Inconvenience is the mechanism working.

Worked against the paths this brief already knows:

| Path | Gray → white? |
| --- | --- |
| Uniform gray draw, dial, handshake confirmed | Yes |
| Same address, already white, contact this node opened | Clock moves. Already white |
| Foundation fleet, handshake confirmed | Yes. §3 |
| Bootstrap harvest of anyone else | No. Returned addresses are gray |
| `--add-peer`, exclusive, priority | No. Gray until drawn |
| Incoming peer, advertisement, received peerlist | No. Gray only |
| Reload | No. Gray, unordered |
| White, no contact for `EXPIRATION_PERIOD` | Demote to gray |
| Undrawn address, handshake confirmed | No |

Where a later lane will try:

- **Cluster T's Noise transcript.** A transcript is not the door. The dialer still has to have drawn the address from gray, or be confirming a Foundation seed.
- **A relay that succeeds.** Bytes on a path are not a gray draw.
- **An operator assertion.** `--add-peer` is gray. Ruling that an operator may assert white is a steering decision, and it would be a third door.

Falsify the constructor by a confirmed gray draw that `handshake_confirmed`
cannot express. Fix the signature. That does not widen white.

---

## 13. Increments

| # | Content | Greens when |
| --- | --- | --- |
| 1 | The crate: gray, white, `EXPIRATION_PERIOD`, the draws, the door, the address file. No FFI | The crate's tests cover §11.2, and `git diff dev..HEAD --stat -- src/ contrib/` is empty |
| 2 | The divergence ledger of §8, checked against the tree at the increment's pin | Each §8 row names the Rust operation that replaces it, and §11.1 passes |
| 3 | Delete the C++ peerlist. Dial sites that remain call the outcome functions. Delete every remaining `pruning_seed` in `src/`, `rust/`, and `tests/` | §11.3 |

Increment 1 changes no production behavior. Increment 3 is the cutover. The
crate boundary is what makes `White`'s constructor crate-private; `shekyl-ffi`
is the wrong crate for that. The crate's name is the increment's, and the
neighbor `shekyl-peer-policy` owns the inbound ceiling, not these lists.

---

## 14. Scope fences

- No admission-ceiling policy. Socket admission is the transport layer
  ([`P2P_TRANSPORT_LAYER.md`](P2P_TRANSPORT_LAYER.md)), which folded
  slice 2 on 2026-09-25.
- No policy for which draw to dial next, and no seed-list editing. Choosing
  which connector to dial is slice 3's, not this slice's. Slice 3
  calls `draw_gray`, `draw_white`, and `handshake_confirmed`. It does not grow
  a third door. The Foundation fleet is data this slice reads, not a second
  selector.
- No connection object. Slice 5. Expiry and the clock do not wait for it.
- No new cap, no `--in-peers` number, no refusal-window number.
- The failure cache stays where it is. It may cause the dialer to skip an
  address `draw_gray` returned. It does not write white.
- Disclosure stays a sample of white with no clock in the value. PWD-I2's
  property (a second answer does not reveal which address was confirmed more
  recently) is what `disclose` implements. The `by_time` walk is not part of
  that property.

---

## 15. What this brief does not decide

The on-disk byte layout past "an unordered set of addresses, no
`last_observed`, no white tag", and the crate's name.

It does not re-open §4.2's ordering.

It does not claim the C++ peerlist is the specification. §8 is the list a port
would otherwise preserve.
