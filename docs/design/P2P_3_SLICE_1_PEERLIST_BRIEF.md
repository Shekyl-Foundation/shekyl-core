# P2P-3 slice 1 — the peerlist

**Status:** **REVISED 2026-10-08 (decision-anchored: PR #1001).**
The interim composition is the dialer brief's. Per connector,
`disclose_count` is that connector's outbound target and
`white_diversity_floor` is `INTERIM_WHITE_DIVERSITY_MULTIPLE` (4)
times that count. The list writer is `apply(DialOutcome)`. The
derivation of the floor is still owed.
*Records-was: REVISED 2026-09-25 (connector partition; white target is
diversity), and the 2026-10-08 working values used outbound degree 16.*
Lists are partitioned
by connector, derived from the address type. Gray is drawn when white falls
below that target, not on a fixed minute. The peerlist moves into Rust. The C++ is a
quarry: evidence for the invariant, and a list of behaviors the Rust model
drops.

Owed before slice 1's first increment
([`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc),
[`P2P_3_IMPLEMENTATION_ROUND.md`](P2P_3_IMPLEMENTATION_ROUND.md) §4.4).
Quarry lines below were read at `81746913c`. **Re-read 2026-10-08
against `dev` `f317d979c4`.** *Records-was: the 2026-10-07 pass pinned
`9eb5f473cd`.* `net_node.inl` has moved. The citations checked, and
where they are now:

| Was, at `9eb5f473cd` | Now, at `f317d979c4` | What the line is |
| --- | --- | --- |
| `get_seed_nodes` at `:796`; the seed vector filled at `:1965` | `get_ip_seed_nodes` at `:771`, the six-host array at `:781`; `get_seed_nodes` at `:810` (clearnet returns `get_ip_seed_nodes`); the seed vector is filled at `:2042` | the compiled seed list |
| `set_peer_just_seen` at `:1332` and `:1392` | `set_peer_just_seen` in the handshake at `:1403` and `append_with_peer_white` at `:1707` are the white writes on a kept dial. Housekeeping writes white at `:3363` after the session was closed | the C++ white writes |
| the `just_take_peerlist` branch at `:1618` | the `just_take_peerlist` close at `:1695` | the harvest close |
| `connect_to_peerlist` at `:2840` | `connect_to_peerlist` at `:2912`, called from `connections_maker` at `:2116` | the exclusive list |
| `append_operator_candidate` at `:1036` | `append_operator_candidate` at `:1098` | `--add-peer` |
| `handle_remote_peerlist` still at `:2376` | the function at `:2448`; foreign-connector reject at `:2460-2466`; the fail-and-ban predicate at `:2471-2472` | a received peerlist |

The body citations below use the `f317d979c4` column. Re-read them
before slice 1's first increment.

---

## 0. What this slice moves

Rust owns the peerlist: the gray list, the white list, the one door between
them, the 24-hour demotion, disclosure, and the file. At the end of the slice
`peerlist_manager` is gone from `src/p2p`. **UPDATE 2026-10-07:** dial
outcomes are reported by the Rust dialer (P2P-3 slice 3), not by the C++
dial path. The dialer is the only writer of a white promotion, and it
writes through this slice's type contract. *Records-was: the dial and the
socket stay in C++ until later slices, and they report an outcome.* They
do not insert, replace, or erase list entries except through that contract.
Gray admission refuses an address the failed-address memory holds, and
a banned one (`handle_remote_peerlist`, `net_node.inl:2472`). Until
slice 3 lands, this slice takes that predicate from the C++ cache.
Slice 3 replaces where the predicate comes from. The dialer emits
`DialOutcome`. This slice's `apply` is the only list writer.

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
the peer's whole list (`net_node.inl:2460-2466`). `--add-peer` routes to its
connector by address type. An address whose type no local connector serves
is not admitted. Promotion, the 24-hour demotion (`EXPIRATION_PERIOD`), and
§3's Foundation-seed exception operate within one connector.

An address moves from gray to white only when both of these happened, in
order:

1. This node drew it uniformly from gray.
2. The dialer emitted `SessionAccepted` or `Confirmed` for that address.

Nothing else writes white, except `HarvestDone` for the fleet in §3.
`SessionAccepted` keeps the session. `Confirmed` closes it. Both are
that same draw. A dial of an address that was not that draw does not
write white. `--add-peer` does not. An incoming peer does not. A
finished harvest does not, except §3.

The other direction is demotion. A white address with no additional contact
for `EXPIRATION_PERIOD` (24 hours) returns to gray. Additional contact is a
confirmed handshake, or a later successful exchange, on a connection this node
opened to that address. It moves the clock forward. Contact that arrived
inbound does not. One failed redial does not demote; the clock does.

**White's target is draw diversity (ruled 2026-09-25).** Outbound
connections are drawn uniformly from white, so a small white list is a
small set of hosts an attacker can dominate. The target is enough
distinct candidates that no attacker-held fraction dominates the draws.
The 2026-09-25 ruling stands: the floor is not "twice the out-degree",
and it is not today's 1,000 cap. *Records-was, the same ruling: both
levels had no number yet.*

**Interim working values (Rick, 2026-10-08), until this slice's
derivation.** They are the dialer brief's composition, not a second
degree. `disclose_count` is that connector's outbound target:
`hidden_out` or `clearnet_out`, each `MIN_PROVISIONED_OUT_PEERS` or
`P2P_DEFAULT_OUT_PEERS` (both 12) until a ruled operating point.
`white_diversity_floor` is `INTERIM_WHITE_DIVERSITY_MULTIPLE` (4)
times `disclose_count`, so about 48. These replace
`P2P_DEFAULT_PEERS_IN_HANDSHAKE` (250, `cryptonote_config.h:193`) as
the size this node aims to send. *Records-was: that 250, and
`P2P_MAX_PEERS_IN_HANDSHAKE` beside it at `:194`, also 250. Records-was
the same day: outbound degree 16, `disclose(n)` with `n = 16`, floor
about 64. Sixteen was the withdrawn §95.2 illustration.* The
operating point (`DAEMON_RELAY_PRIVACY.md` §95) is still unchosen.
When it is ruled, `disclose_count` and the floor move with that
connector's target. The derivation this slice still owes: the white
floor and the refill line, from draw diversity and the candidate
filters; `disclose_count`, from intake diversity, honest fill, and
per-reply exposure. The multiple 4 is the interim stand-in for that
floor, not the derivation. The refill line stays above the floor. The
gap is headroom. Refill starts when white crosses the refill line,
while it is still above the floor, so the node is not probing stale
gray entries in the moment connectivity has already collapsed.

**The refill trigger is the refill line, plus one deadline for quiet decline.**
If white is already below the refill line, including empty after boot
or after eviction, slice 1 reports that immediately. There is no expiry
to wait for. When white is at or above the refill line, slice 1 holds
the earliest expiry among its entries. When that deadline fires, slice
1 re-counts and reports below the refill line if it is. That is one
timer for the list, not one per entry. Evaluating expiry when the list
is next used still decides whether an entry has demoted. In steady
state every outbound slot is full and nothing draws from white, so a
demotion with no deadline would wait until a connection is already
lost. Slice 1 does not dial. While white is under the refill line,
the promotion dials are slice 3's fill: a kept session while a slot
is free, and one confirm-and-close while outbound is already at
target. Both are one dial on the jittered wake. The inherited
60-second housekeeping timer did both the trigger and the pace, and it
is not kept. *Records-was: the pace was named here as a bounded
derived rate without saying it is that wake.*

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
(`get_ip_seed_nodes`, `src/p2p/net_node.inl:771`, the array at `:781`).
`HarvestDone` for one of those addresses writes white even though the
address was not drawn from gray.

That exception is the fleet, not the word "seed". `--seed-node`, `--add-peer`,
and a peerlist taken from a seed are not it. Addresses a seed returns are
incoming, and they are admitted to gray.

The fleet is not loaded onto white. Startup does not treat those six as
already confirmed. The handshake is still required. Today's seed dial
closes on `just_take_peerlist` before any white write
(`src/p2p/net_node.inl:1695`, from `connect_to_seed` at `:2032`). For
this fleet, `apply(HarvestDone)` writes white. For every other harvest,
that close leaves white unchanged.

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
| `disclose(disclose_count)` | The connector's cached sample: `disclose_count` distinct white addresses of that connector, uniform, order randomized. Gray is absent. `last_observed` is absent. Interim `disclose_count` is the composition's 12 |
| `apply(outcome)` | The only writer of `White`, and the only drop of an outstanding gray draw. The match is total |

`apply` matches `DialOutcome`:

| Variant | List effect |
| --- | --- |
| `SessionAccepted` | Outstanding gray draw: move to white and set `last_observed`. The session stays. Already white, on a session this node opened: move the clock. Anything else: white unchanged |
| `Confirmed` | Outstanding gray draw: the same white write. No session remains. Anything else: white unchanged |
| `HarvestDone` | One of the six Foundation hosts: the same white write. Anyone else: white unchanged |
| `DialFailed`, `PeerlistRefused` | Outstanding gray draw is dropped. A white address stays white |
| `PayloadRefused` | No promotion, no demotion, no gray drop. An outstanding draw stays gray |

*Records-was: `handshake_confirmed` was the only writer, and `draw_failed`
dropped an outstanding gray draw. A refused payload shared that failure
path. The spellings are not in Rust.*

C++ disclosure walks white newest-first and then shuffles
(`src/p2p/net_peerlist.h:302`, `:312`). Both callers pass the anonymize flag
(`get_peerlist_head` at `src/p2p/net_node.inl:2721` and `:2843`), so the
sample that goes out is already a shuffle of the whole white list,
truncated. The dial path never became a draw: it sorts candidates by
`last_seen` (`src/p2p/net_node.inl:1935-1938`) and picks with a bias
toward the front of that order (`:1970-1974`). Rust has no time-ordered
walk for
either caller. The property PWD-I2 kept is the one `disclose` has to keep: two
answers cannot be lined up to infer which address was confirmed more recently.

### Cached disclosure — INTERIM 2026-10-08

One sample per connector. It is drawn once and kept for a window. The
window starts at the 24-hour white expiry (`EXPIRATION_PERIOD`). Every
requester in that window, on that connector, receives that sample.
Refresh draws a new sample for that connector only. Interim
`disclose_count` (12) is the sample size and the number of addresses
this node accepts from one message.

The cache is per connector. Serving one sample on two connectors
links this node's IP and its onion: the same addresses on both
answers are the join.

**Receiver limits, every connector.** A message with more than
`disclose_count` addresses is a violation. It is not trimmed and kept.
Gray also has a per-source share limit, so one sender cannot fill the
list. The share is part of the derivation of `disclose_count` still
owed above: intake
diversity, honest fill, and per-reply exposure. No share number is
set here.

**Wargame: fresh samples enumerate white.** A requester who is
answered with a new uniform draw each time unions the answers and
walks white, and white includes the peers this node currently dials.
The cached sample closes that inside the window: a repeat adds no
address. The window is what limits how often the union grows.

---

## 6. Operations beside the door

| Operation | Effect |
| --- | --- |
| `admit_gray(address)` | Insert into gray. Does not touch a white entry at that address. This is the incoming path, the gossip path, `--add-peer`, exclusive, priority, and load |
| `bootstrap_harvested(addresses)` | `admit_gray` for each returned address. The dialed harvest peer is not promoted by this call |
| expiry | `now - last_observed >= EXPIRATION_PERIOD` moves that white address to gray and does not copy the clock across |

`--add-exclusive-node` and `--add-priority-node` are gray admits. Today
`connect_to_peerlist` (`src/p2p/net_node.inl:2912`) dials them straight onto
white. `apply` writes white on that path only for `SessionAccepted`
or `Confirmed` of an outstanding gray draw, or `HarvestDone` of a
Foundation host.

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
| Promote from a bare address and stamp now | `set_peer_just_seen`, `src/p2p/net_peerlist.h:334` | No such function. White is written only by `apply` under §5 |
| Two white writes on one kept outbound dial | `set_peer_just_seen` at `src/p2p/net_node.inl:1403` and `append_with_peer_white` at `:1707` | One `apply`, and only for `SessionAccepted` or `Confirmed` of the gray draw or `HarvestDone` of a Foundation host |
| `trust_last_seen` | `append_with_peer_white`, `src/p2p/net_peerlist.h:347` | No flag. The clock moves only on contact this node initiated |
| Gossiped `last_seen` stored on gray insert | `src/p2p/net_peerlist.h:239`, `src/p2p/net_peerlist.h:405` | Ignored. Gray has no clock |
| Time order as a rank | `by_time` at `src/p2p/net_peerlist.h:184`; the dial sort at `src/p2p/net_node.inl:1935-1938` | Uniform draws. Load is unordered |
| White list never expires on age | trim is capacity only, `src/p2p/net_peerlist.h:215` | `EXPIRATION_PERIOD` demotes to gray |
| Foundation seed handshake does not promote | the `just_take_peerlist` close at `src/p2p/net_node.inl:1695` | §3. `HarvestDone` for this fleet writes white |
| `--add-peer` kept off the trim front by a synthetic absence of `last_seen` | `src/p2p/net_peerlist.h:444` | The named address is admitted to gray and is not the one a full list drops. The draw is still uniform |

`append_with_peer_white(const peerlist_entry&)` accepts any entry. Porting
that signature is the hole §5 closes.

---

## 9. What the quarry is actually for

These C++ outcomes match the lists. The functions that produce them are not
the API.

- `--add-peer` is gray (`append_operator_candidate`, `src/p2p/net_node.inl:1098`, `src/p2p/net_peerlist.h:419`).
- An inbound advertisement is gray (`append_with_peer_gray`, `src/p2p/net_node.inl:2831`).
- A received peerlist is merged into gray (`src/p2p/net_peerlist.h:239`).
- Inbound timed sync does not write white (`src/p2p/net_node.inl:1467-1468` writes only when the session is one this node opened).
- The file cannot represent white (`src/p2p/net_peerlist.cpp:310`).

C++ `gray_peerlist_housekeeping` writes white
(`set_peer_just_seen` at `src/p2p/net_node.inl:3363`) after a
handshake that already closed (`check_connection_and_handshake_with_peer`,
the close at `:1752`). That probe does not keep a session and does not
consult the outbound cap. The fill's gray dial does keep one
(`try_to_connect_and_handshake_with_new_peer` at `:2019`). Rust does
not merge those into a harvest. A kept gray dial is `SessionAccepted`.
A confirm while outbound is already at target is `Confirmed`: white
is written and no session remains. A harvest stays `HarvestDone` and
writes white only for the Foundation fleet. *Records-was: this
paragraph called the probe a harvest, so a peer outside that fleet
stayed off white.*

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

Until slice 3 lands the dialer, C++ is still the process that dials. It
does not choose the list. The reports it will make, once the dialer
exists, are:

- `draw_gray` / `draw_white` / `disclose`
- `apply(DialOutcome)`
- `admit_gray` / `bootstrap_harvested`

*Records-was: `handshake_confirmed(address)` / `draw_failed(address)`,
and the sentence that slices 3 and 5 both had to move the dial first.*

A `u16` named on both sides of the FFI is not the mitigation. The port carries
no provenance either way. The residual lie is a caller whose `apply` promotes
an address the peerlist did not draw and that is not in the Foundation fleet.
`SessionAccepted` or `Confirmed` of an undrawn ordinary address writes
nothing. `HarvestDone` writes white only for the six hosts. The match
cannot be talked into a third door. `Confirmed` is not that door: it
is the same gray draw, closed after the payload is accepted.

---

## 11. Falsifiers

They check different things. Neither stands for the other.

1. **Constructor reachability (source).** `White` has no public constructor.
   The only call is inside `apply`, and that match promotes only
   `SessionAccepted` or `Confirmed` of an outstanding gray draw, or
   `HarvestDone` of a Foundation-fleet address. There is no `bool` on
   either type, and no
   `last_seen` beside `last_observed`. There is no ordered iterator. The
   check fails if it cannot find the constructor it is asserting about
   (rule 47).
2. **No entry crosses connectors (ruled 2026-09-25).** On admit, on
   disclosure, on eviction, and on reload, including the whole-list
   rejection when one foreign entry arrives. If a future network shares
   address syntax with another, so its connector cannot be derived from the
   address type, the connector becomes a stored field, validated against the
   address at admit, and D7 reopens on the same event.
3. **Model sequences (runtime).** An outstanding gray draw promotes on
   `SessionAccepted` and on `Confirmed`; either outcome on an undrawn
   ordinary address does not; a Foundation seed `HarvestDone` does; incoming
   and `--add-peer` stay gray; expiry returns white to gray; contact this node
   opened moves the clock; inbound contact does not; reload is gray only and
   does not draw former white first; `disclose` is a sample of white and
   carries no clock; `DialFailed` and `PeerlistRefused` drop an outstanding
   gray draw; `PayloadRefused` leaves that draw on gray; a failed redial
   leaves white.
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
| Uniform gray draw, kept dial, `SessionAccepted` | Yes. The session stays |
| Uniform gray draw, confirm while outbound is at target, `Confirmed` | Yes. No session remains |
| Same address, already white, `SessionAccepted` on a session this node opened | Clock moves. Already white |
| Foundation fleet, `HarvestDone` | Yes. §3 |
| Bootstrap harvest of anyone else | No. Returned addresses are gray |
| `--add-peer`, exclusive, priority | No. Gray until drawn |
| Incoming peer, advertisement, received peerlist | No. Gray only |
| Reload | No. Gray, unordered |
| White, no contact for `EXPIRATION_PERIOD` | Demote to gray |
| Undrawn ordinary address, `SessionAccepted` | No |
| Outstanding gray draw, `PayloadRefused` | No. Stays gray |

Where a later lane will try:

- **Cluster T's Noise transcript.** A transcript is not the door. The dialer still has to have drawn the address from gray, or be confirming a Foundation seed.
- **A relay that succeeds.** Bytes on a path are not a gray draw.
- **An operator assertion.** `--add-peer` is gray. Ruling that an operator may assert white is a steering decision, and it would be a third door.

Falsify the constructor by a `SessionAccepted` gray draw that `apply`
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
  calls `draw_gray`, `draw_white`, and `apply`. It does not grow a third
  door. The Foundation fleet is data this slice reads, not a second
  selector.
- No connection object. Slice 5. Expiry and the clock do not wait for it.
- The gray cap 5000 and the white cap 1000 are not re-derived. No
  `--in-peers` number, no refusal-window number. The interim `n` and
  the per-source gray share are intake limits, and the share's number
  is still the derivation.
- The failure cache stays where it is. It may cause the dialer to skip an
  address `draw_gray` returned. It does not write white.
- Disclosure is that connector's cached sample of white, with no clock
  in the value. PWD-I2's property (a second answer does not reveal which
  address was confirmed more recently) is what one sample per window
  keeps. The `by_time` walk is not part of that property.

---

## 15. What this brief does not decide

The on-disk byte layout past "an unordered set of addresses, no
`last_observed`, no white tag", and the crate's name.

It does not re-open §4.2's ordering.

It does not claim the C++ peerlist is the specification. §8 is the list a port
would otherwise preserve.

**Ban-list coordination is open (2026-09-28).** The ban list and these
lists are separate today. Discovery's pre-dial check is the only link,
so a banned host can still be drawn and disclosed. This slice decides,
per connector — only clearnet addresses can be banned
([`P2P_TRANSPORT_LAYER.md`](P2P_TRANSPORT_LAYER.md) D7) — whether a ban
removes or marks entries, whether banned addresses are refused at admit
and excluded from disclosure, and what an expiry does. That decision is
not inherited from the two lists staying independent.
