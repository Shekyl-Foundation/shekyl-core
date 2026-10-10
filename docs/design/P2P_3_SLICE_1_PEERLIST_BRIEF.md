# P2P-3 slice 1 — the peerlist

**Status:** **REVISED 2026-10-09 (decision-anchored: Rick's D3, D4
and D-S1 rulings and the PR-2 kickoff, recorded in #1018).**
`DISCLOSE_COUNT = 12` is a protocol constant, the same on every node
and every connector (D3, §5a); a ban demotes a white entry to gray and
never removes it (D4, §5b); gray intake is capped per session at
`2 × DISCLOSE_COUNT` distinct addresses in any 24-hour span (D-S1,
§5c); the handshake carries no address (dialer brief). PR-2 is slice 1
increments 1 and 2, pre-flight first (§16). *Records-was: REVISED
2026-10-08 (decision-anchored: PR #1001): per connector,
`disclose_count` was that connector's outbound target and
`white_diversity_floor` was `INTERIM_WHITE_DIVERSITY_MULTIPLE` (4)
times that count.* The floor is still 4 × 12 = 48. The list writer is `apply(DialOutcome)`. The
derivation of the floor runs on the Rust path after the slice 3
cutover (Ruling B, 2026-10-08); it does not gate this slice's crate
increments. Until then the floor, the refill line and the per-source
gray share are named interim constants, labelled `Assumption` in
`DAEMON_RELAY_PRIVACY.md` §97.
*Records-was: "the derivation of the floor is still owed", and before
that REVISED 2026-09-25 (connector partition; white target is
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
a banned one (`handle_remote_peerlist`, `net_node.inl:2472`; D4, §5b:
refused at admit during the ban, and a white entry under a ban is
demoted to gray when white is next read). Until
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
uniform draw of `min(DISCLOSE_COUNT, white)` from white, cached per
connector per 24-hour window (D3, §5a). Gray is never in that message.

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

**`DISCLOSE_COUNT = 12` (D3, Rick, 2026-10-09).** A protocol
constant, the same on every node and every connector. It replaces
`P2P_DEFAULT_PEERS_IN_HANDSHAKE` (250, `cryptonote_config.h:193`) and
`P2P_MAX_PEERS_IN_HANDSHAKE` (`:194`, also 250): the size this node
sends and the most it accepts in one message. It is not tied to the
outbound target. `white_diversity_floor` is
`INTERIM_WHITE_DIVERSITY_MULTIPLE` (4) times `DISCLOSE_COUNT`, 48.
Both are labelled `Assumption` in `DAEMON_RELAY_PRIVACY.md` §97 and
derived on the Rust path after PR-3. *Records-was (2026-10-08):
`disclose_count` was that connector's outbound target, `hidden_out` or
`clearnet_out`, each `MIN_PROVISIONED_OUT_PEERS` or
`P2P_DEFAULT_OUT_PEERS` (both 12) until a ruled operating point, and
"when it is ruled, `disclose_count` and the floor move with that
connector's target". Records-was the same day: outbound degree 16,
`disclose(n)` with `n = 16`, floor about 64. Sixteen was the withdrawn
§95.2 illustration.* The operating point (`DAEMON_RELAY_PRIVACY.md`
§95) is still unchosen; under D3 it no longer moves the sample size. **The derivation is not a gate before the cutover
(Ruling B, 2026-10-08).** The white floor and the refill line ship as
named interim constants, each labelled `Assumption` in the register
(`DAEMON_RELAY_PRIVACY.md` §97); the per-source gray share is folded
into D-S1's per-session cap (D-PR2-1, §16.3). They are
derived on the Rust path after the slice 3 cutover: the list's
behaviour includes dial timing, and dial timing is C++ until then, so
a derivation made now would rest on a `CppPath` reading. What that
derivation owes, when it runs: the white floor and the refill line,
from draw diversity and the candidate filters; `disclose_count`, from
intake diversity, honest fill, and per-reply exposure. The multiple 4
is the interim stand-in for that floor, not the derivation.
*Records-was: "the derivation this slice still owes", read as owed
before the cutover.* The refill line stays above the floor. The gap is
headroom. Refill starts when white crosses the refill line, while it
is still above the floor, so the node is not probing stale gray
entries in the moment connectivity has already collapsed.

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
drawable gray address. An outstanding draw is not a candidate: the dialer
has it, and only `apply` moves it (§5). While those dials are in flight and
no other drawable gray seat remains, gray may sit over the cap by that
handful rather than cancelling one. Over the white cap, demote a random
white address to gray. The
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
| `draw_gray()` | One uniform drawable gray address, remembered as an outstanding draw. Outstanding is still gray to every reader, and is not drawn again until `apply` returns it |
| `draw_white()` | One uniform white address. Used to re-contact, which can refresh the clock. Not a promotion |
| `disclose()` | The connector's cached sample: `min(DISCLOSE_COUNT, white)` distinct white addresses of that connector, drawn uniformly once per 24-hour window and sent unchanged to every requester in the window (D3, §5a). A sample once drawn is served until its window ends, whatever white does meanwhile; the floor is checked only when a sample is drawn, and below `white_diversity_floor` nothing is drawn (F1, 2026-10-09). Gray is absent. `last_observed` is absent. No exceptions by default |
| `snapshot()` | Read-only, for the RPC `peers` grant: every address and which list it is on. No `last_observed`, no order (PR-2, Rick 2026-10-09) |
| `apply(outcome)` | The only writer of `White`, and the only transition of an outstanding draw: promote, drop, or return it to drawable gray. The match is total |

`apply` matches `DialOutcome`:

| Variant | List effect |
| --- | --- |
| `SessionAccepted` | Outstanding gray draw: move to white and set `last_observed`. The session stays. Already white, on a session this node opened: move the clock. Anything else: white unchanged |
| `Confirmed` | Outstanding gray draw: the same white write. No session remains. Anything else: white unchanged |
| `HarvestDone` | One of the six Foundation hosts: the same white write, from any seat. Anyone else: white unchanged, and an outstanding draw of that address returns to drawable gray |
| `DialFailed`, `PeerlistRefused` | Outstanding gray draw is dropped. A white address stays white |
| `PayloadRefused` | No promotion, no demotion. An outstanding draw returns to drawable gray |

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

### Cached disclosure — RULED 2026-10-09 (D3)

One sample per connector. It is drawn uniformly once per 24-hour
window and kept for the window. Every requester in that window, on
that connector, receives that sample unchanged. Refresh draws a new
sample for that connector only. `DISCLOSE_COUNT` (12) is the sample
size — `min(12, white)` when white is short — and the most this node
accepts from one message. *Records-was (INTERIM 2026-10-08): the
window started at the 24-hour white expiry (`EXPIRATION_PERIOD`) and
the size was the interim `disclose_count`.*

The cache is per connector. Serving one sample on two connectors
links this node's IP and its onion: the same addresses on both
answers are the join.

**Receiver limits, every connector.** A message with more than
`DISCLOSE_COUNT` addresses is `PeerlistRefused`. It is not trimmed and
kept. Gray intake is also capped per session (D-S1, §5c): more than
`2 × DISCLOSE_COUNT` distinct addresses from one session in any
24-hour span is `PeerlistRefused`, and an honest peer's cached sample
cannot reach it. *Records-was: "gray also has a per-source share …
the crate PR names it."* That share is folded into the per-session cap
(D-PR2-1, RULED 2026-10-09, §16.3): one intake rule, keyed on the
session; the clearnet reconnect throttle registered in
`P2P_TRANSPORT_LAYER.md` covers the host case, and Tor stays a
residual there. The derivation of `DISCLOSE_COUNT` and the cap runs
on the Rust path after the cutover: intake diversity, honest fill, and
per-reply exposure.

**Wargame: fresh samples enumerate white.** A requester who is
answered with a new uniform draw each time unions the answers and
walks white, and white includes the peers this node currently dials.
The cached sample closes that inside the window: a repeat adds no
address. The window is what limits how often the union grows.

### 5a. D3 — the sample's exceptions (RULED 2026-10-09)

**Default: the sample has no exceptions.** It is the uniform draw of
§5, with this node's own dialable address as one uniform member when
it is known (the dialer brief's handshake-address ruling: the
clearnet entry is included when known; a hidden connector's address
likewise; it has no special position). A node discloses nothing on a
connector until that connector's eligible white list reaches
`white_diversity_floor` — checked when the window's sample is drawn; a
sample already drawn is served until the window ends even if white
falls below the floor meanwhile (F1), since a reply that changed
mid-window would tell the requester what changed.

An exception — leaving out this node's current outbound sessions —
goes in only if a conformance measurement in PR-2 shows it helps:

- *The observer:* a requester that polls the cached sample every
  window. Run once controlling some of our outbound peers, and once
  controlling none.
- *What it tries to identify:* our current outbound peers, and our
  hidden stem slot.
- *The comparison:* the uniform sample against the sample that leaves
  out current outbound sessions. Report how much better the observer
  guesses under each.
- *The rule:* the exception is adopted only if it lowers the
  observer's success and no observer gains from it. Otherwise the
  uniform sample stands.

The banned-entry exclusion is not measured: under D4 (§5b) a banned
white entry is already demoted to gray before white is sampled, so
there is nothing to exclude.

**Results (PR-2, `shekyl-peerlist::conformance::simulate_disclosure_exception`,
pinned by `tests/exception.rs`).** `|O| = 12`, every outbound session
on the connector hides the address (the hidden connector, where the
hidden slot lives), 400 trials per cell. *beyond* is how many nodes
the absence observer knows that are not on our white list (0 is an
observer who knows `W` exactly); *ctrl* is how many of `O` it controls;
`k` is windows polled. Cells are precision / recall on the uncontrolled
outbound sessions; *slot* is the chance of naming the hidden stem slot.

| `W` | beyond | ctrl | `k` | uniform, presence | uniform, absence | excluded, presence | excluded, absence | slot (excl. absence) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 48 | 0 | 0 | 1 | 0.25 / 0.25 | 0.25 / 0.75 | 0 / 0 | 0.33 / 1.00 | 0.083 |
| 48 | 0 | 0 | 7 | 0.25 / 0.86 | 0.27 / 0.14 | 0 / 0 | 0.86 / 1.00 | 0.083 |
| 48 | 0 | 0 | 30 | 0.25 / 1.00 | 0 / 0 | 0 / 0 | **1.00 / 1.00** | 0.083 |
| 48 | 0 | 4 | 30 | 0.18 / 1.00 | 0 / 0 | 0 / 0 | **1.00 / 1.00** | 0.125 |
| 48 | 48 | 0 | 30 | 0.25 / 1.00 | 0 / 0 | 0 / 0 | 0.20 / 1.00 | 0.083 |
| 100 | 0 | 0 | 7 | 0.12 / 0.59 | 0.12 / 0.41 | 0 / 0 | 0.28 / 1.00 | 0.083 |
| 100 | 0 | 0 | 30 | 0.12 / 0.98 | 0.10 / 0.02 | 0 / 0 | **0.93 / 1.00** | 0.083 |
| 100 | 100 | 0 | 30 | 0.12 / 0.98 | 0.00 / 0.03 | 0 / 0 | 0.11 / 1.00 | 0.083 |

**Reading.** Under the uniform sample neither observer learns anything
about `O`: the presence observer's precision is the base rate
`|O| / |W|` at every `k`, and the absence observer's falls to zero as
the union of samples covers `W`. The exception silences the presence
observer — a disclosed address is never an outbound session — and
hands `O` to the absence observer: recall 1 at every `k`, precision
rising to `|O| / (|O| + beyond + unseen)` as the uniform draw covers
the rest of white, 1.00 at `|W| = 48` after thirty windows when `W` is
known, 0.93 at `|W| = 100`, and the hidden slot one guess among the
outbound hidden sessions (`1/12`) instead of one among the whole
hidden white list. An observer who knows little beyond `W` gains
certainty; an observer who knows twice `W` still gains over the
uniform sample at every `k`.

**Outcome, by the rule above: the exception is not adopted. The
uniform sample stands.** It lowers one observer's success and raises
another's, and the one it raises is the cheaper to be: polling and
remembering what was *not* said.

### 5b. D4 — a ban demotes, it does not remove (RULED 2026-10-09)

**Demotion.** A white entry covered by an active ban (host, or IPv4
subnet, per the transport layer's ban list) is moved to gray. The
demotion happens when white is next counted, drawn from, or sampled;
the transport layer never writes the peer list. White therefore holds
only unbanned, confirmed peers, so the floor and the refill line count
white as it stands.

**Gray handling.** A demoted entry is an ordinary gray entry, subject
to normal random eviction, with no protection; it enters gray through
the capped insert, so a mass demotion — a subnet ban, an expiry sweep —
leaves gray at or below its cap (F3). While the ban lasts,
the dialer's pre-dial ban check skips it, and gray admission refuses
it if it is gossiped back in. After the ban expires, it can be drawn,
dialled, and earn white again through `SessionAccepted` or
`Confirmed` — the normal door, §2.

**Disclosure is unchanged:** gray is never disclosed, and the cached
sample is not rebuilt on a ban.

**Scope:** the clearnet partition only. Tor has no bannable address
(`P2P_TRANSPORT_LAYER.md` D7).

**Tests (PR-2):** a banned white entry is demoted on the next white
read; the floor count drops with it; it is evictable from gray; it is
skipped by the pre-dial check during the ban; after expiry it re-earns
white only through the normal door.

### 5c. D-S1 — gray intake per session (RULED 2026-10-09)

Gray intake is limited per session, the same on every connector: at
most `2 × DISCLOSE_COUNT` distinct addresses per session in any
24-hour span (24 today). Exceeding it is `PeerlistRefused`: an honest
peer's cached sample cannot exceed it. The cap is checked for a whole
received list before any entry is admitted, so a list that would cross
it admits nothing (F2); a banned entry never enters gray and is not
counted. The limit is a named constant
derived from `DISCLOSE_COUNT`, labelled `Assumption` in
`DAEMON_RELAY_PRIVACY.md` §97, and applies to inbound and outbound
sessions alike.

*Measurement*, part of the `DAEMON_RELAY_PRIVACY.md` §96 item 3
instrument: time for an attacker to fill gray and the resulting
`p_h`, per connector, under this limit.

*Transport-layer question*, registered in `P2P_TRANSPORT_LAYER.md`
and not built in PR-2: a reconnect throttle on clearnet. Tor has no
host to throttle; that is recorded there as the residual.

---

## 6. Operations beside the door

| Operation | Effect |
| --- | --- |
| `admit_gray(address)` | Insert into gray when the address sits nowhere. An address already gray, outstanding, or white is left where it sits; the call reports whether it newly entered gray, and a seated address is not a new intake charge. This is the incoming path, the gossip path, `--add-peer`, exclusive, priority, and load. Refused while the address is under an active ban (D4) and when the session's 24-hour intake would pass `2 × DISCLOSE_COUNT` distinct addresses (D-S1, `PeerlistRefused`) |
| ban demotion | A white entry under an active ban moves to gray at the next white read: count, draw, or sample (D4, §5b). The clock is not copied across |
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
   gray draw; `PayloadRefused`, and a non-fleet `HarvestDone`, return that
   draw to drawable gray; a failed redial leaves white.
   The harness fails if it has no sequence (rule 47).
4. **The C++ list is gone, and so is the old spelling.** `rg -n 'm_peers_white|peerlist_manager' src/p2p`
   returns nothing. `rg -n pruning_seed src rust tests` returns nothing,
   comments included. A gate that allowlists the word in a comment or a
   negative test has not finished.
5. **PR-2 additions (Rick, 2026-10-09).** Beside §11.1 to §11.3:
   - *D4:* a banned white entry is demoted on the next read, the floor
     count drops with it, and the entry is evictable from gray.
   - *D-S1:* the 25th distinct address from one session within 24 hours
     is a violation; a list that would cross the cap admits nothing (F2).
   - *F1:* white drops below the floor mid-window and the reply is
     unchanged. *F3:* mass demotion leaves gray at or below its cap.
   - *Sampling:* below the floor the sample is empty; above it, our own
     address is drawn uniformly as one member.
   - *Snapshot:* the read-only snapshot for the RPC `peers` grant lists
     addresses and which list each is on, with no `last_observed`.
   - *The D3 exception measurement:* a conformance instrument compares
     the uniform sample with the sample that leaves out current
     outbound sessions, under the observer of §5a; the results are
     recorded in §5a.

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
| 1 | The crate `shekyl-peerlist`: gray, white, `EXPIRATION_PERIOD`, the draws, the door, the cached sample (D3), ban demotion (D4), the per-session intake cap (D-S1), the snapshot, the address file. No FFI, no C++ | The crate's tests cover §11.2, §11.3 and §11.5, and `git diff dev..HEAD --stat -- src/ contrib/` is empty |
| 2 | The divergence ledger of §8, checked against the tree at the increment's pin; the D3 exception instrument and its results in §5a | Each §8 row names the Rust operation that replaces it, and §11.1 passes. **Checked 2026-10-09 at the PR-2 pin (§16.1):** every C++ site in §8 is where the row says (the `net_peerlist.h` lines moved by four, §16.1), and each row's Rust column is an operation the crate has — `Peerlist::apply` (rows 1, 2, 3, 7), `Source::Session` admits with no clock (row 4), `draw_gray` / `draw_white` / `restore` uniform (row 5), `Partition::expire` through every white read (row 6), `insert_gray`'s keep-the-named eviction (row 8) |
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
  `--in-peers` number, no refusal-window number. `DISCLOSE_COUNT` and
  the per-session cap are the intake limits (the per-source share is
  folded into the cap, D-PR2-1); both ship as named constants, and
  their derivation runs on the Rust path after the cutover (§97's
  register carries them as `Assumption`).
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

**Ban-list coordination — RULED 2026-10-09 (D4, §5b).** A ban
demotes; it does not remove. *Records-was (open 2026-09-28): the ban
list and these lists were separate, discovery's pre-dial check was
the only link, so a banned host could still be drawn and disclosed;
this slice was to decide, per connector — only clearnet addresses can
be banned ([`P2P_TRANSPORT_LAYER.md`](P2P_TRANSPORT_LAYER.md) D7) —
whether a ban removes or marks entries, whether banned addresses are
refused at admit and excluded from disclosure, and what an expiry
does.*

## 16. PR-2 — pre-flight (rule 26 Round 0, 2026-10-09)

**Status: OPEN — pre-flight recorded and increments 1 and 2 built on
`feat/p2p3-pr2-peerlist`, stacked on #1018 (`487d4550fc`), rebased onto
`dev` when #1018 merges; the §5a measurement is in and the exception is
not adopted; D-PR2-1 and D-PR2-2 are RULED (§16.3, 2026-10-09).** PR-2 is increments 1 and 2 (§13). The
rulings it implements are D3 (§5a), D4 (§5b), D-S1 (§5c) and the PR-2
additions (§11.5), written in #1018's docs commit so they reach `dev`
first. This section is the substrate re-check between those rulings
and the crate's first production commit. PR-2 mints no identifier
family. No FFI, no C++: `git diff dev..HEAD --stat -- src/ contrib/`
is empty at every commit.

### 16.1 Substrate re-check (A2) — read at `dev` `a86ba6d13f` + #1018

**The quarry.** `src/p2p/net_node.inl` is frozen (Ruling A) and every
citation this brief makes into it is where `f317d979c4` left it:
`get_ip_seed_nodes` `:771`, the array at `:781`; `append_operator_candidate`
`:1098`; `do_handshake_with_peer` `:1329`; `set_peer_just_seen` `:1403`
and `:3363`; `handle_remote_peerlist` `:2448`; `connect_to_peerlist`
`:2912`; `append_with_peer_white` `:1707`; the `just_take_peerlist`
close `:1695`; `get_local_node_data` `:2477`; `get_peerlist_head`
callers `:2721` and `:2843`; `append_with_peer_gray` `:2831`;
`gray_peerlist_housekeeping` `:3336`; the timed-sync self-insertion
`:2717` to `:2735`. `src/p2p/net_peerlist.h` has moved by four lines
since the body citations were written: `by_time` `:188` (was `:184`),
`trim_white_peerlist` `:217` (`:215`), the gray merge of a received
list `:243` (`:239`), `set_peer_just_seen` `:338` (`:334`),
`append_with_peer_white(…, bool trust_last_seen)` `:351` (`:347`), the
kept previous `last_seen` `:371` (`:367`), the `--add-peer` synthetic
absence `:446` (`:444`). `src/p2p/net_peerlist.cpp`: the v8 comment that
anchor and white are gone `:97` (`:82`), load `:171` (`:156`), save
`:308` and `:317` (`:306`, `:318`). `p2p_protocol_defs.h:66` is still
`last_seen`. `cryptonote_config.h`: gray cap `:183` (5000), white cap
`:182` (1000), `P2P_DEFAULT_PEERS_IN_HANDSHAKE` `:193` and
`P2P_MAX_PEERS_IN_HANDSHAKE` `:194` (both 250, replaced by D3). Nothing
the brief says about the C++ is contradicted; §8's rows hold.

**The Rust substrate the crate consumes** (B6: values read at the
line):

| Claim | Where | Holds? |
| --- | --- | --- |
| The address union is one type with three variants | `shekyl-net-address/src/lib.rs:19` `NetworkAddress::{Ipv4, Ipv6, Tor}`; `ip()` at `:49` is `None` for Tor | yes |
| The connector is derived from the address type, not stored | `shekyl-transport-layer/src/declaration.rs:487` `connector_for(&NetworkAddress) -> Option<ConnectorId>`; `addressing_of` at `:123` | yes. `None` is "no local connector serves this type", §2's refusal at admit |
| The ban list is the transport layer's and is read, never written, by the peer list | `shekyl-transport-layer/src/ban.rs:151` `BanList`; `is_banned(&mut self, IpAddr, Tick)` at `:240`, hosts and IPv4 subnets, expiry on lookup | yes. The crate takes a ban query at every white read (D4); it never holds a `BanList` |
| Only clearnet addresses can be banned | `is_banned` takes an `IpAddr`; `NetworkAddress::Tor::ip()` is `None` | yes (D7). The Tor partition never demotes on a ban |
| The clock is `Tick`, nanoseconds, with a hand-moved test clock | `shekyl-timing-engine/src/lib.rs:26` `Tick(u64)`; `ManualClock` `:46` | yes. `last_observed`, the window and the intake span are `Tick`s; `EXPIRATION_PERIOD` is 24 h in nanoseconds |
| A uniform draw primitive exists and is already a transport-layer dependency | `shekyl-relay-privacy/src/rng.rs:33` `RelayRng`, `bounded_uniform`, `SplitMix64`; `shekyl-transport-layer/Cargo.toml` depends on `shekyl-relay-privacy` | yes. The crate uses it; no new RNG abstraction |
| The `DialOutcome` variants are the ones §5's `apply` table names | §5 table: `SessionAccepted`, `Confirmed`, `HarvestDone`, `DialFailed`, `PeerlistRefused`, `PayloadRefused` | the dialer crate does not exist yet (PR-3); PR-2 defines the enum here and PR-3 consumes it |
| The reference draft | local branch `feat/p2p3-slice1-peerlist`, one commit `6faa836dc1` (2026-09-23, base `dbfc07623d`): increment 1 as first drafted, with `Hypothesis`/`Observed` types, a `Reached` token and `complete_dial` | predates the 2026-09-25 partition ruling, the 2026-10-08 revision and D3/D4/D-S1. Read as a reference for the constructor-reachability shape (§11.1); not cherry-picked |

### 16.2 The crate (B4) — `rust/shekyl-peerlist`

One `Peerlist`, holding one partition per connector, keyed by
`connector_for` at every admit; an address whose type no connector
serves is refused there. Each partition gives an address one seat:
drawable gray (no clock), an outstanding draw (still gray to every
reader: the gray count, the snapshot and the file), or white
(address → `last_observed: Tick`). Also the cached sample and its
window, and the per-session intake ledger. Constants, each a named item the crate owns and §97 labels
`Assumption`: `DISCLOSE_COUNT = 12`; `SESSION_INTAKE_CAP = 2 ×
DISCLOSE_COUNT`; `INTERIM_WHITE_DIVERSITY_MULTIPLE = 4` and
`white_diversity_floor() = 48`; `WHITE_REFILL_LINE = floor +
DISCLOSE_COUNT = 60` (one sample of headroom: a window's worth of
confirmations before the floor; RULED as D-PR2-2 below, labelled
`Assumption`); `GRAY_CAP = 5000`,
`WHITE_CAP = 1000` (the C++ values, not re-derived);
`EXPIRATION_PERIOD = DISCLOSE_WINDOW = INTAKE_SPAN = 24 h`.

Operations, as §5 and §6 name them, with the ruling each carries:

- `admit_gray(address, source, now)` → `Result<bool, Refusal>`: the
  connector from the type (none → `Refusal::NoConnector`); a banned
  address is `Refusal::Banned` (D4), before any intake charge; the
  session's distinct addresses in the last 24 h at the cap is
  `Refusal::PeerlistRefused` (D-S1); over `GRAY_CAP`, one random
  drawable gray entry is evicted, never an outstanding draw. An address
  already gray, outstanding, or white is left where it sits. The `bool`
  is whether it newly entered gray; a seated address is not a new
  intake charge. The session id is `ConnectionId`.
- `draw_gray(connector, rng)` / `draw_white(connector, bans, now, rng)`:
  uniform; `draw_white` demotes banned entries first (D4) and evaluates
  expiry.
- `apply(outcome, now)`: the only writer of white, the §5 match, total.
- `disclose(connector, bans, now, rng)`: demotes and expires, counts
  eligible white; below the floor, empty; else the cached sample if its
  window has not passed, else `min(DISCLOSE_COUNT, population)` drawn
  uniformly from white plus this node's own dialable address on that
  connector when one is set, cached for the window. Not rebuilt on a
  ban (D4).
- `set_own_address(connector, Option<NetworkAddress>)` →
  `Result<(), Refusal>`: `None` clears. An address of another connector
  is `Refusal::ForeignConnector` and is not stored; an address no
  connector serves is `Refusal::NoConnector`. The handshake carries no
  address; this is how the node's own entry joins that connector's
  disclosure population.
- `white_count(connector, bans, now)`, `below_refill_line`,
  `next_deadline`: the floor and refill reads of §2, after demotion.
- `snapshot()`: every address and its list, no clock (the RPC `peers`
  grant).
- `persistable()` / `restore(addresses)`: an unordered set; restore is
  gray only. The byte layout is not this PR's (§15).

`White` has no public constructor and no `Deserialize` (§11.1). Every
operation takes the connector it works in; nothing crosses (§11.2).

### 16.3 Decisions — RULED (Rick, 2026-10-09)

**D-PR2-1 — RULED.** The per-source gray share is folded into D-S1's
per-session cap: one intake rule, keyed on the session. The reconnect
throttle (registered in `P2P_TRANSPORT_LAYER.md`, not built in PR-2)
covers the host case. Tor stays a residual: no host to throttle. No
second share constant is named; §97's row records the fold.
*Posed:* §5 and §97 carried a per-source share beside D-S1's count,
and with D-S1 ruled the share's source key was the open part — a
*session* being D-S1's key already, a *host* what the throttle would
count. Recommended and ruled: fold.

**D-PR2-2 — RULED.** The refill line is `floor + DISCLOSE_COUNT` = 60,
labelled `Assumption` in §97 and re-derived on the Rust path after
PR-3 with the floor. *Posed:* named at that value, accept or set
another headroom.

### 16.4 Falsifiers (§11), mapped to tests

§11.1 by construction and a test that the only `White` constructor is
inside `apply`; §11.2 by partition tests (admit, disclose, evict,
restore, the whole-list rejection); §11.3's sequences one test each;
§11.5: the D4 five, D-S1's 25th address, sampling below and above the
floor with the own address as one uniform member, the snapshot, and
the D3 exception instrument (16.5).

### 16.5 The D3 exception instrument

A conformance instrument in the crate (feature `conformance`), run
against the model, not the network: a node with white `W` at or above
the floor, outbound sessions `O ⊂ W` of size 12 with a hidden subset
and one hidden stem slot; an observer that polls the cached sample
every window for `k` windows, once controlling a share of `O` and once
controlling none. Two observers, because the rule says *no observer
gains*: the **presence** observer guesses that disclosed addresses are
outbound sessions; the **absence** observer, who knows `W` from its
own polling and its controlled peers, guesses that white addresses
never disclosed are the outbound sessions. Each reports precision and
recall on `O` and on the hidden slot, under the uniform sample and
under the sample that leaves `O` out. The exception is adopted only if
it lowers both observers' success. Results are recorded in §5a.

### 16.6 Commit plan (B5) — landed locally, pushed on authorisation

1. `docs: PR-2 pre-flight in the slice 1 brief §16` — `2b06d215fc`.
2. `peerlist: the crate — gray, white, the door, the draws, expiry` —
   increment 1's core with §11.1–§11.3's tests; no caller yet (the
   dialer is PR-3, named in §10 as the consumer). `65e94ad1d4`.
3. `peerlist: the cached sample (D3), ban demotion (D4), the intake cap
   (D-S1)` — §11.5's tests; the snapshot landed with commit 2.
   `9ecc3f02e2`; gray as an indexed set `093d4dbb3b`; F1–F3 (Rick,
   2026-10-09: the drawn sample served to the window's end, the cap
   checked for the whole list, demotion through the capped insert) with
   their tests, and F4's FOLLOWUPS row (the RNG trait's home), in the
   fix commit named below.
4. `peerlist: the D3 exception instrument` — 16.5, results into §5a.
   `cf380509b9`.
5. `docs: the §8 divergence ledger at the increment's pin` — increment
   2; §97's rows name the crate's items; this section's status.

### 16.7 Round denominator

Examined and yielding nothing: `shekyl-peer-policy` (the inbound
ceiling, slice 2's; the crate does not import it); `shekyl-levin`
(frames the address; the crate does not encode); the C++ `peerlist_manager`
locks and the anchor list (deleted in v8; nothing to port). Not
examined: the dialer's fill and its wake (PR-3's), the RPC `peers`
grant's wire shape (reads the snapshot; its own PR).
