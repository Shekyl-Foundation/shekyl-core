# P2P-3 slice 3 — discovery and the dialer

**Status: OPEN.** Design before code. Rule 26 is cited. No
implementation starts from this file until a review of it has closed.
**UPDATE 2026-10-09 (Rick):** `COMMAND_HANDSHAKE` carries no address
field on any connector (the handshake-address ruling below, which
replaces "The address we announce"); `disclose_count` is the protocol
constant `DISCLOSE_COUNT = 12` (slice 1 brief D3); the timed-sync
self-insertion is deleted at the cutover.
Lines below were read on `dev` at `f317d979c4` (2026-10-08), which
contains #991 and #1002. `record_addr_failed` takes the address, the
cause, and the reply (`net_node.h:675`). `shekyl_seam_session_cause`
is `rust/shekyl-ffi/src/cause_ffi.rs:55`, declared at
`shekyl_ffi.h:4430`. The C++ read is `net_node.h:229`.
*Records-was: the pin was `d93074d1c4`, and the declaration was
`shekyl_ffi.h:4448`.* This slice mints no identifier family. It is
the §4.2 row rescoped the same day.

**Ruling 2026-10-07 (Rick).** Order: #991 → slice 1 → this slice → RD.
Dialing moves to Rust. No further fixes to the C++ dial path. Slice 4
keeps the inbound handshake state machine and PWD-B1/B2. This slice
owns the outbound dial, the outbound handshake invoke, and the
outcome. Slice 4 owns the phases after a session exists.

The list writer is slice 1's `apply(DialOutcome)`. This slice emits
that value. It does not write gray or white itself.

---

## The composition

One record. Slice 1 reads it for `disclose_count` and the white
floor. This slice reads it for how many sessions to open. A later
ruling of the operating point edits this record, and both briefs move
together.

| Name | Value until a ruled operating point | Owner |
| --- | --- | --- |
| `hidden_out` | `MIN_PROVISIONED_OUT_PEERS` (12, `shekyl-relay-privacy/src/params.rs:203`) | This slice. The hidden-address pool. No hidden session above it |
| `clearnet_out` | `P2P_DEFAULT_OUT_PEERS` (12, `params.rs:179`), written by `set_max_out_peers` (`net_node.inl:2957`; the `arg_out_peers` call is `:621`) | The setter. A cap of 0 stays legal. A positive cap below the floor is refused. Clearnet is not folded into `hidden_out` |
| `DISCLOSE_COUNT` | 12, a protocol constant: the same on every node and every connector (D3, Rick 2026-10-09). Not tied to the outbound target | Slice 1. Replaces `P2P_DEFAULT_PEERS_IN_HANDSHAKE` (250, `cryptonote_config.h:193`) and `P2P_MAX_PEERS_IN_HANDSHAKE` (`:194`) as the sample size and the receiver limit. *Records-was: `disclose_count`, that connector's outbound target* |
| `white_diversity_floor` | `INTERIM_WHITE_DIVERSITY_MULTIPLE` (4) times `DISCLOSE_COUNT`, 48 | Slice 1. The multiple is the interim until slice 1's derivation names the floor, on the Rust path after PR-3. The refill line stays above the floor |

`hidden_out` is the outbound sessions whose connector declares
`address_hidden_from_peer`. On `dev`, `net_node.inl:984` assigns
`shekyl_relay_zone_min_provisioned_out_peers()` to
`max_out_connection_count`. This slice deletes that assignment and
keeps the target at `hidden_out`.

[`TOR_COVER_POSTURE.md`](TOR_COVER_POSTURE.md) and
[`TOR_RELAY.md`](../TOR_RELAY.md) already name that target.
*Records-was: `HOP0_OUTBOUND_TARGET` (4). The records-was comment is
`params.rs:201-202`. At `d93074d1c4`, `net_node.inl:939` still wrote
`shekyl_hop0_outbound_target`.* The 4 read the paper's 4-regular
anonymity graph (Dandelion++ §4.3, Algorithm 2: two outbound edges
plus about two inbound) as the size of the pool the relays are drawn
from. The paper draws those edges from the node's P2P outbound edges
(η = 8 in the simulations; the measured degree is 12).

The simulation plan is [`DAEMON_RELAY_PRIVACY.md`](DAEMON_RELAY_PRIVACY.md)
§95, **APPROVED 2026-10-08 (Rick).** The hidden-address pool and the
total outbound degree are lower limits. Each is at least
`MIN_PROVISIONED_OUT_PEERS`. The total floor is the fail-safe's
measured range (`fluff_return_ms = 3250` at degree 12). The operating
point above those floors, and any ceiling, are not chosen by the
approval. The ceiling comes from resources. `(h, 0)`, including
`(12, 0)`, is a measured case in §95.3. Recommending Tor-only waits
on §96. A total of 16 was an illustration in the §95.2 grid, and that
grid is records-was. It is not a degree this composition uses.

Stem-slot routing is §95.3: one slot from the hidden outbound
sessions, the other from the remaining outbound sessions, the local
source pinned on the hidden slot, relays forwarding with probability
`1 − q`. This slice does not restate a shorter routing. **UPDATE
2026-10-09:** the relay lane landed §95.3 as PR-1 (#1018,
`DAEMON_RELAY_PRIVACY.md` §98); `own_edge()` is deleted and
`NoOwnEdge` is the plan when no outbound session hides the address or
the origin's pin is exhausted. *Records-was: "`own_edge` and `NoOwnEdge`
stay on `dev` until the relay lane lands §95.3."* This slice depends
on nothing in them and does not choose the slot. Vocabulary (§98.11):
*dial candidates* are the gray and white lists; *hidden outbound
sessions* are the address-hiding subset of the live outbound sessions;
a *pin* is a source's frozen set in `StemMap`.

A later connector, I2P included, is a declaration column, that
connector's measured transit added in `verify_cost`
(`shekyl-relay-privacy`), which the declaration reads, and the
connector crate. `shekyl-relay` is not edited. The column's cells are
address hiding, cover class, and that transit. An unassessed transit
is not a stem edge. Its `disclose_count` is its own outbound target
once that target exists. Until then it has no row in this table.

Sharing one cap of 12 across both connectors would move the degree
the fail-safe was measured at. The two targets stay separate.

---

## The fill

One owner, one wake, one dial. The wake is the jittered spacing ruled
on 2026-09-25, drawn per dial. The spacing has the same shape on every
connector. The connector changes which list is drawn, not the clock.
The 60-second housekeeping timer is not the pace. The owner does not
block a p2p io worker.

Each wake, for one connector, takes the first arm that applies.

1. **Exclusive, then priority.** Exclusive nodes, then clearnet
   priority nodes. Today they are `connect_to_peerlist` at
   `net_node.inl:2912`, called from `connections_maker` (`:2111`) at
   `:2116` and `:2132`. The aim is `Keep`. An exclusive list skips
   harvest and every later arm. Offline skips the wake.
2. **Harvest.** The aim is `Harvest`. Both lists are empty (`has_no_known_peers`,
   `net_peerlist.h:147`), or the previous fill pass added no session
   while the connector is still under its outbound target. One seed
   address per wake. The cursor stops at the first `HarvestDone`.
   The seed list is `get_seed_nodes`, filled at `net_node.inl:2042`.
   Clearnet, once, after every seed has failed, adds
   `get_ip_seed_nodes` (`:2084`) and walks those the same way. The
   C++ `break` after `connect_to_seed`'s dial is `:2073`.
3. **`draw_white`.** The connector is under its outbound target, and
   white has an address that is not already an outbound session on
   that connector and that passes the candidate filter. The draw is
   uniform among those addresses. It re-contacts a white peer this
   node is not already connected to. It is not a promotion. The aim
   is `Keep`. An address already held is not a candidate. A wake
   does not spend itself rejecting one.
4. **`draw_gray`.** Slice 1 reports white under the refill line, the
   connector is still under its outbound target, and arm 3 did not
   apply. The aim is `Keep`. `SessionAccepted` moves that outstanding
   gray draw to white, and the session stays.
5. **`confirm_gray`.** The outbound target counts `Keep` rows only,
   including a `Keep` row still `Arming`, so arm 4 cannot run, and
   slice 1 still reports white under the refill line. One gray draw.
   The aim is `Confirm`. Adopting it inserts a row. That row does not
   count toward the target, is not refused because the target is
   already met, and is not a reason to close a `Keep` row. The strand
   must accept the payload. The session is then closed in that turn,
   the relay is not flipped, and `Confirmed` writes white. This is
   how white reaches the diversity floor while every `Keep` slot is
   full. It stops once white is at the refill line. It is the same
   wake, not a second clock.

The next wake can run while a dial is still in flight. Until
`Hub::adopt`, that address is not an outbound session and a `Keep`
row does not yet exist, so the arms above would not see it. The
dialer keeps a pending attempt from the moment `dial_channel`
returns until every `DialOutcome`. A pending attempt's address and
host are not candidates. A pending `Keep` counts toward the outbound
target. A pending `Confirm` or `Harvest` does not. The set is empty
after the outcome, including failure before adopt.

**The `Keep` count is the dialer's.** It is adopted `Keep` rows plus
pending `Keep` attempts, per connector. It is not `Board::count`
(`rust/shekyl-seam/src/registry.rs:175`), which counts every outbound
row on the connector, a `Confirm` row included, and knows nothing of
a pending attempt. Lowering the cap at runtime, today
`release_outbound` from `set_max_out_peers` (`net_node.inl:3176`,
defined at `:2240`), moves to the dialer and closes `Keep` rows only.
A `Confirm` row is never what the cap closes.

**Interim in-flight bound: one dial per connector (2026-10-08).** The
fill is one dial per wake, so the interim needs no measurement. It is
measured and raised on the Rust path after the cutover, into the
register (`DAEMON_RELAY_PRIVACY.md` §97). Wargame: at boot, hidden
sessions open one at a time. The node's own transactions are held
(`NoOwnEdge`) only until the first hidden session, so originating does
not wait for all 12.

*Records-was: `connections_maker` (`net_node.inl:2134-2157`) branches
on `P2P_DEFAULT_WHITELIST_CONNECTIONS_PERCENT` (70,
`cryptonote_config.h:200`). Below that share of the cap it tries white
then gray. At or above it, gray then white.* PWD-I4 derives against
this loop. The 70% schedule is what the C++ does until this slice
deletes it.

---

## The dial

`Hub::connect` (`rust/shekyl-seam/src/hub.rs:274`) is the composition
of two operations that already have different jobs. The implementation
PR splits them. `Hub::connect` stays the composition, so the seam
tests keep one call. Callers of `Hub::connect` today are
`hub_tests.rs`. Production dial is still C++ `zone.m_connect`.

| Operation | What it does | Who calls it |
| --- | --- | --- |
| `dial_channel` | `Dial::connect`. Returns the channel. No row, no `adopt` | This slice's dialer |
| `Hub::adopt` (`hub.rs:288`) | Registers a channel the connector already admitted. `write_row` (`:414`) inserts the row with `established: false` and `phase: Arming`, then posts `Post::Established` (`:41`) | The handshake owner, after a well-formed response that is not a harvest. `Post::Established` creates the strand handler. It is not promotion and it is not the relay flip |
| `Hub::connect` | `dial_channel`, then `adopt` | Seam tests. The outbound dialer does not call it |

The dialer passes a `DialAim` with the channel. The aim is input. The
outcome is what the dial became. The owner does not infer one from
the other.

```rust
enum DialAim {
    Keep,
    Confirm,
    Harvest,
}
```

The handshake owner reads frames on the channel. Those frames are not
`Post::Deliver`. On `Harvest`, or on any failure before a well-formed
response, the owner does not adopt. There is no strand and no
established delivery. A well-formed harvest peerlist is `HarvestDone`,
and the session is closed.

On a well-formed response whose aim is `Keep` or `Confirm`, the owner
adopts, then posts one handshake result. That post is not
`Post::Deliver`. `Post::Deliver` is one whole Levin message
(`hub.rs:48`) and the adapter feeds those bytes to `handle_recv`. A
handshake response arriving that way has no invoke handler on the
new strand and is the "no active invoke" close. The handshake owner
already decoded the response on the channel. The result post carries
the support flags, including zero, and the sync payload, and the
strand reads those fields. It does not parse them as a Levin
response. The post is the first strand post after `Post::Established`,
ahead of any later frame. The owner does not call
`process_payload_sync_data`.

In that one strand turn, before any later frame, the strand accepts or
refuses. On accept, `Keep` sets the session-established flag, flips
the relay registry (`shekyl_relay_zone_on_session_established`), and
the dialer emits `SessionAccepted`. `Confirm` does not flip the relay
and does not leave the row: the owner closes in that turn and emits
`Confirmed`. A confirm dial is never a stem edge. The outbound target
is the count of `Keep` rows on that connector. A `Confirm` row is
outside that count for the turn it exists. On refuse, either
aim closes the session and the dialer emits `PayloadRefused`. Nothing
enters the relay's peer set before the payload is accepted, and a
confirm dial does not enter it after.

The dialer does not wait on that turn. A slow strand cannot stall the
next wake. Until `SessionAccepted` or `Confirmed`, the session may be
up and the address is still gray.

**The clock (Rick, 2026-10-08).** The outbound handshake's only clock
is each connector's transport gap, from channel established to session
established ([`P2P_TRANSPORT_LAYER.md`](P2P_TRANSPORT_LAYER.md) D3, and
D11 item 5), armed by the connector with D9's values: clearnet 1.430 s
and Tor 2.6 s, set today in `transport_spans` (`net_node.inl:3527`,
`:3529`) and labelled `CppPath` in `DAEMON_RELAY_PRIVACY.md` §97. The
connector arms it when the channel exists. `dial_channel` returns that
channel with the gap already armed. Adopting later does not start
another clock. The 5 s Levin invoke timer
(`P2P_DEFAULT_HANDSHAKE_INVOKE_TIMEOUT`, armed at `net_node.inl:1414`)
is not the dialer's clock. Its outbound arm goes with
`do_handshake_with_peer` at the cutover. The owner does not arm a
second invoke timer. The gap firing is the connector's close. The
owner holds that cause. It does not call `shekyl_seam_session_cause`.
That read is the post-handshake race in the known-defect section.
*Records-was: the armed duration was the 5 s invoke timeout until D9
derived the per-connector value; D9 had already derived it. Before
that, the 5 s invoke was described as having no outbound-handshake
role.*

Test: no frame after the handshake reaches the strand before that
handshake result. With a refused payload, the relay registry never
holds the session. A second wake while a `Keep` dial has not yet
adopted does not dial that address or its host, and does not open
another `Keep` that would put the target over when both adopt.

---

## `DialOutcome`

One report. The dialer emits it on every end path. Slice 1's `apply`
is the only writer of gray and white, and the match is total. The
dialer is the only writer of the failed-address memory, and it reads
the same value. The score owner subscribes to `PeerlistRefused` and
writes neither store. The handshake task does not call
`add_host_fail`. That function stays: inbound and the open
`cryptonote_protocol_handler` row still use it. It is in flight, not
dead.

```rust
enum DialOutcome {
    DialFailed { address: NetworkAddress, cause: CloseCause, reply: u16 },
    PeerlistRefused { address: NetworkAddress },
    PayloadRefused { address: NetworkAddress },
    HarvestDone { address: NetworkAddress },
    Confirmed { address: NetworkAddress },
    SessionAccepted { address: NetworkAddress },
}
```

| Variant | When the dialer emits it | List (`apply`) | Failed-address memory | Score |
| --- | --- | --- | --- | --- |
| `DialFailed` | The channel never reached a well-formed kept response, or `network_id` is not ours (`net_node.inl:1370`). The cause is the one the connector closed with | An outstanding gray draw is dropped. A white address stays white | Written when `implicates_address` is set for that cause and reply. A `network_id` mismatch is `LevinHandshakeRejected` and does write it | No subscription. The mismatch does not call `add_host_fail` |
| `PeerlistRefused` | `handle_remote_peerlist` refuses (`net_node.inl:1377`). Same close as `LevinHandshakeRejected` | Same as `DialFailed` | Same as `DialFailed` with `LevinHandshakeRejected` | The score owner subscribes. A peerlist this node refuses is the event the score records |
| `PayloadRefused` | Levin was well-formed and the strand refused the sync payload | No promotion, no demotion, no gray drop. An outstanding draw stays gray | Not written. The peer answered | None |
| `HarvestDone` | Harvest handshake completed. The session is closed. No `adopt` | Promote only when the address is one of the six Foundation hosts in `get_ip_seed_nodes` (`net_node.inl:771`, the array at `:781`). Every other harvest leaves white unchanged | Cleared for that address | None |
| `Confirmed` | Aim `Confirm`. The strand accepted the sync payload. The owner closed in that turn. The relay was not flipped | An outstanding gray draw moves to white and `last_observed` is set. No session remains. Anything else writes nothing | Cleared for that address | None |
| `SessionAccepted` | Aim `Keep`. The strand accepted the sync payload and the session stays | An outstanding gray draw moves to white and `last_observed` is set. An address that is already white, on a session this node opened, moves the clock. Anything else writes nothing | Cleared for that address | None |

*Records-was: slice 1's `handshake_confirmed` and `draw_failed` were
three endings sharing one name. Neither spelling is in Rust. They are
not the contract.*

A valid Levin response is not `SessionAccepted`. The strand can refuse
the payload after the response was well-formed.

Wargame: a peer completes the handshake and sends a payload the sync
driver refuses. `SessionAccepted` on the Levin response would put that
peer on white and hand the next draw an address this node drops on
sight. `PayloadRefused` keeps the peer on gray. The report does not
block the dialer. A session that dies before the report is not white.
A peer whose payload we refuse is never a stem edge.

---

## The handshake request

`do_handshake_with_peer` (`net_node.inl:1329`) fills
`COMMAND_HANDSHAKE` before the invoke. The sync payload is one field.
The request also carries the address we announce, `network_id`, the
support flags we send, and a self-connection nonce.

**Sync payload.** `get_payload_sync_data`
(`cryptonote_protocol_handler.inl:469`) reads the core on the caller:
height, top id, the ideal hard-fork version at that height, and
cumulative difficulty, low 64 and top 64, then adds one to the
height. The handshake request carries that `CORE_SYNC_DATA`.

The dialer does not call the core. The core publishes that snapshot
when the tip changes. The handshake reads the latest snapshot. A tip
that moves while the handshake is in flight stays the snapshot the
request already took. The fields are public chain data.

**Handshake address — RULED 2026-10-09 (Rick).** `COMMAND_HANDSHAKE`
carries no address field on any connector. A node's own dialable
address is one uniform member of that connector's disclosure
population (slice 1 brief §5a), with no special position; our clearnet
entry is included when it is known, as today. A node discloses nothing
on a connector until its eligible white list reaches
`white_diversity_floor`. The timed-sync self-insertion
(`net_node.inl:2717` to `:2735`, `outgoing_to_same_zone` inserting
`zone.m_our_address` into the peerlist it sends) is deleted at the
cutover; it is in the deletion table below. The ProxyMark rerun
(`DAEMON_RELAY_PRIVACY.md` §99, PM-1) measures step 1 — identity in the
cached sample — against this design, with per-boot and persistent
onions, shortly after restart and in steady state; its result decides
whether the onion stays per-boot (PWD-E7). This ruling replaces the
section that follows, kept as records-was of what `get_local_node_data`
does on `dev`.

**The address we announce — SUPERSEDED 2026-10-09 (records-was).**
`get_local_node_data`
(`net_node.inl:2477`) writes it. The address is this node's own
address on the connector being dialed. The declaration decides the
shape. The rule does not name a connector.

- The declaration says our address is not hidden, the node is
  reachable on that connector, and inbound is open
  (`max_in_connection_count > 0`). The request carries a port only.
  The host is zero. For a connector that does not hide our address,
  the port is `m_external_port` when set, otherwise
  `m_listening_port` (`get_local_node_data`, `net_node.inl:2504`).
  The receiver pairs the port with the host it saw on its own socket.
- The declaration says our address is hidden, the node is reachable
  there, and inbound is open. The request carries this node's address
  on that connector. When that address is not a reachable address, the
  request carries that connector's unknown placeholder.
- Inbound is 0, or the node is not reachable on that connector. A
  hidden connector carries its unknown placeholder. A connector that
  does not hide our address carries a zero address. Nothing dialable
  is announced.

Wargame (records-was with the section above): a handshake whose
connector hides our address carries this node's address on that
connector, or the unknown placeholder. It does not carry the clearnet
port. A clearnet port on that handshake links the hidden identity to
the clearnet one. Under the ruling the handshake carries no address at
all, so the join it guarded against has no field to ride.

**`network_id` and the flags we send.** The same `node_data` carries
`m_network_id` and that connector's `support_flags`, the two
assignments after the address in `get_local_node_data`. Those are
what we send. The response's support flags are the section below.

**`HandshakeNonceSet`.** One set per connector, owned by the dialer.
The nonce is 32 random bytes, minted for this attempt
(`mint_recorded_handshake_nonce`, called at `net_node.inl:1347`,
defined at `:1497`). It is inserted before the request bytes are
written, and erased on every end path. The scope guard at `:1348` is
that lifetime in C++. The set moves to Rust with the dialer.

Until slice 4, the C++ inbound check (`detect_self_handshake`, called
at `net_node.inl:2789`, defined at `:1536`) reads it through
`shekyl_dial_take_handshake_nonce`. The query takes the inbound
session's connector and the nonce, returns whether that connector's
set held it, and erases it. The connector is the inbound session's,
not one the request names. The set contains the nonce before the
request bytes are written, because our own listener reads the request
before the dial's invoke can finish. Detection is that order, not a
timer. `detect_self_handshake` stays until slice 4. It is in flight.
The C++ mint and erase are deleted with the outbound function, because
the Rust set is the one the FFI read consults.

Test: a dial to our own listener is detected, and the session is not
kept as a peer.

---

## The candidate filter

Before a dial, `make_new_connection_from_peerlist`
(`net_node.inl:1789`) rejects a candidate. Rust takes every kept row.
A row that is not in this table, and not in the pending paragraph
under it, is dropped with the C++ dial path.

| Filter | Disposition | Reason |
| --- | --- | --- |
| Our own address (`zone.m_our_address`, and `is_self_dial` on a seed) | Kept | A dial to ourselves is not a peer |
| One outbound per host (`has_outbound_connection_to_host`) | Kept | One outbound session per host on that connector |
| Peer already in use (`is_peer_used`) | Kept | A second session to an address we already have |
| Banned (`is_remote_host_allowed`, `net_node.inl:243`) | Kept | Calls `shekyl_ban_remaining_ns` (`seam_ffi.rs:706`). A return of 2 is banned. The check is already Rust |
| Recently failed (`is_addr_recently_failed`) | Kept | This slice's failed-address memory |
| One candidate per host while the list is built | Kept | A host that advertises many ports is not drawn more often. The port kept for a host is chosen uniformly, not first in list order. The address that is dialed is still host and port |
| White-list index weighted by `last_seen`, and the cap of the 20 most recent (`net_node.inl:1948`, weighted pick `:1970-1974`) | Dropped | The uniform draw already ruled. A last-seen weight is the eclipse lever in the wargame below |

**Pending Rick, not a kept row.** PWD-B9 owns outbound diversity. Two
keys are proposed under it and are not in force: (i) the
occupied-subnet set is outbound sessions on that connector only, so an
inbound session does not occupy a subnet; (ii) IPv6 that is not
v4-mapped is grouped by `/32`, and a v4-mapped IPv6 address stays
`/24`. The C++ second pass, which lifts the limit when the first pass
yields no candidate, is what the binary does today
(`net_node.inl:1842-1933` is the subnet pass, public zone only). It
leaves with the C++ dial path. It is not a Rust rule until those keys
are ruled. The index does not say this slice has ruled them.

---

## Seeds and harvest dials

`connect_to_seed` (`net_node.inl:2032`) and `just_take_peerlist` are
one disposition: a harvest. The handshake runs. The response peerlist
is admitted to gray through slice 1. The session is closed. There is
no `adopt` and no `SessionAccepted`. White changes only through
`HarvestDone` for the Foundation fleet, slice 1 §3.

The C++ gray probe is not that harvest. `gray_peerlist_housekeeping`
(`net_node.inl:3336`, declared `net_node.h:713`) dials one random gray
peer through `check_connection_and_handshake_with_peer` (`:1715`),
which calls `do_handshake_with_peer` with `just_take_peerlist`
(`:1735`), closes (`:1752`), and on success the caller writes white
(`:3363`) without keeping the session. It does not consult the
outbound cap. An exclusive list skips it. That probe is the ancestor
of arm 5, and it is deleted with the dial path: the function, the
60-second interval (`m_gray_peerlist_housekeeping_interval`,
`net_node.h:756`, the `idle_worker` call at `net_node.inl:2307`), and
the comment at `:1091`. Leaving them would dial gray on a second
clock, including while white is already above the refill line. Arm 5
confirms only while white is under that line, and only after the
strand accepts the payload. The gray dial that keeps a session is
`make_new_connection_from_peerlist` (`:1789`) through
`try_to_connect_and_handshake_with_new_peer` (`:2019`,
`just_take_peerlist` false). That is arm 4.

A harvest that completes is `HarvestDone`. A harvest that fails is
`DialFailed` or `PeerlistRefused`, with the connector's cause. A
confirm the strand accepts is `Confirmed`. It is not `HarvestDone`.

---

## Support flags

The handshake response carries `support_flags`. That value, including
zero, is what the handshake result hands the strand.
`try_get_support_flags` (`net_node.inl:1435`, defined at `:2677`) asks
again when the field is zero. The field is optional on the wire
(`KV_SERIALIZE_OPT`, default 0), and the second invoke is how an
omitted field was recovered. Shekyl sends the field. Zero is the
peer's answer. The dialer does not own a second command.

The inbound call (`net_node.inl:2837`, inside `handle_handshake`) is
the same ask. Slice 4 deletes it for this reason. This slice deletes
the outbound call. The function and the inbound call stay. They are
in flight.

---

## Failed-address memory

The key is the host and the port, the address that was dialed. A
refused port is not evidence about another port on that host. The C++
keys `addr.host_str()` only (`net_node.h:282`). That host key is
records-was.

The memory is not kept across restarts. It is the process map
`m_conn_fails_cache` (`net_node.h:788`). `store_config` writes the
peerlist and does not write this map. A restart dials again.

Windows come from `failed_addr_cache::window` (`net_node.h:263`).
Clearnet is the hour. Tor starts at the short window and doubles,
capped at the hour.

`implicates_address` decides the write, on `DialFailed` and on
`PeerlistRefused`. Only a refused dial, a rejected handshake, and an
onion reply in `0x04 0x05 0xF0 0xF1 0xF2` write the memory. A
handshake timeout, a peer close, a local failure, and a clearnet
proxy reply do not. `PayloadRefused` does not. `HarvestDone`,
`Confirmed`, and `SessionAccepted` clear the address.

Slice 1's gray admission refuses an address the memory holds, and a
banned one (`handle_remote_peerlist`, `net_node.inl:2472`). Until
this slice lands, slice 1 takes that predicate from the C++ cache.
This slice replaces where the predicate comes from.

---

## What the C++ still calls into the peerlist, until slice 4

After the cutover these are the only C++ calls into the Rust peerlist,
and nothing else. Each is a call into Rust. None returns list state for
the C++ to hold.

- `admit_gray`, called on a received peerlist (`handle_remote_peerlist`,
  `net_node.inl:2448`), on an inbound advertisement (`:2831`, today
  `append_with_peer_gray`), and for `--add-peer` (`:1098`, today
  `append_operator_candidate`).
- `disclose`, called for the inbound handshake response and the
  timed-sync response.
- `shekyl_dial_take_handshake_nonce`, the inbound `detect_self_handshake`
  reading the dialer's `HandshakeNonceSet` (the deletion table).

A fourth call is a finding, not a convenience. Slice 4 moves the
inbound handshake and timed sync, and these three go with it.

## Measured after the cutover, on the Rust path

Dial pacing, the handshake gap per connector (D9), and the in-flight
bound are measured after the cutover, on the Rust dialer, into the
register (`DAEMON_RELAY_PRIVACY.md` §97, Ruling B). Then the white
floor, the refill line and the per-source gray share are re-derived
from those readings. No derivation and no measurement gates the
cutover PR; a number taken with the C++ dial path in front would be
thrown away.

## What else the cutover moves to Rust

Values Rust reads through C++ move to Rust in the cutover, so
retuning them no longer means editing C++. Each move removes the C++
lines; it does not add a second copy.

- `transport_spans` (`net_node.inl:3504`, declared `net_node.h:776`;
  the D9 deadlines, the send-queue cap, the shutdown wait, the thread
  budget) moves into `shekyl-transport-layer`. The three C++ call
  sites (`:967`, `:1127`, `:1158`) go with it.
- The hidden outbound cap assignment (`net_node.inl:984` to `:985`,
  `shekyl_relay_zone_min_provisioned_out_peers` into
  `max_out_connection_count`) and `set_max_out_peers`'s floor check
  (`:2957`; the refusal of a positive cap below
  `shekyl_relay_zone_min_provisioned_out_peers`, the F-8b floor) move
  to the dialer, which owns outbound targets. A cap of 0 stays legal
  there.

| What | Where, at `98fbd20acb` | `rg` when it has landed |
| --- | --- | --- |
| `transport_spans` | definition `net_node.inl:3504`, declaration `net_node.h:776`, calls `:967`, `:1127`, `:1158` | `rg -n -e transport_spans src/p2p` returns nothing. Before the move that command hits all five sites |
| The hidden cap assignment and the floor check | `net_node.inl:984` to `:985`; `set_max_out_peers` `:2957` | `rg -n -e shekyl_relay_zone_min_provisioned_out_peers src/p2p` returns nothing. Before the move it hits the assignment and the floor check |

---

## What is deleted

Each name is where it is on `dev` at `f317d979c4`. A deletion check
uses `rg -n -e`. A `\|` inside the pattern is a literal pipe under
ripgrep's default, so that form matches nothing and the gate is green
while the subject is still there (rule 47).

Before the deletion, the same command must hit the sites named in the
row. A before-run that matches nothing means the pattern is wrong, and
the implementation PR stops.

**The freeze (Ruling A, 2026-10-08).** Until the cutover deletes them,
these functions do not change. The list is
`scripts/ci/dial_path_freeze.tsv`, one row per function below plus the
two dial calls inside `idle_worker`, and `scripts/ci/check_dial_path_freeze.py`
compares each body with the base revision on every PR to `dev`: a
change fails, a deletion passes, a row it cannot find at base fails.
Deleted means gone: the row's witness identifier (its bare name, or
`open_outcome` for `zone_server::open`, whose bare name is an ordinary
word) matches nothing under `src/` at head outside comments and
string literals, and the body does not survive under another
signature. A definition moved out of `src/p2p` is still the dial path. **`net_node.inl`, `net_node.h` and
`src/cryptonote_protocol/levin_notify.cpp` take deletions only (Rick,
2026-10-09):** a change may add no code lines to them. A comment-only
addition is free; an edited line, or logic swapped for a call into
Rust, is an added code line, so each PR that moves something to Rust
carries one dated `UNFREEZE` line naming the file. *Records-was,
2026-10-08: the two p2p files were shrink-only, which an in-place edit
passed.* This table cites that file so the two cannot drift. The one
exception is a line in this brief, new in the PR, of exactly this
form, naming the row's full anchor or the file path:
`**UNFREEZE (Rick, YYYY-MM-DD):** <anchor or file path> — <reason>`.
Nothing looser is read. **Scope (Rick, 2026-10-09):** a line naming a
function covers that function's row and nothing else. Editing a frozen
function inside one of these files takes two lines, one naming the
anchor and one naming the file, because the two rules guard two
different things. At the cutover the same list is the deletion gate:
every body and calls row's function is absent, and the cutover PR
removes those rows. A shrink row is retired only when its file is
deleted, and deleted means gone: `git diff --name-status -M` over the
tree reports no rename or copy from the path, and no file under
`src/` at head holds half or more of the file's distinct code lines.
`net_node.inl` outlives the dial path, since slice 4 and RD still edit
it, and `levin_notify.cpp` is RD's. *Records-was: the cutover PR
empties the file.*

`do_handshake_with_peer` is the outbound invoke. Its callers are the
two dial sites (`:1677`, `:1735`). Inbound is `handle_handshake`
(`:2752`), which does not call it. Once those calls are gone the
function has no caller, so the definition and the declaration go with
them. That is dead, not in flight. `handle_handshake`,
`detect_self_handshake`, `try_get_support_flags`, and `add_host_fail`
keep the callers named below.

| What | Where, at `f317d979c4` | `rg` when it has landed |
| --- | --- | --- |
| `connections_maker` | `net_node.inl:2111`, declared `net_node.h:655` | `rg -n -e connections_maker src/p2p` returns nothing |
| `make_new_connection_from_peerlist` and `connect_to_seed` | `:1789` and `:2032` (the seed walk stops at `:2073`) | `rg -n -e make_new_connection_from_peerlist -e connect_to_seed src/p2p` returns nothing |
| `make_expected_connections_count` | `net_node.inl:2185` | `rg -n -e make_expected_connections_count src/p2p` returns nothing |
| `try_to_connect_and_handshake_with_new_peer` | `net_node.inl:1637` | `rg -n -e try_to_connect_and_handshake_with_new_peer src/p2p` returns nothing |
| `do_handshake_with_peer` | definition `:1329`, declaration `net_node.h:657`, calls `:1677` and `:1735` | `rg -n -e do_handshake_with_peer src/p2p` returns nothing. Before deletion that command hits all four sites |
| `check_connection_and_handshake_with_peer` | `net_node.inl:1715` | `rg -n -e check_connection_and_handshake_with_peer src/p2p` returns nothing |
| `m_conn_fails_cache`, `record_addr_failed`, `record_addr_success` | cache `net_node.h:788`; `record_addr_failed` `:1763`; `record_addr_success` `:1776` | `rg -n -e m_conn_fails_cache -e record_addr_failed -e record_addr_success src/p2p` returns nothing |
| The dial path in `idle_worker` | `idle_worker` is `:2303`. The fill call is `:2306`. The gray-probe call is `:2307` | `rg -n -e connections_maker -e gray_peerlist_housekeeping src/p2p` returns nothing. `idle_worker` itself stays until its other gates move |
| `gray_peerlist_housekeeping` and its interval | function `:3336`, declaration `net_node.h:713`, interval `:756`. The comment at `net_node.inl:1091` names the function and goes with it | `rg -n -e gray_peerlist_housekeeping -e m_gray_peerlist_housekeeping_interval src/p2p` returns nothing. Before deletion that command hits the declaration, the interval, the `idle_worker` call, the definition, and that comment |
| `zone_server::open` and its `open_outcome` result type | `zone_server.h:382`; `struct open_outcome` at `:376` | `rg -n -e 'open_outcome open\(' src/p2p/zone_server.h` returns nothing, and `rg -n -w open_outcome src/p2p` returns nothing: the struct is the freeze row's witness and goes with the function |
| `shekyl_seam_open`'s blocking wait | `rust/shekyl-ffi/src/seam_ffi.rs:303` | The function remains and returns the channel without waiting for the handler to arm. `rg -n -e shekyl_seam_open rust/shekyl-ffi/src/seam_ffi.rs` still hits the definition. Zero hits fails |
| `shekyl_seam_session_cause` | `cause_ffi.rs:55`, declared `shekyl_ffi.h:4430`, C++ read `net_node.h:229` | `rg -n -e shekyl_seam_session_cause rust src` returns nothing |
| The outbound call of `try_get_support_flags` | call `:1435`, definition `:2677`, inbound call `:2837` inside `handle_handshake`, declaration `net_node.h:673` | `rg -n -e try_get_support_flags src/p2p` still matches the declaration, the definition, and the call in `handle_handshake`, and nothing else. Zero matches fails. A match inside `do_handshake_with_peer` fails, because that function is gone |
| The timed-sync self-insertion (handshake-address ruling, 2026-10-09) | `net_node.inl:2717` to `:2735`: `outgoing_to_same_zone`, the `max_peerlist_size` subtraction, and the `local_peerlist_new.insert` of `zone.m_our_address` | `rg -n -e outgoing_to_same_zone src/p2p` returns nothing. Before deletion it hits `:2717`, `:2718` and `:2730` |
| The C++ in-flight nonce mint and erase | call `:1347`, guard `:1348`, `mint_recorded_handshake_nonce` `:1497`, `erase_outbound_handshake_nonce` `:1516` | `rg -n -e mint_recorded_handshake_nonce -e erase_outbound_handshake_nonce src/p2p` returns nothing. `rg -n -e detect_self_handshake src/p2p` still hits the declaration and the call in `handle_handshake` (`:2789`). Zero hits on `detect_self_handshake` fails. The dialer's `HandshakeNonceSet` is what `shekyl_dial_take_handshake_nonce` reads |

---

## Wargame

**Dial timing as a fingerprint.** An observer who sees when this node
dials can tell a fresh process from a steady one, and can tell Tor
from clearnet if the spacing is the connector's RTT. The answer is
the jittered spacing already ruled on 2026-09-25, drawn per dial, not
a fixed delay and not the 60-second timer. The spacing is the same
shape for every connector. The connector changes which list is drawn,
not the clock.

**Candidate-draw bias as an eclipse lever.** A draw that prefers
recent, front-of-list, or attacker-supplied addresses lets an eclipse
fill the outbound set. The answer is slice 1's uniform draw within a
connector. This slice does not sort by `last_seen` and does not give
`--add-peer` a better chance than any other gray address. Exclusive
and priority nodes are operator-named and are not part of that draw.
Whether an inbound session occupies a subnet is the pending PWD-B9
paragraph above. It is not a kept filter.

**The failed-address memory as something an attacker can drive.** A
peer, or a directory, that can force a forgetting cause can suppress
an address for the window. The answer is `implicates_address` on
`DialFailed` and `PeerlistRefused`: only a refused dial, a rejected
handshake, and an onion reply in `0x04 0x05 0xF0 0xF1 0xF2` write the
memory. A handshake timeout, a peer close, a local failure, and a
clearnet proxy reply do not. The window is the one
`failed_addr_cache::window` already derived. An attacker who can force
reply 4 still buys only the short Tor window. That residual is
unchanged. The key is host and port, so a refused port does not
suppress another port on the same host. The memory dies with the
process.

**Dial concurrency.** Many simultaneous onion dials are a load the
managed Tor process was not sized for, and a way to stall every other
dial behind one SOCKS exchange. Many simultaneous clearnet dials pin
the dialer's tasks and the peers' handshake slots the same way. Each
connector has its own in-flight bound, owned by this slice. The
interim is one dial per connector (the fill section). It is measured
and raised on the Rust path after the cutover, not before it: a bound
measured with the C++ dial path in front is a `CppPath` reading
(`DAEMON_RELAY_PRIVACY.md` §97) and nothing is derived from it.
*Records-was: both numbers are measured before the implementation PR
names them.* The fill's one-dial-per-wake is the schedule, not that
bound.

**Full-pool capture.** The chance an attacker holds every hidden
session is `p_h^h`. `p_h` is the onion-candidate spy share, as §95
defines it. Holding the pool means every hidden stem slot, every
epoch, is the attacker's: they see the first hop of every transaction
this node originates, and rotation protects nothing. Hidden
addressing keeps the IP off that hop. It does not keep the
transactions from linking to one origin. Until the sweep is ruled,
the pool the dialer keeps is `hidden_out` (12), which is also what
`dev` writes at `net_node.inl:984`. The cost at that interim is 12
onion circuits on the managed Tor, where the old target opened 4. The
in-flight dial bound limits how fast they open. Total outbound is
`clearnet_out` plus `hidden_out`, and relayed stems are drawn over
all of them. Both the hidden outbound sessions and that total are lower limits.
*Records-was: the capture was written `p^k`.*

**What a peer can make us dial.** A peerlist, an advertisement, and a
timed-sync payload are gray entries. They become dials only through
the uniform draw, at the paced rate. A peer cannot name an address
and have this node dial it next. Exclusive and priority nodes are not
accepted from a peer.

---

## Tests

Differential against the current C++ wherever the behaviour is kept:
the windows, which causes forget an address, exclusive and priority
nodes dialed before the draw, white promotion only on
`SessionAccepted` or `Confirmed` of an outstanding gray draw or
`HarvestDone` of a Foundation host, and each kept row of the candidate
filter. The
subnet pass is not a Rust assertion until the pending keys are ruled.
A hidden-connector handshake does not carry the clearnet port. A dial
to our own listener is detected.

Property tests on draw uniformity, within one connector, including a
full gray list.

A starvation test: no p2p io worker is blocked while a dial is in
flight. The pair-run repro is the before and the after. Before: a
dial on the 2-worker io pool can leave `get_connections` with claims
unknown. After: the same dial leaves every io worker free, and the
claim post lands.

The handshake-result test above. `PayloadRefused` leaves the address
off white and still on gray when it was an outstanding draw. A
harvest of anyone outside the Foundation fleet leaves white
unchanged. `HarvestDone` for one of the six hosts writes white.
`Confirmed` of an outstanding gray draw writes white, leaves no
session, and never appears in the relay registry. That dial, started
while `Keep` rows are already at the target, leaves the `Keep` count
unchanged: no `Keep` peer is closed to make room, and the adopt is
not refused for being at the target. `SessionAccepted` of that draw
writes white and the session stays. When every white address is
already an outbound session and white is under the refill line, the
next wake is `draw_gray`, not another dial of a live white peer.

The deletion section is the gate. Each before-command hits the sites
it names. Each after-command does what its row says, including the
rows whose subject must still be present.

## Known defect this slice carries

`idle_worker` dials on the 2-worker io pool. While a dial is in
flight, one thread runs every strand, and the operator view can
report claims unknown. Recorded on #991. The reopen is this slice
landing the dial off that pool. Do not fix it in C++.

The post-handshake cause race is the same carrier. The dial thread
reads `shekyl_seam_session_cause` after the strand has queued the
reap, so a cause that does not implicate the address can be read as
`LocalClose`. The closed post logs the cause and does not hand it to
the strand. No counted cause takes that path. The closeout pair's
shut-write row was `PeerClosed` once and `LocalClose` otherwise, not
recorded either way. This slice's handshake receives the cause
directly. Do not patch the C++. The record is
`LV3_CONNECTION_OBJECT.md`. Reopen if the Rust handshake still
classifies a shut write by reading a row the strand can reap first.
