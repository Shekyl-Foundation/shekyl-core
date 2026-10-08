# P2P-3 slice 3 — discovery and the dialer

**Status: OPEN.** Design before code. Rule 26 is cited. No
implementation starts from this file until a review of it has closed.
Lines below were read on `dev` at `d93074d1c4` (2026-10-07), which
contains #991. `record_addr_failed` takes the address, the cause, and
the reply (`net_node.h:675`). `shekyl_seam_session_cause` is
`rust/shekyl-ffi/src/cause_ffi.rs:55`. A later tip, `7f7109dc7e`,
inserts Tor boot warnings above these functions and does not change
them; the line numbers below are `d93074d1c4`. This slice mints no
identifier family. It is the §4.2 row rescoped the same day.

**Ruling 2026-10-07 (Rick).** Order: #991 → slice 1 → this slice → RD.
Dialing moves to Rust. No further fixes to the C++ dial path. Slice 4
keeps the inbound handshake state machine and PWD-B1/B2. This slice
owns the outbound dial, the outbound handshake invoke, and the
outcome. Slice 4 owns the phases after a session exists.

---

## What moves to Rust

Candidate draw comes from the slice-1 lists, partitioned by connector,
uniform as [`P2P_3_SLICE_1_PEERLIST_BRIEF.md`](P2P_3_SLICE_1_PEERLIST_BRIEF.md)
already specifies. Refill pacing is the 2026-09-25 ruling: when white
is below its refill line, gray is dialed at a bounded derived rate
with jittered spacing. The 60-second housekeeping timer is not the
pace.

Exclusive nodes and priority nodes are dialed by this slice. Today
they are `connect_to_peerlist` at `net_node.inl:2864`, called from
`connections_maker` (`:2063`) at `:2068` and `:2084`.

The dial is `Hub::connect`. The outbound Levin handshake is a
timing-engine owner. It is not a thread waiting on an event, and it
is not a job of the C++ timing-engine bridge.

The outcome goes through `implicates_address` into the failed-address
memory below. That memory carries the Tor and clearnet windows from
`failed_addr_cache::window` (`net_node.h:263`). Clearnet is the hour.
Tor starts at the short window and doubles, capped at the hour.

White promotion of a gray draw is a completed dial, defined below.
The Foundation fleet stays slice 1 §3.

## Outbound handshake frames

On an outbound session, frames before the handshake ends are read by
this slice's handshake owner, `shekyl-levin`'s reader. They are not
delivered to the strand.

On success, that owner queues one established delivery to the strand,
ahead of the first frame after the handshake. The delivery carries
the response's support flags, the peer's sync payload, and the board's
established flag. The strand is the first reader of those three. The
owner does not call `process_payload_sync_data`.

On failure, the cause is the one the connector closed with. The
handshake owner has it. It does not read it back from the hub.

The gap deadline is the only clock on an outbound handshake. The 5 s
Levin invoke timer (`P2P_DEFAULT_HANDSHAKE_INVOKE_TIMEOUT`,
`cryptonote_config.h:199`) has no outbound-handshake role and is not
armed for one.

Test: no frame after the handshake reaches the strand before the
established delivery.

## The handshake request

`do_handshake_with_peer` (`net_node.inl:1281`) fills
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

**The address we announce.** `get_local_node_data`
(`net_node.inl:2429`) writes it. The address is this node's own
address on the connector being dialed. The declaration decides the
shape. The rule does not name a connector.

- The declaration says our address is not hidden, the node is
  reachable on that connector, and inbound is open
  (`max_in_connection_count > 0`). The request carries a port only.
  The host is zero. The receiver pairs the port with the host it saw
  on its own socket.
- The declaration says our address is hidden, the node is reachable
  there, and inbound is open. The request carries this node's address
  on that connector. When that address is not a reachable address, the
  request carries that connector's unknown placeholder.
- Inbound is 0, or the node is not reachable on that connector. A
  hidden connector carries its unknown placeholder. A connector that
  does not hide our address carries a zero address. Nothing dialable
  is announced.

Wargame: a handshake whose connector hides our address carries this
node's address on that connector, or the unknown placeholder. It does
not carry the clearnet port. A clearnet port on that handshake links
the hidden identity to the clearnet one.

**`network_id` and the flags we send.** The same `node_data` carries
`m_network_id` and that connector's `support_flags`, the two
assignments after the address in `get_local_node_data`. Those are
what we send. The response's support flags are the section below.

**The self-connection nonce.** It is 32 random bytes, minted for this
attempt (`mint_recorded_handshake_nonce`, `net_node.inl:1299`). It is
recorded in that connector's in-flight set before the request is
written. It is erased when the attempt ends on any path; the scope
guard at `:1300` is the attempt's lifetime. The set moves to Rust.
The dialer owns it. Until slice 4, the C++ inbound check
(`detect_self_handshake`, called at `net_node.inl:2741`, defined at
`:1488`) reads it through `shekyl_dial_take_handshake_nonce`. The
query takes the inbound session's connector and the nonce, returns
whether that connector's set held it, and erases it. The connector is
the inbound session's, not one the request names. The set contains
the nonce before the request bytes are written, because our own
listener reads the request before the dial's invoke can finish.
Detection is that order, not a timer.

Test: a dial to our own listener is detected, and the session is not
kept as a peer.

## The candidate filter

Before a dial, `make_new_connection_from_peerlist`
(`net_node.inl:1741`) rejects a candidate. Rust takes every row. A
row that is not in this table is dropped with the C++ dial path.

| Filter | Disposition | Reason |
| --- | --- | --- |
| Our own address (`zone.m_our_address`, and `is_self_dial` on a seed) | Kept | A dial to ourselves is not a peer |
| One outbound per host (`has_outbound_connection_to_host`) | Kept | One outbound session per host on that connector |
| Peer already in use (`is_peer_used`) | Kept | A second session to an address we already have |
| Banned (`is_remote_host_allowed`, `net_node.inl:243`) | Kept | Calls `shekyl_ban_remaining_ns` (`seam_ffi.rs:704`). A return of 2 is banned. The check is already Rust |
| Recently failed (`is_addr_recently_failed`) | Kept | This slice's failed-address memory |
| `/24` diversity, then a second pass with the limit lifted | Kept. The key changes | Eclipse defence. Today the pass runs when the zone object is the clearnet zone. It runs when the connector's addressing cell is IP. A connector whose addressing is not IP has no subnet pass. A v4-mapped IPv6 address uses the v4 `/24`. Other IPv6 is not limited. The second pass runs only when the first pass produced no candidate |
| One candidate per host while the list is built | Kept | A host that advertises many ports is not drawn more often. The address that is dialed is still host and port |
| White-list index weighted by `last_seen`, and the cap of the 20 most recent | Dropped | The uniform draw already ruled. A last-seen weight is the eclipse lever in the wargame below |

## What the response does besides the sync payload

A `network_id` that is not `m_network_id` (`net_node.inl:1322`) is
`LevinHandshakeRejected`. `handshake_close_cause`
(`net_node.h:218`) returns that cause when the invoke returned and
`levin_rejected` is set. The mismatch sets that flag and does not
call `add_host_fail`.

A peerlist `handle_remote_peerlist` refuses (`net_node.inl:1332`)
closes the same way, `LevinHandshakeRejected`, and the C++ also calls
`add_host_fail` (`:451`). The dialer posts that address to the C++
score. The score stays C++. A peerlist this node refuses is the event
the score records. The dialer does not compute the score and does not
call it on the handshake task. Dropping the post would delete the
score on the outbound path without a ruling that the score is
rejected.

`set_peer_just_seen` is slice 1's write. The dialer posts that the
address answered. Slice 1 records the observation.

## Completed dial

A gray draw is promoted when the strand has accepted the sync payload
and reported that acceptance back to the dialer. The report is a
post. The dialer does not wait on it. Until the report, the session
may be up and the address is still gray.

A valid Levin response is not the promotion. The strand can refuse
the payload after the response was well-formed. That refusal closes
the session, leaves the address off white, and does not write the
failed-address memory: the peer answered. `implicates_address` is
unchanged.

Wargame: a peer completes the handshake and sends a payload the sync
driver refuses. Promoting on the Levin response would put that peer
on white and hand the next draw an address this node drops on sight.
Waiting for the strand's acceptance keeps the peer on gray. The
report does not block the dialer, so a slow strand cannot stall the
next dial. A session that dies before the report is not white.

The Foundation fleet is not this definition. Slice 1 §3 writes white
on a confirmed handshake with that fleet even though the dial is a
harvest and closes. A harvest does not post the established delivery,
so the sync driver never sees that session. The exception is the six
addresses, not a second door for anyone else.

## Seeds and harvest dials

`connect_to_seed` (`net_node.inl:1984`) and `just_take_peerlist` are
one disposition: a harvest. The handshake runs. The response peerlist
is admitted to gray through slice 1. The session is closed. There is
no established delivery and no white write, except slice 1 §3.

Two callers become that disposition.

- The seed pass. Slice 1 reports both lists empty
  (`has_no_known_peers`, `net_peerlist.h:147`), or a fill pass added
  no session while the connector is still under its outbound target.
  The dialer tries the compiled seed list (`get_seed_nodes`, filled
  at `net_node.inl:1994`) one address at a time and stops at the first
  confirmed handshake, the `break` after `connect_to_seed`'s dial at
  `:2024`. Clearnet, once, after every seed has failed, adds
  `get_ip_seed_nodes` (`:2036`) and tries those the same way. The
  session closes, and the fill that follows dials the fleet address
  slice 1 wrote to white. An exclusive
  list skips the pass. Offline skips it.
- The gray re-test. `gray_peerlist_housekeeping` (`net_node.inl:3288`)
  dials one random gray peer through
  `check_connection_and_handshake_with_peer` (`:1667`), which today
  calls `do_handshake_with_peer` with `just_take_peerlist` (`:1687`)
  and closes. Same disposition. An exclusive list skips it.

A harvest that completes clears that address in the failed-address
memory. A harvest that fails uses the connector's cause.

## Outbound targets

**APPROVED 2026-10-08 (Rick).** The simulation plan is
[`DAEMON_RELAY_PRIVACY.md`](DAEMON_RELAY_PRIVACY.md) §95. The
hidden-address pool and the total outbound degree are lower limits.
Each is at least `MIN_PROVISIONED_OUT_PEERS` (12,
`shekyl-relay-privacy/src/params.rs:195`). The total floor is the
fail-safe's measured range (`fluff_return_ms = 3250` at degree 12).
The hidden floor is the own-edge capture cost. An own transaction
rides a stem slot. The operating point above those floors, and any
ceiling, are not chosen by the approval. `(h, 0)`, Tor-only, is a
measured case in §95.3 and is not the target. Recommending Tor-only
waits on §96. The ceiling comes from resources.

Until a run is ruled, the target is 12. That is the floor,
kept as the interim, and it is a hard cap in the code the dialer
takes over. On the relay branch, `net_node.inl:939` assigns
`shekyl_relay_zone_min_provisioned_out_peers()` to
`max_out_connection_count`. This slice deletes that assignment and
keeps the target at 12. It does not open more than 12 hidden sessions
before the operating point is chosen.

*Records-was, earlier the same day: the address-hiding outbound
target is exactly `MIN_PROVISIONED_OUT_PEERS`.* *Records-was before
that: Tor's target is `HOP0_OUTBOUND_TARGET` (4, `params.rs:205`),
and at this brief's pin `d93074d1c4` `net_node.inl:939` still writes
it with `shekyl_hop0_outbound_target`.* The 4 read the paper's
4-regular anonymity graph (Dandelion++ §4.3, Algorithm 2: two
outbound edges plus about two inbound) as the size of the pool the
relays are drawn from. The paper draws those edges from the node's
P2P outbound edges (η = 8 in the simulations; the measured degree is
12). The relay lane deletes the constant.

The own-edge pool is the outbound sessions whose connector declares
`address_hidden_from_peer`. That is a property of the connector. The
dialer keeps that pool up to the interim target. `Relay::own_edge`
draws uniformly from it (`hidden_outbound_ids`). The dialer does not
choose the edge. An empty pool is the relay's `NoOwnEdge`. The draw
stays the relay lane's. The relay never sees a per-connector count.

Clearnet's cap is what `set_max_out_peers` writes
(`net_node.inl:2909`; the `--out-peers` call is `:621`). The default
is `shekyl_p2p_default_out_peers`, which is `P2P_DEFAULT_OUT_PEERS`
(12). A cap of 0 stays legal. A positive cap below the floor is
still refused by that setter. Clearnet is not folded into the hidden
target. Sharing one cap of 12 across both connectors would move the
degree the fail-safe was measured at.

A later connector, I2P included, is a declaration column, that
connector's measured transit added in `verify_cost`
(`shekyl-relay-privacy`), which the declaration reads, and the
connector crate. `shekyl-relay` is not edited. The column's cells are
address hiding, cover class, and that transit. An unassessed transit
is not a stem edge.

## Support flags

The handshake response carries `support_flags`. That value, including
zero, is what the established delivery hands the strand.
`try_get_support_flags` (`net_node.inl:1387`) asks again when the
field is zero. The field is optional on the wire
(`KV_SERIALIZE_OPT`, default 0), and the second invoke is how an
omitted field was recovered. Shekyl sends the field. Zero is the
peer's answer. The dialer does not own a second command.

The inbound call (`net_node.inl:2789`) is the same ask inside the
inbound handshake. Slice 4 deletes it for this reason. This slice
deletes the outbound call.

## Failed-address memory

The key is the host and the port, the address that was dialed. A
refused port is not evidence about another port on that host. The C++
keys `addr.host_str()` only (`net_node.h:282`). That host key is
records-was.

The memory is not kept across restarts. It is the process map
`m_conn_fails_cache`. `store_config` writes the peerlist and does not
write this map. A restart dials again.

## What is deleted

Each name is where it is on `dev` at `d93074d1c4`. When the deletion
has landed, the `rg` returns nothing.

| What | Where | `rg` when it is gone |
| --- | --- | --- |
| `connections_maker` | `net_node.inl:2063`, declared `net_node.h:655` | `rg -n 'connections_maker' src/p2p` |
| `make_new_connection_from_peerlist` and `connect_to_seed` | `net_node.inl:1741` and `connect_to_seed` at `:1984` (it stops at the first confirmed handshake, `:2024`) | `rg -n 'make_new_connection_from_\|connect_to_seed' src/p2p` |
| `make_expected_connections_count` | `net_node.inl:2137` | `rg -n 'make_expected_connections_count' src/p2p` |
| `try_to_connect_and_handshake_with_new_peer` | `net_node.inl:1589` | `rg -n 'try_to_connect_and_handshake_with_new_peer' src/p2p` |
| The outbound calls of `do_handshake_with_peer` | `:1629` and `:1687`. The function itself is `:1281`. Inbound handshake handling is slice 4 and is not this deletion | `rg -n 'do_handshake_with_peer' src/p2p/net_node.inl` finds no call from a dial |
| `m_conn_fails_cache`, `record_addr_failed`, `record_addr_success` | the cache at `net_node.h:788`; `record_addr_failed` at `net_node.inl:1715` (`addr`, `cause`, `reply`); `record_addr_success` writes at `:1730` | `rg -n 'm_conn_fails_cache\|record_addr_failed\|record_addr_success' src/p2p` |
| The dial path in `idle_worker` | `idle_worker` is `net_node.inl:2255`. The dial is the `connections_maker` call at `:2258` | `rg -n 'connections_maker' src/p2p/net_node.inl` |
| `zone_server::open` | `zone_server.h:382` | `rg -n 'open_outcome open\(' src/p2p/zone_server.h` |
| `shekyl_seam_open`'s blocking wait | `rust/shekyl-ffi/src/seam_ffi.rs:301` | the function returns without waiting for the handler to arm |
| `shekyl_seam_session_cause` | `rust/shekyl-ffi/src/cause_ffi.rs:55`. Declared at `shekyl_ffi.h:4448`. The C++ read is `net_node.h:229` | `rg -n shekyl_seam_session_cause rust src` |
| The outbound call of `try_get_support_flags` | `net_node.inl:1387`. The function is `:2629`. The inbound call at `:2789` remains until slice 4 | `rg -n try_get_support_flags src/p2p/net_node.inl` finds no call from `do_handshake_with_peer` |
| The in-flight handshake-nonce set on the C++ zone | recorded at `net_node.inl:1299`, erased by the guard at `:1300`, read by `detect_self_handshake` at `:2741` | the set lives in the dialer; the inbound check calls `shekyl_dial_take_handshake_nonce` |

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

**The failed-address memory as something an attacker can drive.** A
peer, or a directory, that can force a forgetting cause can suppress
an address for the window. The answer is `implicates_address`: only a
refused dial, a rejected handshake, and an onion reply in
`0x04 0x05 0xF0 0xF1 0xF2` write the memory. A handshake timeout, a
peer close, a local failure, and a clearnet proxy reply do not. The
window is the one `failed_addr_cache::window` already derived. An
attacker who can force reply 4 still buys only the short Tor window.
That residual is unchanged. The key is host and port, so a refused
port does not suppress another port on the same host. The memory
dies with the process.

**Dial concurrency.** Many simultaneous onion dials are a load the
managed Tor process was not sized for, and a way to stall every other
dial behind one SOCKS exchange. Many simultaneous clearnet dials pin
the dialer's tasks and the peers' handshake slots the same way. Each
connector has its own in-flight bound, owned by this slice. Both
numbers are measured before the implementation PR names them. This
brief picks neither.

**Full-pool capture.** Per epoch, the chance the own-edge is a spy is
about the spy fraction `p`, at any pool size. The chance an attacker
holds every session in the pool is `p^k`. At `p = 0.3` that is about
0.8% for `k = 4` and about `5×10⁻⁷` for `k = 12`. Holding the pool
means every own-edge, every epoch, is the attacker's: they see the
first hop of every transaction this node originates, and rotation
protects nothing. Hidden addressing keeps the IP off that hop. It
does not keep the transactions from linking to one origin.
Compositions above a pool of 12 are the §95 sweep, including total
16. Until that sweep is ruled, the pool the dialer keeps is 12,
which is also the hard cap the relay branch writes at
`net_node.inl:939`. The cost at that interim is 12 onion circuits
on the managed Tor, where the old target opened 4. The in-flight
dial bound limits how fast they open. Total outbound is clearnet
plus hidden, and stems are drawn over all of them. Both the hidden
pool and that total are lower limits.

**What a peer can make us dial.** A peerlist, an advertisement, and a
timed-sync payload are gray entries. They become dials only through
the uniform draw, at the paced rate. A peer cannot name an address
and have this node dial it next. Exclusive and priority nodes are not
accepted from a peer.

## Tests

Differential against the current C++ wherever the behaviour is kept:
the windows, which causes forget an address, exclusive and priority
nodes dialed before the draw, white promotion only after a completed
dial, and each kept row of the candidate filter. The subnet pass
runs for a connector whose addressing cell is IP and does not run
for one whose addressing is not. A hidden-connector handshake does
not carry the clearnet port. A dial to our own listener is detected.

Property tests on draw uniformity, within one connector, including a
full gray list.

A starvation test: no p2p io worker is blocked while a dial is in
flight. The pair-run repro is the before and the after. Before: a
dial on the 2-worker io pool can leave `get_connections` with claims
unknown. After: the same dial leaves every io worker free, and the
claim post lands.

The established-delivery test above. A strand that refuses the sync
payload leaves the address off white. A harvest leaves it off white
too, and a Foundation-fleet handshake writes white.

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
