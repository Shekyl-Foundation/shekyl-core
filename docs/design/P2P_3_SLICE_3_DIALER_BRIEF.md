# P2P-3 slice 3 — discovery and the dialer

**Status: OPEN.** Design before code. Rule 26 is cited. No
implementation starts from this file until a review of it has closed.
Lines below were read on `dev` at `9eb5f473cd` (2026-10-07). `#991`
changes `record_addr_failed`'s signature; re-read that function after
it merges. This slice mints no identifier family. It is the §4.2 row
rescoped the same day.

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
they are `connect_to_peerlist` at `net_node.inl:2840`, called from
`connections_maker` at `:2039` and `:2055`.

The dial is `Hub::connect`. The outbound Levin handshake is a
timing-engine owner. It is not a thread waiting on an event, and it
is not a job of the C++ timing-engine bridge.

The outcome goes through `implicates_address` into the failed-address
memory below. That memory carries the Tor and clearnet windows from
`failed_addr_cache::window` (`net_node.h:221`). Clearnet is the hour.
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

## The request's sync payload

`get_payload_sync_data` (`cryptonote_protocol_handler.inl:458`) reads
the core on the caller: height, top id, the ideal hard-fork version
at that height, and cumulative difficulty, low 64 and top 64, then
adds one to the height. The handshake request carries that
`CORE_SYNC_DATA`.

The dialer does not call the core. The core publishes that snapshot
when the tip changes. The handshake reads the latest snapshot. A tip
that moves while the handshake is in flight stays the snapshot the
request already took. The fields are public chain data.

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

`connect_to_seed` (`net_node.inl:1955`) and `just_take_peerlist` are
one disposition: a harvest. The handshake runs. The response peerlist
is admitted to gray through slice 1. The session is closed. There is
no established delivery and no white write, except slice 1 §3.

Two callers become that disposition.

- The seed pass. Slice 1 reports both lists empty
  (`has_no_known_peers`, `net_peerlist.h:147`), or a fill pass added
  no session while the connector is still under its outbound target.
  The dialer tries the compiled seed list (`get_seed_nodes`, filled
  at `net_node.inl:1965`) one address at a time and stops at the first
  confirmed handshake, the `break` after `connect_to_seed`'s dial at
  `:1995`. Clearnet, once, after every seed has failed, adds
  `get_ip_seed_nodes` (`:2007`) and tries those the same way. The
  session closes, and the fill that follows dials the fleet address
  slice 1 wrote to white. An exclusive
  list skips the pass. Offline skips it.
- The gray re-test. `gray_peerlist_housekeeping` (`net_node.inl:3258`)
  dials one random gray peer through
  `check_connection_and_handshake_with_peer` (`:1645`), which today
  calls `do_handshake_with_peer` with `just_take_peerlist` (`:1665`)
  and closes. Same disposition. An exclusive list skips it.

A harvest that completes clears that address in the failed-address
memory. A harvest that fails uses the connector's cause.

## Outbound targets

Each connector has one outbound target. The dialer fills toward it
and does not invent the number.

Clearnet's target is the zone cap `set_max_out_peers` writes
(`net_node.inl:2884`). The default is `shekyl_p2p_default_out_peers`,
which is `P2P_DEFAULT_OUT_PEERS` (12). The floor is
`MIN_PROVISIONED_OUT_PEERS` (12,
`shekyl-relay-privacy/src/params.rs:195`). `--out-peers` is that cap.
A cap of 0 stays legal.

Tor's target is `HOP0_OUTBOUND_TARGET` (4, `params.rs:205`), asserted
below `MIN_PROVISIONED_OUT_PEERS`. Today `net_node.inl:926` writes it
with `shekyl_hop0_outbound_target` onto the ephemeral Tor zone, and
the comment there says `--out-peers` does not set it. The source of
truth is the Rust constant.

The dialer feeds the relay's own-edge pool. `Relay::own_edge` draws
uniformly from the hidden-address outbound sessions this slice keeps
up (`hidden_outbound_ids`). The dialer does not choose the edge. An
empty pool is the relay's `NoOwnEdge`. This is a cross-lane
dependency on the relay: the Tor target is that pool's size, and the
relay lane owns the draw.

## Support flags

The handshake response carries `support_flags`. That value, including
zero, is what the established delivery hands the strand.
`try_get_support_flags` (`net_node.inl:1359`) asks again when the
field is zero. The field is optional on the wire
(`KV_SERIALIZE_OPT`, default 0), and the second invoke is how an
omitted field was recovered. Shekyl sends the field. Zero is the
peer's answer. The dialer does not own a second command.

The inbound call (`net_node.inl:2764`) is the same ask inside the
inbound handshake. Slice 4 deletes it for this reason. This slice
deletes the outbound call.

## Failed-address memory

The key is the host and the port, the address that was dialed. A
refused port is not evidence about another port on that host. The C++
keys `addr.host_str()` only (`net_node.h:240`). That host key is
records-was.

The memory is not kept across restarts. It is the process map
`m_conn_fails_cache`. `store_config` writes the peerlist and does not
write this map. A restart dials again.

## What is deleted

Each name is where it is on `dev` at `9eb5f473cd`. When the deletion
has landed, the `rg` returns nothing.

| What | Where | `rg` when it is gone |
| --- | --- | --- |
| `connections_maker` | `net_node.inl:2034`, declared `net_node.h:607` | `rg -n 'connections_maker' src/p2p` |
| `make_new_connection_from_peerlist` and `connect_to_seed` | `net_node.inl:1712` and `connect_to_seed` at `:1955` (it dials at `:1995`) | `rg -n 'make_new_connection_from_\|connect_to_seed' src/p2p` |
| `make_expected_connections_count` | `net_node.inl:2108` | `rg -n 'make_expected_connections_count' src/p2p` |
| `try_to_connect_and_handshake_with_new_peer` | `net_node.inl:1561` | `rg -n 'try_to_connect_and_handshake_with_new_peer' src/p2p` |
| The outbound calls of `do_handshake_with_peer` | `:1601` and `:1665`. The function itself is `:1267`. Inbound handshake handling is slice 4 and is not this deletion | `rg -n 'do_handshake_with_peer' src/p2p/net_node.inl` finds no call from a dial |
| `m_conn_fails_cache`, `record_addr_failed`, `record_addr_success` | the cache at `net_node.h:740`; the functions at `net_node.inl:1693` and `:1699` | `rg -n 'm_conn_fails_cache\|record_addr_failed\|record_addr_success' src/p2p` |
| The dial path in `idle_worker` | `idle_worker` is `net_node.inl:2226`. The dial is the `connections_maker` call at `:2229` | `rg -n 'connections_maker' src/p2p/net_node.inl` |
| `zone_server::open` | `zone_server.h:374` | `rg -n 'bool open\(' src/p2p/zone_server.h` |
| `shekyl_seam_open`'s blocking wait | `rust/shekyl-ffi/src/seam_ffi.rs:301` | the function returns without waiting for the handler to arm |
| `shekyl_seam_session_cause` | lands with #991 at `rust/shekyl-ffi/src/seam_ffi.rs:402`. Absent on this branch's pin `9eb5f473cd`. Re-read the line after #991 merges | `rg -n shekyl_seam_session_cause rust src` |
| The outbound call of `try_get_support_flags` | `net_node.inl:1359`. The function and the inbound call at `:2764` remain until slice 4 | `rg -n try_get_support_flags src/p2p/net_node.inl` finds no call from `do_handshake_with_peer` |

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

**What a peer can make us dial.** A peerlist, an advertisement, and a
timed-sync payload are gray entries. They become dials only through
the uniform draw, at the paced rate. A peer cannot name an address
and have this node dial it next. Exclusive and priority nodes are not
accepted from a peer.

## Tests

Differential against the current C++ wherever the behaviour is kept:
the windows, which causes forget an address, exclusive and priority
nodes dialed before the draw, and white promotion only after a
completed dial.

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
