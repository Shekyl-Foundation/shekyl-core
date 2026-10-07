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

The outcome goes through `implicates_address` into a Rust
failed-address memory. That memory carries the Tor and clearnet
windows from `failed_addr_cache::window` (`net_node.h:221`). Clearnet
is the hour. Tor starts at the short window and doubles, capped at
the hour.

White promotion happens only through the slice-1 type contract: a
completed dial. The peer's sync data is handed to the C++ sync driver
as a fire-and-forget post onto that connection's strand.

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
That residual is unchanged.

**Tor dial concurrency against the managed Tor.** Many simultaneous
onion dials are a load the managed Tor process was not sized for, and
a way to stall every other dial behind one SOCKS exchange. The answer
is a bound on in-flight Tor dials, owned by this slice, separate from
the clearnet bound. The number is not in this brief. It is measured
before the implementation PR names it. Until then the implementation
does not pick one.

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
