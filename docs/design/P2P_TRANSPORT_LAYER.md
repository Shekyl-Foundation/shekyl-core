# P2P transport layer — Rust connectors in place of epee's TCP server

**Status: OPEN — Round 3, 2026-09-25.** Round 1 was pinned to `dev`
`db2788d164660003948376ba369fa396c5f4c482`. Round 2 re-read that pin.
The 11 commits `dev` gained after it are S-POOL / chain-store and do
not touch epee, `src/p2p`, `src/net`, the transport crate, or the
protocol docs, so Round 1's anchors still hold. **The deliverable of
this round is a design, not code.** Implementation does not start until
the round closes. Target is 4–6 review rounds (rule 20). **Rule 26 is
cited explicitly** (`26-sub-pr-design-discipline.mdc`): this work
crosses an FFI boundary and replaces an inherited reference. Numeric
budgets are not written before a measurement (rule 26 B9). This
document mints no identifier family; decisions stay `PWD-` and the
slices stay P2P-3's.

**Vocabulary (ruled 2026-09-25).** A **network** is where a peer lives.
A **connector** reaches one network. A **capability** is one named
property against a named adversary, native or added by a **layer**.
**Encryption** is that kind of property: the bytes of the stream cannot
be read. It benefits confidentiality and does not create it. A peer's
address and port stay visible, and traffic can still be watched by
volume and by which other peers are connected. The word confidentiality
is not a capability. The **transport layer** hosts connectors and
layers. Rounds 1 and 2 called that subsystem "the connector". The
filename is `P2P_TRANSPORT_LAYER.md` so the old word does not survive
in the path.

**Ordering ruling (Rick, 2026-09-25).** The epee TCP server is replaced by
the transport layer first. The clearnet option is then tested on that
layer,
and the flip happens only after that testing passes. The interim pipe
(`pipe.rs`, the descriptor-handoff FFI, epee's `network_pipe_ops`) is
deleted at cutover and receives no further work. Host evidence gathered on
the pipe would not carry; protocol evidence does not need the pipe.

| Step | What | Kind |
| --- | --- | --- |
| 1 | Crypto core split onto `fix/p2p-transport-hmac-oracle` (`75f826cfb`); pipe branch parked at `190cbdc3b` | Done locally; crypto branch pushed |
| 2 | Documentation and register corrections | Separate doc PR; not this file |
| 3 | Pi-4 crypto bench and protocol fuzz | After this round opens; results count at the flip |
| 4 | This design round | This document |
| 5 | Transport-layer implementation, then a differential harness against epee | Code, after the round closes |
| 6 | Cutover: epee's transport and the pipe deleted | Not a flag day (D11) |
| 7 | Option evaluation on the transport layer | Evaluation record |
| 8 | The flip | Flag day (rule 07), only after step 7 |

Owner of the scaffolding-deletion FOLLOWUPS row (step 2 of that list):
**this document**. The row itself is added in the documentation PR, not
here. Target of that row: pre-genesis.

---

## 0. What Round 1 is asking

Round 1 records the substrate that was read at the pin, the requirements
the parked pipe branch taught, and a proposed shape. Dispositions in D3
are **PROPOSED**. D14 is not decided here.

Three requirements come from the review of
`fix/clearnet-pipe-option-testing` at `190cbdc3b` (commits `ea050fc4e`,
`190cbdc3b`). The transport layer must not repeat them:

1. **Failure causes cover the whole connection, both directions.** The
   pipe reported every post-channel close as `TransportHandshakeFailed`,
   and only the outbound dial logged a label. Inbound failures were never
   logged. That is D12.
2. **One source for the cause table.** The branch kept Rust constants and
   a C++ `switch` as two copies of the same integers. That is D12.
3. **A descriptor test counts the socket, not the process.** Counting all
   of `/proc/self/fd` races with `cargo test`'s other threads. Count the
   descriptors whose `readlink` is this socket's `socket:[inode]`, and
   assert one. That is D11.

---

## D0 — substrate read at `db2788d`

Verified by reading the files. Line numbers are from that pin.

epee's TCP stack is three layers. Only the bottom one is the transport layer.

- **Transport.** `boosted_tcp_server` / `connection<T>` in
  `contrib/epee/include/net/abstract_tcp_server2.h` (612 lines) and
  `abstract_tcp_server2.inl` (2,322 lines). `connection_basic.hpp` is 196
  lines and `connection_basic.cpp` is 285.
- **Levin.** `contrib/epee/include/net/levin_protocol_handler_async.h`.
  `foreach_connection`, `close`, and the invoke timers live on the
  handler config, reached from `net_node` as
  `m_net_server.get_config_object()`. Replacing the transport does not
  move that registry. LV-3 step c stays LV-3's.
- **Sessions and relay.** `net_node`, `levin_notify`, and the cryptonote
  handler. Out of scope (D1).

`i_service_endpoint` is the existing seam Levin already uses
(`contrib/epee/include/net/net_utils_base.h:441-453`): `do_send`,
`close`, `send_done`, `call_run_once_service_io`, `request_callback`,
`get_io_context`, `add_ref`, `release`.

Every `m_net_server` call in `net_node.inl`, read at this pin:
`add_connection`, `add_idle_handler`, `connect`, `deinit_server`,
`get_binded_port`, `get_binded_port_ipv6`, `get_config_object`,
`get_config_shared`, `get_io_context`, `init_server`,
`is_stop_signal_sent`, `run_server`, `send_stop_signal`,
`set_connection_filter`, `set_connection_limit`, `set_default_remote`,
`set_network_pipe`, `set_threads_prefix`. `get_config_shared` is what
each zone's `levin::notify` is constructed with (`net_node.inl:483`,
`:642`, `:890`), together with `get_io_context()`.

Under `src/`, only `src/p2p/net_node.h` includes epee's TCP server. The
other hits are epee's own internals (`connection_basic.cpp`,
`network_throttle-detail.cpp`, the Levin handler) and tests
(`tests/unit_tests/epee_boosted_tcp_server.cpp`, `tests/fuzz/levin.cpp`,
`tests/net_load_tests/`). p2p is the only production user.

Timers that exist today, read at `abstract_tcp_server2.inl:59-63`:

| Constant | Value | Who |
| --- | --- | --- |
| `NEW_CONNECTION_TIMEOUT_LOCAL` | 1,200,000 ms (20 minutes). The comment on `:60` says "2 minutes"; the value is the fact | inherited `m_local` path, refused by D3 |
| `NEW_CONNECTION_TIMEOUT_REMOTE` | 10,000 ms | not `m_local` |
| `DEFAULT_TIMEOUT_MS_LOCAL` | 1,800,000 ms (30 minutes) | `m_local` idle (`:109`) |
| `DEFAULT_TIMEOUT_MS_REMOTE` | 300,000 ms (5 minutes) | not `m_local` |
| `AGGRESSIVE_TIMEOUT_THRESHOLD` | 120 sockets | shifts the idle timer |
| `TIMEOUT_EXTRA_MS_PER_BYTE` | 0.2 | bytes-read extension |

`m_local` is set at `abstract_tcp_server2.inl:992` from
`is_loopback() || is_local()` on the remote address the connection was
started with, and the new-connection timer picks the local or remote
constant at `:1001-1004`. `is_local` is RFC 1918 (`local_ip.h:41-62`).
A peer in that class holds the socket for 20 minutes before any Levin
session exists, then has a 30-minute idle timer. D3 recommends refusing
that split. The ruling is D14 item 6.

`P2P_DEFAULT_CONNECTION_TIMEOUT` at `src/cryptonote_config.h:189` is
**5,000 ms**, not 10 seconds. `P2P_DEFAULT_HANDSHAKE_INVOKE_TIMEOUT` at
`:193` is also 5,000 ms. The 10-second figure and the 5-second figure
are different clocks. D9 re-derives both; neither number is adopted as
a connector deadline.

Send-queue caps, read at `abstract_tcp_server2.h:72-73`: 1,000 messages
and `100 * 1024 * 1024` bytes.

Outbound dialing is serial. `connections_maker` is
`net_node.inl:2009`. It reaches
`try_to_connect_and_handshake_with_new_peer` (`net_node.inl:1544`) at
the call sites `:1917` and `:1970`. A transport handshake adds a round
trip to every dial. A stalled peer holds that loop for the whole
attempt. The transport layer dials asynchronously and does not choose the
schedule. How many to dial, and when, is discovery policy (P2P-3 slice
3). Dials stay serial through cutover. The extra round trip is measured
in step 7, C7.

The peers-monitor thread starts at `net_node.inl:1114` and walks
`foreach_connection` at `:1125` once a second.
`is_host_limit` is `net_node.inl:231`. Both read the Levin registry.
Connections that have no channel yet are invisible to that walk (D8).

Two private tokio runtimes already exist:
`rust/shekyl-daemon-rpc/src/ffi_exports.rs:162` and
`rust/shekyl-tor-control-daemon/src/blocking.rs:120`. Both call
`Builder::new_multi_thread()`. The transport layer must not silently add a
third (D5, D14).

Sizes that are deletable at cutover, counted at this pin: the two
`abstract_tcp_server2` files (2,934 lines), `connection_basic` (481
lines), and `src/net/socks.cpp` + `socks.h` + `socks_connect.cpp` +
`socks_connect.h` (1,241 lines). The network-throttle sources are in
the deletion list (D13) and were not line-counted in Round 1.

p2p is treated as the only production user of this TCP server. Round 1
does not paste a grep of every caller; D13's deletion check is that
grep, run at cutover, and it must be empty.

---

## D1 — scope

**In.** The transport layer, for every network: listen, dial, SOCKS dial
for Tor and I2P, the overlay inbound listener, each connector's channel,
pre-channel timers, rate limiting, the socket count, and the send queue
with its bounds. Bytes are presented to the unchanged C++ Levin layer
through an `i_service_endpoint` adapter until LV-3.

**Out.** The `Connection` type, ownership transfer, the registry, and
relay dispatch (LV-3 steps a–d). The peerlist, admission policy,
discovery, and the handshake state machine (P2P-3 slices 1–4). Whether
Levin framing moves with the transport layer is D14 item 3.

**Decoupling rule.** Levin framing, the p2p protocol, and the cryptonote
protocol run over the transport contract and nothing else. The transport
layer never sees a command. Levin never sees a socket, an event loop, or
a network's mechanics. The `i_service_endpoint` adapter is this line.

The transport contract, on every network: an ordered, reliable byte
stream; encryption of that stream against the network observer, with
integrity of those bytes (they cannot be read or altered undetected);
exactly one close cause (D12); the observed endpoint; the connector's
declared capabilities, including what each leaves exposed. Encryption
is not confidentiality. The peer's address and port remain available,
and traffic patterns remain observable by volume and by the other
connections. The contract does not address traffic analysis. Connection
existence, timing, volume, sizes, and cross-connection patterns are
outside it.

The Rust reader already meets the rule. `shekyl-levin`'s reader is
"socket bytes in, complete Levin messages out" (`reader.rs:6`), with no
socket, zone, or runtime in it. The jumble is in the C++, read at this
pin. These are facts for LV-3 and the P2P-3 slices, not work for this
round:

1. The Levin layer owns connections. The registry, close-by-id, and
   `add_ref`/`release` live in `async_protocol_handler_config`.
   `net_node` reaches them through `get_config_object()`.
2. Levin drives the transport event loop. Invoke timers come from
   `get_io_context()` (`levin_protocol_handler_async.h:229`). The
   synchronous invoke pumps that I/O (`:753`). D6 is the interim for
   this item.
3. One protocol stack per network. Each `network_zone` owns its own
   `m_net_server` (`net_node.h:335-339`), and therefore its own Levin
   config, registry, and notifier.
4. `network_zone` mixes plumbing (`m_connect`, bind addresses and ports,
   `m_proxy_address`, `m_our_address`) with protocol state (seed nodes,
   the peerlist, config).
5. A framing field does a network job. The per-message
   `LEVIN_SIGNATURE` / PWD-T5 prefix is PWC-A2's.
6. Network identity inside protocol and policy. About 62 zone
   comparisons: 53 in `src/p2p`, 7 in `src/cryptonote_protocol`, 2 in
   `src/net`. `enum class zone` hides policy in its order
   (`enums.h:53`, "order from here changes priority of selection for
   origin TXes").

Three names, kept apart. **Levin framing** is bytes to messages: the
bucket header, invoke, and notify. The **p2p protocol** is the
node-control commands over that framing (1001, timed sync, peer
exchange). The **cryptonote protocol** is chain data over that framing
(blocks, transactions). Framing is the analogue of HTTP's message
framing. The two protocols are the application. A connector plus its
layers is TCP+TLS, or a Tor stream.

---

## D2 — not a port

LV-3's guardrail applies here. The transport layer is designed from the
rulings. `connection<T>` is a non-canonical reference. For every duty
that is carried, the row names the ruling it serves. The following are
refused up front, before the inventory argues them back in:

- SSL plumbing.
- A per-connection OS thread.
- Handing a descriptor from C++ into Rust (`try_clone`, `native`
  release, `network_pipe_ops`).
- epee's `host_count` where admission owns the count.
- Any timeout whose only justification is that epee already uses that
  number.

---

## D3 — duty inventory (PROPOSED)

Round 1's table. Each disposition is proposed for review, not closed.
"Carry" means the duty survives. "Re-derive" means the duty survives
and the mechanism does not. "Refuse" means it does not survive.

| Duty | Read at this pin | Proposed disposition |
| --- | --- | --- |
| Accept loop, connection filter, connection limit | Filter type `i_connection_filter` in `abstract_tcp_server2.h`; admission walk `net_node.inl:231` | Carry. The connector calls admission. It does not own the policy. Serves the ceiling admission already owns. |
| Outbound dial | `P2P_DEFAULT_CONNECTION_TIMEOUT` = 5 s (`cryptonote_config.h:189`); remote new-connection timer = 10 s (`abstract_tcp_server2.inl:61`) | Carry the dial. Re-derive both clocks (D9). They are not one number. |
| SOCKS dial; `add_connection` | `net_node.inl:3618`; `src/net/socks*` (1,241 lines) | Carry in Rust. `tokio-socks` 0.5.3 is already a workspace dependency (`shekyl-p-fetch/Cargo.toml:40`, `shekyl-rpc-transport/Cargo.toml:43`). Reusing it adds no supply-chain surface (rule 17). A separate `socks` 0.3.4 crate is in `Cargo.lock` because `ureq` 3.3.0 depends on it, and `shekyl-p-transport` enables `ureq/socks-proxy` via its `tor-socks` feature. The connector uses `tokio-socks`, not that crate. |
| Overlay inbound attribution | `set_default_remote` at `net_node.inl:678` (`--anonymous-inbound`) and `:885` (`tor_address::unknown()`); applied at `abstract_tcp_server2.inl:1905-1908` | **Carry, and do not attribute from the socket.** Tor and I2P inbound connections arrive on the local router's loopback socket. The observed endpoint is "this zone, no address", never `127.0.0.1`. Attributing from the socket would collapse admission's per-host view into one host. This is where LV-3's OBSERVED endpoint originates. |
| Tor forward listener | `net_node.inl:863-880` | Carry. Bound to `127.0.0.1` on port 0. The OS-assigned port is read back with `get_binded_port` (`:881`) and handed to Tor control. Bind failure erases the zone (`:878`). |
| Local versus remote timers | `m_local` at `abstract_tcp_server2.inl:992`; timers at `:100-112` and `:1001-1004`. Local new-connection is 1,200,000 ms (20 minutes), not the "2 minutes" comment on `:60` | **Recommended refuse. Ruling is D14 item 6.** D2 already refuses a timeout whose only justification is that epee uses it, and this row names no other ruling. `m_local` is loopback or RFC 1918, so a LAN neighbour holds a connection for 20 minutes before any Levin session, against 10 seconds for everyone else. A test rig that needs a longer timer sets it explicitly. |
| Gap from channel established to session established | Outbound Levin invoke is 5 s (`cryptonote_config.h:193`). Inbound has the 256 KiB pre-session byte cap and then the idle timer | **A per-connector timer, derived under D9.** Once the C++ object exists, epee's new-connection timer no longer covers this gap. An inbound peer that finishes the transport handshake and then sends nothing holds a slot until the idle timer (5 minutes, or 30 minutes on the `m_local` path D14 item 6 is asked to refuse). Each connector owns one deadline for its peers, beside PWD-B3's byte cap for command 1001. |
| Dual-stack bind and port 0 | `init_server` at `net_node.inl:1065` takes IPv4 and IPv6 ports and addresses plus `m_use_ipv6` / `m_require_ipv4` | Carry. A port-0 bind reads the assigned port back. The Tor listener above is the port-0 case that must not abort the rest of the boot. |
| Worker pool | `run_server`'s thread count; `set_threads_prefix` | Carry the pool as a stated size, not as "however many epee used". D6 sizes the socketless executor separately. |
| Graceful stop | `send_stop_signal`, then connections drained, then `deinit_server` (`net_node.inl:1187` is one `deinit_server` site) | Carry the order: stop accepting, drain or cancel live connections, then tear the listeners down. |
| `call_run_once_service_io` | Called from `levin_protocol_handler_async.h:753`. The synchronous `invoke_remote_command2` (`levin_abstract_invoke2.h:60`) has no caller under `src/` at this pin. p2p uses `async_invoke_remote_command2` only (`net_node.inl:1270`, `:1351`, `:2802`). Tests call the async form too | **Delete**, not carry. The sync invoke path goes with it. A test-only caller found later reopens this row. |
| New-connection, idle, bytes, and aggressive timers | `abstract_tcp_server2.inl:59-63` | Re-derive each. Channel-established and session-established bound different waits. The inherited values are inputs, not the answer. |
| Rate limit and per-connection speed stats | `network_throttle*`; the pipe's `on_wire` path on the parked branch | Carry the limit. Stats are observed facts reported upward, not a second policy. |
| Send-queue bounds | 1,000 messages and 100 MiB (`abstract_tcp_server2.h:72-73`) | Carry, with one source. The pipe's `PIPE_PLAINTEXT_BUDGET` was a second copy and is not repeated. |
| Send backpressure and strand order | Send path in `abstract_tcp_server2.inl` (queue checks near the caps above) | Re-derive. Nonce order equals wire order because there is one writer per direction. A strand is not required to get that. |
| `--proxy` (clearnet through SOCKS) | `daemon.cpp:156-157` passes `arg_proxy` (`command_line_args.h:97`). `net_node.inl:926-935` sets the public zone's `m_connect = socks_connect` and a proxy address | **Carry, and name it.** Aimed at Tor, this is clearnet addressing reached through Tor exit relays. The peer does not see this node's address. Encryption ends at the exit, which sees the clearnet peer, so the Noise layer is still required on that hop. Proxied connections enter the public server via `add_connection`, so the option-on path covers them today. The declaration makes that coverage a property of the stack, not an accident of which server the pipe attached to. |
| Overlay proxy precondition | `--tx-proxy tor,<ip>:<port>` accepts any address (`net_node.inl:623`) | **Declare the precondition. The disposition of a non-loopback address is D14 item 5.** Tor's native encryption holds from the local router onward. A router on another host means unencrypted Levin crosses that hop. The Tor connector's declaration states "the hop to the router is loopback", and configuration checks the part it can check. |
| `--tos-flag` / `IP_TOS` | `net_node.cpp:182`, default `-1`. Applied at `net_node.inl:597` and `set_tos_flag` `:3378-3383` (a `-1` returns without storing). Every socket still calls `setsockopt` at `abstract_tcp_server2.inl:966-976`. The static `m_default_tos` (`connection_basic.cpp:121`) is zero-initialized, so the default path sets TOS to 0 | **Recommended refuse. Ruling is D14 item 7.** A per-operator DSCP is a per-node marker on every packet. The recommendation is no `setsockopt` at all, so TOS stays at the OS default. Step 7 C1 records the DSCP that actually leaves today on the `-1` default, which sets TOS to 0. What the kernel emits is measured, not assumed. |
| `no_delay(false)` (Nagle) | Set on every socket at `abstract_tcp_server2.inl:977-982` | **Measure before deciding**, under step 7 C9. Nagle changes the record sizes an observer sees, so it is part of the record-length evidence. It is not fixed before that evidence exists. |
| FIN versus RST, linger | epee close / shutdown | **One behaviour for every failure before the channel exists:** close after zero bytes written, FIN, no linger and no RST variant. Step 7 C4 asserts those failures are indistinguishable from the far side. |
| `add_ref` / `release`, `request_callback`, `send_done` | `i_service_endpoint` | The adapter's contract (D4). Not a copy of epee's refcount. |
| Executor for invoke timers and idle handlers | `levin_protocol_handler_async.h:229` takes `get_io_context()` for the invoke timer | D6. Proposed: a socketless `io_context` until LV-3. |
| Serial outbound dialing | `connections_maker` at `net_node.inl:2009`, call at `:1917` | **Stays serial through cutover.** The transport layer exposes an asynchronous dial and does not choose the schedule. When and how many to dial is discovery policy, P2P-3 slice 3. The extra round trip is measured in step 7, C7. |
| SSL | `m_state.ssl` on the connection | **Refuse.** |

---

## D4 — seam contract (PROPOSED)

- **No C++ object exists before the channel is established.** The
  connector owns the socket from accept or dial. The C++ Levin handler
  and connection context are created when the transport handshake
  finishes. The Levin handshake clock therefore starts there. The
  pre-channel byte limit is the size of one flight, not a 256 KiB
  inherited cap. Nothing above the transport can see a connection that
  has no channel.
- **The connector supplies only observed endpoints.** For a clearnet
  socket that is the peer address. For Tor and I2P inbound, the
  observed truth is "this zone, no address". It is never the loopback
  socket the local router accepted on. A C++ object created at channel
  established receives that observed endpoint, not `127.0.0.1`.
- **Tasks, not threads.** Transport-layer tasks post into the C++ executor.
  Delivered buffers are bounded by a read window. A C++ call does not
  block a connector task. A connector task is never the last owner of
  a C++ object.
- **A refused delivery closes the connection.** If the C++ side declines
  a buffer, the connection ends with the D12 cause for that refusal.
  The connector does not drop the buffer and keep reading.
- **Close from either side is idempotent** and records exactly one
  cause.
- **FFI (rule 40).** Every call names its direction and who owns the
  buffer. A callback context is not a raw `this`.

The parked branch's `on_plain` nonzero path is this contract, not code
to keep.

---

## D5 — runtime ownership (not decided)

Options, with the cost left for the Pi-4 floor rather than invented:

1. One daemon-owned runtime, handed to the transport layer and to the
   existing daemon-rpc and tor-control users.
2. A connector runtime with a stated thread budget, beside the two
   that already exist.

Round 1 does not pick. D14 item 1 is this choice.

---

## D6 — executor above the transport, until LV-3 (INTERIM)

This is D1 violation 2, kept on purpose until LV-3, not a carried
design. Levin invoke timeouts take their timer from `get_io_context()`
(`levin_protocol_handler_async.h:229`). `net_node` idle handlers run
on the server's `io_context`. Each zone's relay notifier is
constructed with that same `io_context` and with `get_config_shared()`
(`net_node.inl:483`, `:642`, `:890`). Keep a socketless asio
`io_context` as that executor, and delete it at LV-3. It hosts Levin's
invoke timers, `net_node`'s idle handlers, and LV-3's relay-dispatch
timers. Its thread pool is sized for those three, not only the first
two. The socket-bearing context does not survive cutover.

---

## D7 — capabilities are data (PROPOSED)

Each connector declares its native capabilities as data. The stack for
a connection is assembled from that declaration in a fixed order:
routing, then the connector, then added layers, then the contract.
Whatever the contract needs and the network lacks, a layer supplies.
If no layer can supply it, that connector is not usable. Nothing above
the transport layer asks which network it is on. The order is tested,
so a misordered or doubled layer cannot occur by configuration.

**No connector, capability, or declaration carries an unqualified
"protected", "secure", or "anonymous".** Every declared capability
names the property, the adversary, and what remains exposed (and who
owns that remainder, or "unowned"). A cell nobody has assessed reads
**not assessed**. It does not inherit a default from another network.
No deep assessment is owed in this round. I2P, Nym, and Lokinet are
columns that test the interface. They are not work.

| Declared per connector | Clearnet | Tor | I2P |
| --- | --- | --- | --- |
| Addressing | IPv4/IPv6 + port | onion v3 | `.b32.i2p` |
| Encryption of the byte stream against the network observer | none native — **Noise layer added** (hybrid PQ). Encryption only: the peer's address and port stay visible, and traffic patterns stay observable | native, classical only (accepted); precondition: the hop to the local router (D3). Encryption only; the rows below say what stays visible | native; not assessed further |
| This node's address hidden from the peer | no | native | native |
| This node's address hidden from an observer at one end | no | partially — the observer sees Tor use, not the destination; not assessed further | not assessed |
| Correlation by an observer at both ends (timing, volume) | **not provided** | **not provided** | **not assessed** |
| Connection existence, timing, volume, sizes visible to an observer at this node's end | **visible** — sizes pending the record-length ruling (D14 item 4) | visible as Tor traffic (cell-quantised sizes) | not assessed |
| Origin of relayed transactions, against peers | **not provided by any connector** — owned by Dandelion++ | same | same |
| Stream semantics | TCP | Tor stream | streaming library |
| Observed identity of an inbound peer | the socket address | "this zone, no address" | "this zone, no address" |
| Deadline inputs (D9) | measured per connector | measured per connector | measured per connector |

Consequences:

- **Clearnet is a connector plus the Noise layer.** Noise is not a
  clearnet special case in code. The stack includes it because clearnet
  declares no native encryption. Noise supplies encryption. It benefits
  confidentiality and does not create it: the peer's IP address and
  port stay available, and traffic can still be monitored by volume and
  by the other connections. The option-off path is a stack
  that does not meet the contract. The flip is "enforce the contract".
  There is no mode that accepts both the Noise prefix and plaintext on
  one port. `noise.rs`, `channel.rs`, `prefix.rs`, and `aead.rs` are
  that layer. The HMAC implementation and the NN oracle live on
  `fix/p2p-transport-hmac-oracle`.
- **`--proxy` is clearnet addressing plus Tor routing** (D3). The peer
  does not see this node's address. Encryption ends at the exit, so the
  Noise layer is still required beyond it.
- **Deadlines are per-connector data** (D9). A network with seconds of
  mixing delay would break one global handshake deadline.
- **Stream semantics are a capability.** A future message-shaped
  network would need a stream layer (ordering, reliability, framing).
  That is the interface's stress test. This round does not design that
  layer.
- **A precondition we can check is checked.** A loopback hop, a
  completed handshake. One we cannot check — an overlay's own
  cryptography — is a trust assumption with its concession. Tor's is
  classical-only.
- **Meeting the contract is encryption of the byte stream, and
  integrity of those bytes, against the network observer.** It is not
  confidentiality. It says nothing about traffic analysis, peer
  graphing, or origin privacy. Those rows name their owner or say they
  are unowned.
- **One source.** `RelayZone` / `LinkSecrecy` in
  `rust/shekyl-relay-privacy/src/zone.rs` is a second per-network
  property table for the same networks. The connector declaration is
  the source. The relay lane reads it. Recording that requirement is
  this round's job. Changing the relay lane is not.

Behaviour stays uniform within a connector (the TCP-option and close
decisions in D3), even where connectors differ from each other.

## Network partitions (REQUIREMENT)

Decoupling must not erase separations that are privacy properties.
These partitions exist today, and each one stays:

- Relay and Dandelion++ run per zone.
- Self-detection nonce windows are zone-scoped (PWD-I1).
- `m_our_address`, and what is advertised, are per zone.
- Admission counts are per zone.

**Every partition survives as explicit policy keyed by the session's
network, not as a duplicated protocol stack, and a test proves none of
them leaks across networks.** A single registry with one broadcast loop
over every session would be a cross-network leak.

Through cutover, the per-network Levin instances stay as they are. The
differential harness needs parity with epee. The design input for LV-3
is one Levin and p2p layer serving every connector, with these
partitions as tested policy. Items 1, 3, and 6 of D1 are that work.
The existing C++ zone branches move with LV-3 and the P2P-3 slices, not
with this round. The transport layer does not grow new ones.

The peer-exchange address union is closed and will be frozen at
genesis: `ADDR_IPV4`, `ADDR_IPV6`, `ADDR_I2P`, `ADDR_TOR`
(`rust/shekyl-levin/src/payload/address.rs:17-20`). An address type
belongs to the connector for that network. A future network needs a
stated rule for a type this node does not recognise. That decision
belongs to `SHEKYL_P2P_PROTOCOL.md`. It is a FOLLOWUPS row, not a
ruling here.

---

## D8 — socket count (PROPOSED)

The transport layer owns the count of live sockets, per network and per
direction, including sockets that have no channel yet. The Levin
registry never sees those. Admission (P2P-3 slice 2) can read the
count instead of walking `foreach_connection` (`net_node.inl:231` and
the monitor at `:1125`). Whether the monitor thread then goes away is
slice 2's decision. This round does not build a second count beside
admission's.

---

## D9 — deadlines are derived, and not yet

The transport handshake's 15 s on the pipe, the 5 s dial timeout, and
the 10 s / 5 min inherited timers are not transport-layer constants.
Deadlines are derived **per connector**. Inputs, when they exist:
flight sizes (1,224 and 1,160 bytes on the wire, prefix included), the
Pi-4 crypto cost from step 3, and RTT measured on that connector. A
single global handshake deadline would break on a network whose mixing
delay is seconds. No deadline is written into this document before that
measurement. Rule 26 B9.

---

## D10 — pre-channel bounds (PROPOSED)

Per connection that does not yet have a channel: one task, one
descriptor, at most one flight of buffered bytes. The responder runs
ML-KEM encapsulation after it has read message 1. What bounds the rate
of that work is the existing admission-before-channel question. This
round does not re-solve it; it names the dependency.

The transport layer also bounds the time **after** the channel exists and
before the Levin handshake finishes. Outbound already has the 5 s
invoke timeout. Inbound does not: a peer that completes the transport
handshake and then sends nothing holds its slot until the idle timer.
That deadline is derived under D9, next to PWD-B3's byte cap for
command 1001. It is not the idle timer.

---

## D11 — test gates

These are the gates for the implementation PR, written now so the
round can reject them.

- **Differential harness against epee, before any deletion.** The same
  Levin traffic through both transports, option off, on loopback.
  Compare delivered bytes, close causes, and timeout behaviour. epee
  stays in the tree as the reference until this passes. It is not a
  test host for the option.
- **Cross-build interop.** A connector node and an epee node, option
  off, peering on testnet through sync, relay, and both dial
  directions. The loopback harness is one build. The claim that
  cutover is not a flag day is about two builds talking to each other.
- **One descriptor per connection.** Count `readlink` results equal to
  that socket's `socket:[inode]`. Assert one. Do not count
  `/proc/self/fd` for the whole process.
- **Carried from step 3.** The fuzz targets, and the Pi-4 bench run
  again on the transport layer's handshake path.
- **Cutover is not a flag day.** With the option off, the transport layer
  carries the same bytes epee does, and Tor/I2P are unchanged on the
  wire, so a connector node and an epee node interoperate. The
  differential harness is what shows that. The flag day is the flip
  (step 8), under rule 07, not the cutover.

---

## D12 — one failure cause, both directions (REQUIREMENT)

Every connection ends with exactly one typed cause, logged once, on
both the dialing side and the accepting side. The table is defined
once and exported to C++ through the FFI header. There is no second
hand-kept copy.

| Phase | Causes |
| --- | --- |
| Before the channel exists | `PrefixMismatch`, `TransportHandshakeFailed`, `TransportTimeout`, `AdmissionRefused`, `DialFailed`, `ProxyRefused`, `LocalClose` |
| Channel exists, Levin handshake not done | `LevinHandshakeTimeout`, `LevinHandshakeRejected`, `LocalClose` |
| Any time after the channel exists | `PeerClosed`, `RecordRejected`, `SessionRefused`, `IoError`, `LocalClose` |

`AdmissionRefused` is a ban-filter or inbound-ceiling refusal at
accept. `DialFailed` is an outbound TCP connect that did not complete.
`ProxyRefused` is a SOCKS or overlay failure and carries the reply
code (an unreachable onion is this cause, not a generic I/O error).
`LocalClose` is this node closing, including a shutdown during the
handshake, so it is valid in every phase.
`RecordRejected` is an AEAD failure or a poisoned receiver.
`SessionRefused` is the C++ side declining a delivery (D4).

This table is a requirement of the transport layer. It is not implemented
on the pipe. A failure an operator can act on is one of these values
(rule 82), not a generic drop. On the overlays that is
`ProxyRefused` with its reply code, not `IoError`.

---

## D13 — deletions at cutover

Each of these goes at step 6, after the differential harness passes.
The check is an `rg` that returns nothing, and that `rg` is written
into the cutover PR only after a search shows no other consumer.
Round 1 names the set:

- `contrib/epee/include/net/abstract_tcp_server2.h`
- `contrib/epee/include/net/abstract_tcp_server2.inl`
- `connection_basic.hpp` / `connection_basic.cpp`
- `network_throttle*`
- `src/net/socks*`
- `network_pipe_ops` and `set_network_pipe`
- `rust/shekyl-p2p-transport/src/pipe.rs`
- `rust/shekyl-ffi/src/clearnet_transport_ffi.rs`
- the epee transport unit tests that exist only to drive that server

`noise.rs`, `channel.rs`, `prefix.rs`, and `aead.rs` are not in this
list. They are the crypto core.

---

## D14 — rulings for Rick

The round will prepare these. Round 1 does not decide them.

1. **Runtime ownership** (D5): one daemon runtime, or a transport-layer
   runtime with a stated budget.
2. **Overlays in the same cutover as clearnet, or staged.** One
   transport layer, with a connector per network, matches D7. Staging
   leaves two transports, and a zone branch in `net_node`, until the
   second cutover.
3. **Whether Levin framing moves with the transport layer** or stays
   C++ until LV-3.
4. **Record framing and the rekey interval.** Record-length
   concealment is in scope against a network observer; fixed-window
   framing versus BOLT-8 is open. `REKEY_NONCES = 1000` is BOLT-8's
   inherited value, not a derivation. Step 7's evidence informs both.
   This design does not freeze either.
5. **A non-loopback overlay proxy address:** refuse, warn, or accept
   (D3). The model only requires that the precondition is declared and
   checked. It does not pick the disposition.
6. **The local/remote timer split.** Recommended refuse (D3). The local
   new-connection value is 20 minutes, and the class includes RFC 1918.
7. **The `--tos-flag` knob.** Recommended refuse (D3). Leave TOS at the
   OS default, with no `setsockopt`. C1 records what goes out today.

---

## D15 — falsifiers

Re-cut the transport layer, rather than follow this plan, if any of these
is observed:

1. **A transport duty needs to walk connections.** The registry is
   then not where D0 says it is, and LV-3's registry step is being
   pulled into the transport.
2. **Levin cannot run on an `i_service_endpoint` adapter** without
   changes beyond that endpoint.
3. **Another piece of the daemon grows its own socket owner** while
   this round is open.

---

## What Round 2 closed, and what Round 3 still owes

Closed in this revision, from a re-read at `db2788d`:

- Overlay inbound attribution and the Tor forward listener (D3, D4).
- The local new-connection timer is 1,200,000 ms, which is 20 minutes.
  The comment on `abstract_tcp_server2.inl:60` says "2 minutes".
  Refusing the local/remote split is recommended. The ruling is D14
  item 6.
- A derived deadline between channel established and session
  established (D9, D10).
- `AdmissionRefused`, `DialFailed`, `ProxyRefused`, and `LocalClose`
  in every phase (D12).
- Cross-build interop as a D11 gate.
- Dual-stack bind, the worker pool, stop order, and `levin::notify`
  on the socketless executor (D3, D6).
- The full `m_net_server` call list and the sole production user (D0).
- `tokio-socks` 0.5.3 is the SOCKS client. `socks` 0.3.4 is `ureq`'s,
  via `shekyl-p-transport`'s `tor-socks` feature.
- `call_run_once_service_io` and the sync invoke are a deletion. A
  test-only caller found later reopens that row.

Closed in the same revision, from the review of that text:

- `--tos-flag` is recommended refused (D14 item 7). The default path
  `setsockopt`s TOS 0. C1 records the DSCP that leaves.
- Nagle waits on C9.
- Failures before the channel exists close with a FIN after zero bytes
  written. C4 measures that they match.
- Dials stay serial through cutover. The schedule is P2P-3 slice 3.
  C7 measures the extra round trip.

## What Round 3 adopted

Ruled vocabulary and structure, no new implementation tasks:

- The subsystem is the transport layer. A connector reaches one network.
  The filename is `P2P_TRANSPORT_LAYER.md`.
- D1's decoupling rule, with the six C++ violations recorded for LV-3.
- D7's capability table. Clearnet has no native encryption. The Noise
  layer adds encryption and does not create confidentiality.
  Unassessed cells say so.
- `--proxy` and the overlay proxy precondition (D3). The precondition's
  disposition is D14 item 5.
- Network partitions stay as tested policy keyed by the session's
  network. One Levin layer for every connector is an LV-3 input.
- `LinkSecrecy` reads the connector declaration. It does not keep a
  second copy.
- Unrecognised peer-exchange address types are a FOLLOWUPS row owned by
  `SHEKYL_P2P_PROTOCOL.md`.

Still open:

- D14, all seven items.
