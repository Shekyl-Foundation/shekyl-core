# P2P transport layer — Rust connectors in place of epee's TCP server

**Status: CLOSED — Round 4, 2026-09-25. D3 RULED. D6 RULED.** The design is the spec for
implementation. Round 1 was pinned to `dev`
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
layer, and the flip happens only after that testing passes. The interim pipe
(`pipe.rs`, the descriptor-handoff FFI, epee's `network_pipe_ops`) is
deleted at cutover and receives no further work. Host evidence gathered on
the pipe would not carry; protocol evidence does not need the pipe.

| Step | What | Kind |
| --- | --- | --- |
| 1 | Crypto core on `fix/p2p-transport-hmac-oracle`; pipe branch parked at `190cbdc3b` | Branch state is the index row, not this table |
| 2 | Documentation and register corrections | Separate doc PR; not this file |
| 3 | Pi-4 crypto bench and protocol fuzz | After this round opens; results count at the flip |
| 4 | This design round | Closed. This document is the spec |
| 5 | Transport-layer implementation, then a differential harness against epee | Code, after the round closes |
| 6 | Cutover: epee's transport and the pipe deleted | Not a flag day (D11) |
| 7 | Option evaluation on the transport layer | Evaluation record |
| 8 | The flip | Flag day (rule 07), only after step 7 |

The scaffolding-deletion FOLLOWUPS row is step 2, a separate doc PR.
Its owner is [`SHEKYL_P2P_PROTOCOL.md`](SHEKYL_P2P_PROTOCOL.md), which
is the wire spec and is already on `dev`. Target: pre-genesis. D13 is
what that row deletes.

---

## 0. Status

The design round is closed. D6 is ruled: a socketless `io_context` is a
bounded interim that ends when the timing engine lands, not at LV-3.
What is not a number yet is named in the section that owns it: deadline
values (D9), the fixed-window size and whether every-record rekey is
affordable (D14 item 4, gated on C9 and C5), and the executor's thread
budget (D6, from C6). Those measurements do not reopen the direction.

The wire spec is `SHEKYL_P2P_PROTOCOL.md`. It carries the framing
direction. This document does not.

Three requirements from the parked pipe branch (`190cbdc3b`) are in
force. The transport layer does not repeat the mistakes:

1. **Failure causes cover the whole connection, both directions** (D12).
2. **One source for the cause table** (D12).
3. **A descriptor test counts the socket, not the process** (D11).

---

## D0 — substrate read at `db2788d` (the pin)

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
session exists, then has a 30-minute idle timer. D14 refuses that split.

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
the deletion list (D13). They were not line-counted.

Under `src/`, `src/p2p/net_node.h` is the only production include of
this TCP server (D0, above). D13's deletion check is the grep that
must be empty at cutover.

---

## D1 — scope (RULED 2026-09-25)

**In.** The transport layer, for every network: listen, dial, SOCKS dial
for Tor and I2P, the overlay inbound listener, each connector's channel,
pre-channel timers, rate limiting, the socket count, and the send queue
with its bounds. Bytes are presented to the unchanged C++ Levin layer
through an `i_service_endpoint` adapter until LV-3.

**Out.** The `Connection` type, ownership transfer, the registry, and
relay dispatch (LV-3). The peerlist, discovery, and the handshake
state machine (P2P-3 slices 1, 3, and 4). Session admission stays
above the seam. Socket admission is this round: P2P-3 slice 2 is
folded in. Levin framing stays C++ through cutover and moves with
LV-3 (D14).

**Each layer owns its own admission.** The transport layer owns socket
admission: may this socket exist? That is the ban list and the inbound
ceiling, enforced in Rust at accept, from values given to it — the
operator's ban entries, and the ceiling derived by
`shekyl-peer-policy`. The session layer (Levin framing and the p2p
protocol) owns session admission: may this peer have a session? That
is `network_id`, the self-detection nonce, support flags, and
PWD-B3's per-command caps, in `handle_handshake`. Neither layer reads
the other's state to decide.

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
pin. Items 1–6 are facts for LV-3 and the P2P-3 slices, not work for
this round. Item 7 is the knot this round untangles.

1. The Levin layer owns connections. The registry, close-by-id, and
   `add_ref`/`release` live in `async_protocol_handler_config`.
   `net_node` reaches them through `get_config_object()`.
2. Levin drives the transport event loop. Invoke timers come from
   `get_io_context()` (`levin_protocol_handler_async.h:229`). The
   synchronous invoke pumps that I/O (`:753`) and is deleted under D3.
   D6 keeps a socketless `io_context` until the timing engine lands,
   and then C++ has no event loop.
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
7. Socket admission walks the Levin registry. `census_inbound`
   (`net_node.inl:3158`) counts by walking connections because epee's
   transport keeps no count. This round untangles it: the transport
   layer keeps the count (D8) and enforces the ceiling at accept.

Three names, kept apart. **Levin framing** is bytes to messages: the
bucket header, invoke, and notify. The **p2p protocol** is the
node-control commands over that framing (1001, timed sync, peer
exchange). The **cryptonote protocol** is chain data over that framing
(blocks, transactions). Framing is the analogue of HTTP's message
framing. The two protocols are the application. A connector plus its
layers is TCP+TLS, or a Tor stream.

---

## D2 — not a port (RULED 2026-09-25)

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

## D3 — duty inventory (RULED 2026-09-25)

The local/remote timer split and `--tos-flag` are refused (D14).
"Carry" means the duty survives. "Re-derive" means the duty survives
and the mechanism does not. "Refuse" means it does not survive.

| Duty | Read at this pin | Disposition |
| --- | --- | --- |
| Accept loop, connection filter, connection limit | Filter type `i_connection_filter` in `abstract_tcp_server2.h`; admission walk `net_node.inl:231` | **Enforce socket admission at accept, in Rust, with no C++ call.** The ceiling comes from `shekyl-peer-policy`. Ban entries come from the operator. The transport layer does not own those values. It does not call into C++ admission. |
| Ban list | `block_host` at `net_node.inl:256`. The registry sweep that drops live connections is `foreach_connection` at `:302`. RPC callers: `core_rpc_server.cpp:193`, `:997` (`get_blocked_hosts`), `:1101`, `:1103`. Discovery's pre-dial check is `is_remote_host_allowed` at `net_node.inl:1902` | **Move the list to Rust**, keyed on the observed host, carrying IPv4 subnets and expiry. The operator's RPC reaches it through the FFI (`block_host`, `unblock_host`, `get_blocked_hosts`). A ban closes existing sockets to that host directly. It does not sweep the Levin registry. Discovery's pre-dial check reads the same list. |
| Outbound dial | `P2P_DEFAULT_CONNECTION_TIMEOUT` = 5 s (`cryptonote_config.h:189`); remote new-connection timer = 10 s (`abstract_tcp_server2.inl:61`) | Carry the dial. Re-derive both clocks (D9). They are not one number. |
| SOCKS dial clock | A SOCKS dial is the proxy handshake, then the overlay circuit build and rendezvous. `src/net/socks*` has its own timeout | **Its own per-connector clock, derived under D9.** It does not inherit the timeout from `src/net/socks`. |
| SOCKS dial; `add_connection` | `net_node.inl:3618`; `src/net/socks*` (1,241 lines) | Carry in Rust. `tokio-socks` 0.5.3 is already a workspace dependency (`shekyl-p-fetch/Cargo.toml:40`, `shekyl-rpc-transport/Cargo.toml:43`). Reusing it adds no supply-chain surface (rule 17). A separate `socks` 0.3.4 crate is in `Cargo.lock` because `ureq` 3.3.0 depends on it, and `shekyl-p-transport` enables `ureq/socks-proxy` via its `tor-socks` feature. The connector uses `tokio-socks`, not that crate. |
| Overlay inbound attribution | `set_default_remote` at `net_node.inl:678` (`--anonymous-inbound`) and `:885` (`tor_address::unknown()`); applied at `abstract_tcp_server2.inl:1905-1908` | **Carry for Tor now, and for I2P when an I2P connector exists (D14 item 2).** Do not attribute from the socket. Inbound arrives on the local router's loopback socket. The observed endpoint is "this zone, no address", never `127.0.0.1`. Attributing from the socket would collapse admission's per-host view into one host. This is where LV-3's OBSERVED endpoint originates. |
| Tor forward listener | `net_node.inl:863-880` | Carry. Bound to `127.0.0.1` on port 0. The OS-assigned port is read back with `get_binded_port` (`:881`) and handed to Tor control. Bind failure erases the zone (`:878`). |
| Local versus remote timers | `m_local` at `abstract_tcp_server2.inl:992`; timers at `:100-112` and `:1001-1004`. Local new-connection is 1,200,000 ms (20 minutes), not the "2 minutes" comment on `:60` | **Refuse (D14).** D2 already refuses a timeout whose only justification is that epee uses it. The class is loopback or RFC 1918, so any LAN host gets 20 minutes before a Levin session, against 10 seconds for everyone else. Container port-forwarding makes this worse: inbound peers arrive from the bridge gateway's private address, every peer looks local, and admission's per-host view collapses to one host. A test rig that needs a longer timer sets it explicitly. |
| Gap from channel established to session established | Outbound Levin invoke is 5 s (`cryptonote_config.h:193`). Inbound has the 256 KiB pre-session byte cap and then the idle timer | **A per-connector timer, derived under D9.** Once the C++ object exists, epee's new-connection timer no longer covers this gap. An inbound peer that finishes the transport handshake and then sends nothing holds a slot until the idle timer (5 minutes on the path that remains after D14 refuses the local split). Each connector owns one deadline for its peers, beside PWD-B3's byte cap for command 1001. |
| Dual-stack bind and port 0 | `init_server` at `net_node.inl:1065` takes IPv4 and IPv6 ports and addresses plus `m_use_ipv6` / `m_require_ipv4` | Carry. A port-0 bind reads the assigned port back. The Tor listener above is the port-0 case that must not abort the rest of the boot. |
| Worker pool | `run_server`'s thread count; `set_threads_prefix` | Carry the pool as a stated size, not as "however many epee used". D6 sizes the socketless executor separately. |
| Graceful stop | `send_stop_signal`, then connections drained, then `deinit_server` (`net_node.inl:1187` is one `deinit_server` site) | Carry the order: stop accepting, drain or cancel live connections, then tear the listeners down. |
| `call_run_once_service_io` | Called from `levin_protocol_handler_async.h:753`. The synchronous `invoke_remote_command2` (`levin_abstract_invoke2.h:60`) has no caller under `src/` at this pin. p2p uses `async_invoke_remote_command2` only (`net_node.inl:1270`, `:1351`, `:2802`). Tests call the async form too | **Delete**, not carry. The sync invoke path goes with it. A test-only caller found later reopens this row. |
| New-connection, idle, bytes, and aggressive timers | `abstract_tcp_server2.inl:59-63` | Re-derive each. Channel-established and session-established bound different waits. The inherited values are inputs, not the answer. |
| Rate limit and per-connection speed stats | `network_throttle*`; the pipe's `on_wire` path on the parked branch | Carry the limit. Stats are observed facts reported upward, not a second policy. |
| Send-queue bounds | 1,000 messages and 100 MiB (`abstract_tcp_server2.h:72-73`) | **Carry the mechanism, with one source, and re-derive the value.** The value is PWD-T6's session-established limit (the largest legitimate message) plus measurement. It is not 100 MiB. That inherited round number gives no memory bound once it is multiplied by the inbound ceiling. The pipe's `PIPE_PLAINTEXT_BUDGET` was a second copy and is not repeated. |
| Send backpressure and strand order | Send path in `abstract_tcp_server2.inl` (queue checks near the caps above) | Re-derive. Nonce order equals wire order because there is one writer per direction. A strand is not required to get that. |
| `--proxy` | `daemon.cpp:156-157` passes `arg_proxy` (`command_line_args.h:97`). `net_node.inl:926-935` sets the public zone's `m_connect = socks_connect` | **Carry as a dial duty.** The clearnet connector can dial through a SOCKS proxy the operator configures. The daemon speaks SOCKS. How the operator reaches that proxy, including a non-loopback address, is the operator's job (D14, settled: accept). It changes no declared capability. Clearnet still needs the Noise layer because its declaration has no native encryption. |
| `--tos-flag` / IP Type of Service | `net_node.cpp:182`, default `-1`. Applied at `net_node.inl:597` and `set_tos_flag` `:3378-3383` (a `-1` returns without storing). Every socket still calls `setsockopt` at `abstract_tcp_server2.inl:966-976`. The static `m_default_tos` (`connection_basic.cpp:121`) is zero-initialized, so the default path sets TOS to 0 | **Refuse (D14).** TOS is the Type of Service byte, DSCP plus ECN, in cleartext on every packet. A chosen value is an operator-made fingerprint. Do not call `setsockopt`. Packets carry the operating system's default. C1 records the DSCP that leaves today, when the default path sets TOS to 0. |
| `no_delay(false)` (Nagle) | Set on every socket at `abstract_tcp_server2.inl:977-982` | **Measure before deciding**, under step 7 C9. Nagle changes the record sizes an observer sees, so it is part of the record-length evidence. It is not fixed before that evidence exists. |
| FIN versus RST, linger | epee close / shutdown | **One behaviour for every failure before the channel exists:** close after zero bytes written, FIN, no linger and no RST variant. Step 7 C4 asserts those failures are indistinguishable from the far side. |
| `add_ref` / `release`, `request_callback`, `send_done` | `i_service_endpoint` | The adapter's contract (D4). Not a copy of epee's refcount. |
| Executor for invoke timers and idle handlers | `levin_protocol_handler_async.h:229` takes `get_io_context()` for the invoke timer. The pool is 10 threads (`net_node.inl:1150`) | **D6, ruled.** A socketless `io_context` is the interim until the timing engine lands. Its pool is a measured budget, not 10. |
| Serial outbound dialing | `connections_maker` at `net_node.inl:2009`, call at `:1917` | **Stays serial through cutover.** The transport layer exposes an asynchronous dial and does not choose the schedule. When and how many to dial is discovery policy, P2P-3 slice 3. The extra round trip is measured in step 7, C7. |
| SSL | `m_state.ssl` on the connection | **Refuse.** |

---

## D4 — seam contract (RULED 2026-09-25)

- **Socket admission is enforced here, at accept, in Rust.** The
  transport layer does not own the ceiling or the ban entries. It
  applies the values it is given. It does not call into C++.
- **Channel established is per connector.** On clearnet it is Split,
  after message 2. On Tor it is SOCKS CONNECT succeeding, or an accept
  on the forward listener. The one-flight pre-channel byte limit is
  clearnet's. Nothing above the transport can see a connection that
  has no channel.
- **No C++ object exists before the channel is established.** The
  connector owns the socket from accept or dial. The C++ Levin handler
  and connection context are created when the transport handshake
  finishes. The Levin handshake clock therefore starts there.
- **`connect` toward `net_node` is synchronous in shape.** It returns
  after the channel is established, or fails with its D12 cause.
- **One connection's bytes are delivered in stream order, one delivery
  at a time.**
- **The connector supplies only observed endpoints.** For a clearnet
  socket that is the peer address. For Tor and I2P inbound, the
  observed truth is "this zone, no address". It is never the loopback
  socket the local router accepted on. A C++ object created at channel
  established receives that observed endpoint, not `127.0.0.1`.
- **Tasks, not threads.** Transport-layer tasks post into the C++ executor.
  Delivered buffers are bounded by a read window. A C++ call does not
  block a transport-layer task. A transport-layer task is never the last
  owner of a C++ object. The C++ object is destroyed on the executor,
  never on a transport thread.
- **No keys, handshake hash, or transcript value crosses upward.**
- **A refused delivery closes the connection.** If the C++ side declines
  a buffer, the connection ends with the D12 cause for that refusal.
  The connector does not drop the buffer and keep reading. A full send
  queue closes the connection with `SendQueueFull`.
- **Close from either side is idempotent** and records exactly one
  cause. On a simultaneous close, the first recorded cause wins.
- **FFI (rule 40).** Every call names its direction and who owns the
  buffer. A callback context is not a raw `this`.

The parked branch's `on_plain` nonzero path is this contract, not code
to keep.

---

## D5 — runtime ownership (RULED 2026-09-25)

One place in the daemon constructs every runtime. The transport layer
gets its own runtime, with a stated thread budget. The budgets are
explicit and have to add up to something the Pi-4 can carry. The
numbers come from measurement, not from this ruling.

The transport layer faces attackers: any peer can drive its load. The
RPC and Tor-control runtimes serve the operator. A tokio multi-thread
runtime has no task priorities, so a shared pool would let a peer flood
starve wallet RPC, and the reverse. Separate runtimes contain that.

Today each subsystem builds its own runtime. Two already do
(`shekyl-daemon-rpc` `ffi_exports.rs:162`, `shekyl-tor-control-daemon`
`blocking.rs:120`). A multi-thread runtime defaults to one worker per
core, so a third unbudgeted runtime on a 4-core Pi-4 is twelve workers
plus blocking pools. The transport layer does not add one that way.

---

## D6 — the executor above the transport (RULED 2026-09-25: a bounded interim)

**Context.** Once the transport layer owns the sockets, the C++ that
stays above the seam still needs something to run on. Today that is a
single asio `io_context`. It belongs to the public zone, and Tor's zone
is built on the same one (`add_zone`, `net_node.inl:805`). Its pool is
a hard-coded 10 threads (`:1150`). It hosts:

- Levin's invoke timers (`levin_protocol_handler_async.h:229`). The
  synchronous invoke path is deleted under D3.
- The 1-second idle cadences for `net_node`'s `idle_worker` and the
  cryptonote handler's `on_idle` (`net_node.inl:1146-1147`).
- Each zone's relay notifier. Each is constructed with this
  `io_context` and `get_config_shared()` (`:483`, `:642`, `:890`) and
  serialises through a per-zone strand.
- All message handling triggered by `handle_recv`, including the
  cryptonote handler.
- The per-connection ordering D4 requires: one delivery at a time.

**Ruling.**

1. **A socketless `io_context` is a bounded interim.** It lasts from
   the transport-layer cutover until the timing-engine round lands,
   not until LV-3. While it lives:
   - there is one executor for all networks;
   - its pool is built by D5's single constructor, with a measured
     budget that counts toward the Pi-4 total, replacing the
     hard-coded 10;
   - it hosts the full list above;
   - the only C++ executed on a transport thread is posting work to it;
   - shutdown runs in this order: the transport stops accepting, the
     transport cancels its tasks, the executor drains posted work, the
     executor stops.

2. **The timing engine, which is the next round, owns every deadline
   in Rust:**
   - Levin's invoke timeouts. C++ keeps the pending-invoke state; Rust
     arms and cancels each timeout and reports expiry by id.
   - The idle cadences.
   - The relay `Driver`'s sleep.
   - PWD-B2's per-connection timed-sync deadlines.

   After it lands, C++ is called, not driven. C++ work runs on a
   budgeted blocking pool owned by Rust, never on an async worker
   thread, with one delivery at a time per connection. The asio
   `io_context` is then deleted, and C++ has no event loop. That
   resolves D1's second violation.

3. **Relay dispatch moves to Rust in its own round, which is LV-3's
   step d brought forward.**
   - It carries out `shekyl-relay`'s `Driver` effects by writing
     directly to transport-layer connections by id. The stem map and
     connection events are already in Rust.
   - Rust builds relay messages with `shekyl-levin`, an exception to
     D14 item 3 scoped to relay messages. Two conditions: each
     submission is a whole message, and there is a single writer per
     direction.
   - The crate already provides the header (byte-pinned against C++'s
     `make_header`, `tests/oracle_kats.rs`), the `notify` builder
     (`message.rs:25`), typed `NewTransactions` (2002) and
     `NewCompactBlock` (2008) with encode and decode, and compression
     and cover-traffic emission, which are already live.
   - **Gate:** before Rust sends a single relay message, the 2002 and
     2008 payloads must either match the C++ serializer byte for byte,
     or pass the dual-stack run (`tests/dual_stack.rs`, made a hard
     gate: Rust emits, a C++ node accepts and relays). Today's payload
     tests are only Rust-to-Rust round trips.

**Why.**

- The relay lane's reason 2 prescribes this, and names when it applies
  (`shekyl-relay-privacy/src/lib.rs:117-146`). Relay timing decisions
  are already Rust's (`shekyl-relay/src/driver/mod.rs:6-13`); only the
  sleep is asio's. Reason 2 keeps one reactor in the p2p path and says
  the reactor moves when the C++ relay path is removed. The transport
  cutover by itself puts a tokio runtime next to asio, which is the
  two-reactor seam reason 2 warns about. This ruling keeps that seam
  short and then removes it.
- Isolation needs both halves. With only the timers in Rust, a relay
  timer would fire on time but its send would still queue behind block
  validation in the C++ pool. With timing and relay dispatch in Rust,
  Dandelion++'s timing and sends never wait behind work an attacker
  can generate.

**Evidence required.**

- Relay conformance grades. The existing statistical grades must pass
  unchanged when the sleeper moves. Only who sleeps changes; the draws
  stay in `shekyl-relay-privacy`.
- Timer lateness under load. Step 7's C6 gains a measurement of how
  late relay timers fire under peer-driven load, taken both on the
  interim and after the timing engine lands. The interim's pool budget
  and the blocking pool's budget both come from it.

**The register.** P2P-3 §4.2 gains two rows, in this order: the timing
engine, after the transport layer; relay dispatch, after the timing
engine. LV-3 keeps steps a–c: the connection type, ownership transfer,
and the registry. LV-3 §6.3 falsifier 3 has already fired, and this
extends that record. The cryptonote handler (3,213 lines, the
register's "(open)" row) runs on the Rust-owned blocking pool once the
timing engine lands, so deleting the executor no longer waits on it.
Its replacement still has no owner, and the row stays visible.

**Falsifiers (rule 21). Reopen this ruling if:**

- any C++ component must block on a timer or an event loop, and so
  cannot be simply called;
- the relay conformance grades degrade after the sleep moves to Rust;
- the timing-engine round has not opened by the time transport-layer
  implementation starts. The interim is bounded only if its end has
  been scheduled.

---

## D7 — capabilities are data (RULED 2026-09-25)

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
| Addressing | IPv4/IPv6 + port. Plain clearnet: no assumption about how the operator routes it | onion v3. Peers are onion services. No exits. Traffic does not leave Tor onto clearnet | `.b32.i2p`; not assessed further |
| Encryption of the byte stream against the network observer | none native — **Noise layer added** (hybrid PQ). Encryption only: the peer's address and port stay visible, and traffic patterns stay observable | native, end to end to the peer's onion service, classical only (accepted) | native; not assessed further |
| Destination authenticated to the dialer | no. Noise NN gives no peer authentication | yes, one way. An onion address is the service's public key, so completing the rendezvous means the dialer reached the holder of that key. The service learns nothing about the client | not assessed |
| This node's address hidden from the peer | no | native | native |
| Destination hidden from an observer at this node's end | no | yes. That observer can see that Tor is in use, not the destination | not assessed |
| This node's address hidden from an observer at the peer's end | no | yes | not assessed |
| Correlation by an observer at both ends (timing, volume) | **not provided** | **not provided** | **not assessed** |
| Connection existence, timing, volume, sizes visible to an observer at this node's end | **visible** — sizes pending the record-length direction (D14) | visible as Tor traffic (cell-quantised sizes) | not assessed |
| Origin of relayed transactions, against peers | **not provided by any connector** — taxed by Dandelion++, not eliminated | same | same |
| Stream semantics | TCP | Tor stream | streaming library |
| Observed identity of an inbound peer | the socket address | "this zone, no address" | "this zone, no address" |
| Inbound peer has a bannable address | yes | no ("this zone, no address") | not assessed |
| Deadline inputs (D9) | measured per connector | measured per connector | measured per connector |

Consequences:

- **Clearnet is plain clearnet, plus the Noise layer.** The declaration
  is what clearnet provides natively. It says nothing about how the
  operator routes it. The stack includes Noise because clearnet declares
  no native encryption. Noise supplies encryption. It benefits
  confidentiality and does not create it: the peer's IP address and
  port stay available, and traffic can still be monitored by volume and
  by the other connections. The option-off path is a stack
  that does not meet the contract. The flip is "enforce the contract".
  There is no mode that accepts both the Noise prefix and plaintext on
  one port. `noise.rs`, `channel.rs`, `prefix.rs`, and `aead.rs` are
  that layer. The HMAC implementation and the NN oracle live on
  `fix/p2p-transport-hmac-oracle`.
- **Tor is a complete overlay, not a VPN.** The Tor connector speaks
  onion to onion. Peers are onion services, so traffic never leaves Tor
  onto clearnet. Encryption is end to end to the peer's service, and
  classical only, which is accepted. The destination is authenticated
  to the dialer, one way, as the table says.
- **Deadlines are per-connector data** (D9). A network with seconds of
  mixing delay would break one global handshake deadline.
- **Stream semantics are a capability.** A future message-shaped
  network would need a stream layer (ordering, reliability, framing).
  That is the interface's stress test. This round does not design that
  layer.
- **A precondition we can check is checked.** A completed handshake is
  one. An overlay's own cryptography is a trust assumption with its
  concession. Tor's is classical-only. The daemon does not police the
  path an operator uses to reach a SOCKS router.
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

## Network partitions (RULED 2026-09-25)

Decoupling must not erase separations that are privacy properties.
These partitions exist today, and each one stays:

- Relay and Dandelion++ run per zone.
- Self-detection nonce windows are zone-scoped (PWD-I1).
- `m_our_address`, and what is advertised, are per zone.
- Admission counts are per zone.
- Peerlists, and what peer exchange returns, are per zone.
- Seed nodes are per zone.

Separately, origin-zone priority is hidden in `enum class zone`'s
ordering (`enums.h:53`: "order from here changes priority of selection
for origin TXes"). That is a cross-network selection rule, not a
partition. It survives decoupling as explicit, named policy.

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

## D8 — socket count (RULED 2026-09-25)

The transport layer owns the count of live sockets, per network and per
direction, including sockets that have no channel yet. That count is
what socket admission reads. The Levin registry is not consulted.
`census_inbound` (`net_node.inl:3158`) and the monitor walk at `:1125`
are the knot this replaces. There is no second count.

---

## D9 — deadlines are derived per connector (RULED 2026-09-25)

The transport handshake's 15 s on the pipe, the 5 s dial timeout, and
the 10 s / 5 min inherited timers are not transport-layer constants.
Deadlines are derived **per connector**. Inputs, when they exist:
flight sizes (1,224 and 1,160 bytes on the wire, prefix included), the
Pi-4 crypto cost from step 3, and RTT measured on that connector. A
single global handshake deadline would break on a network whose mixing
delay is seconds. No deadline is written into this document before that
measurement. Rule 26 B9.

---

## D10 — pre-channel bounds (RULED 2026-09-25)

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

## D11 — test gates (RULED 2026-09-25)

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

## D12 — one failure cause, both directions (RULED 2026-09-25)

Every connection ends with exactly one typed cause, logged once, on
both the dialing side and the accepting side. The table is defined
once and exported to C++ through the FFI header. There is no second
hand-kept copy.

| Phase | Causes |
| --- | --- |
| Before the channel exists | `PrefixMismatch`, `TransportHandshakeFailed`, `TransportTimeout`, `AdmissionRefused`, `DialFailed`, `ProxyRefused`, `LocalClose` |
| Channel exists, Levin handshake not done | `LevinHandshakeTimeout`, `LevinHandshakeRejected`, `LocalClose` |
| Any time after the channel exists | `PeerClosed`, `RecordRejected`, `SessionRefused`, `IoError`, `SendQueueFull`, `LocalClose` |

`SendQueueFull` is a send queue that cannot take another buffer. The
connection closes. It is not a dropped write.
`AdmissionRefused` is a ban-list or inbound-ceiling refusal at
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

## D13 — deletions at cutover (RULED 2026-09-25)

Each of these goes at step 6, after the differential harness passes.
The check is an `rg` that returns nothing, and that `rg` is written
into the cutover PR only after a search shows no other consumer.
The set:

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

Deleting `src/net/socks*` removes the C++ I2P path (`zone::i2p` and the
`--tx-proxy` handling that dials it). I2P support is removed until an
I2P connector is built. The cutover PR states that. It is not a silent
deletion (rule 15). D14 records the same ruling: clearnet and Tor cut
over together.

---

## D14 — rulings (RULED 2026-09-25)

1. **Runtime ownership** (D5). One daemon-level place constructs every
   runtime. The transport layer has its own, with a stated thread
   budget. The numbers are measured against the Pi-4 floor.
2. **Overlays.** Clearnet and Tor cut over together. Staging would
   leave epee's socket-bearing server beside the transport layer.
   I2P's C++ path is removed with epee's SOCKS code, and the cutover
   PR says so, until an I2P connector exists.
3. **Levin framing stays C++ through cutover and moves with LV-3.**
   The adapter already passes bytes, so the transport layer never sees
   a command. Moving framing now would edit `async_protocol_handler`
   twice, and the differential harness would no longer have transport
   as its only variable. `shekyl-levin` is the framing LV-3 inherits.
4. **Record framing and rekey, direction set, sizes measured.**
   Framing is fixed-window. The window size is derived from C9's
   measured size distribution. Until that measurement, the option uses
   BOLT-8 framing, which hides the length field and still leaves a
   burst visible as a message size. Fixed windows hide the size down
   to a count of identical windows, reuse `fragment.rs`, and make one
   window one record: no length field, one nonce per record. The
   PWD-T8 vectors are re-minted when the window size is derived.
   Rekey is every record if C5's Pi-4 benchmark shows three
   HMAC-BLAKE2s per record are affordable beside seal cost. A
   count-based interval lets a quiet link keep one key for a session,
   and a later memory capture then exposes every transaction that key
   sealed. If C5 shows the cost is a meaningful fraction of seal cost,
   the interval is derived from C9's measured record rates instead.
5. **The local/remote timer split is refused** (D3).
6. **`--tos-flag` is refused** (D3). No `setsockopt` for the Type of
   Service byte.

A non-loopback SOCKS address is accepted. Configuring the path to a
router is the operator's job. The daemon speaks SOCKS and does not
police that path. That question is not an open item.

---

## D15 — falsifiers (RULED 2026-09-25)

Re-cut the transport layer, rather than follow this plan, if any of these
is observed:

1. **A transport duty needs to walk connections.** The registry is
   then not where D0 says it is, and LV-3's registry step is being
   pulled into the transport.
2. **Levin cannot run on an `i_service_endpoint` adapter** without
   changes beyond that endpoint.
3. **Another piece of the daemon grows its own socket owner** while
   this round is open.
