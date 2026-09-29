# P2P transport layer — Rust connectors in place of epee's TCP server

**Status: CLOSED — Round 4, 2026-09-25. D1–D15 RULED.** The design is the spec for
implementation. Round 1 was pinned to `dev`
`db2788d164660003948376ba369fa396c5f4c482`. Round 2 re-read that pin.
The 11 commits `dev` gained after it are S-POOL / chain-store and do
not touch epee, `src/p2p`, `src/net`, the transport crate, or the
protocol docs, so Round 1's anchors still hold. **The deliverable of
this round is a design, not code.** Implementation does not start until
the round closes. **Pre-flight discharged 2026-09-26** at `dev`
`0aa207208` (rule 26). Production code follows that record. The
service is the first of it. Target is 4–6 review rounds (rule 20). **Rule 26 is
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
| 5 | Transport-layer implementation, then a differential harness against epee. The thread budget and the per-connector deadlines are measured on this build | Code, after the round closes |
| 6 | Cutover, one branch (ruled 2026-09-28): zone binding, the operator link budget, the call sites that move with them, the cross-build and the measurements on that build, then the deletions and the goldens. Merges once, when the run records are in | Not a flag day (D11) |
| 7 | Option evaluation: window size, rekey cost, Nagle, flood. Not the source of the cutover numbers | Evaluation record |
| 8 | The flip | Flag day (rule 07), only after step 7 |

The scaffolding-deletion FOLLOWUPS row is step 2, a separate doc PR.
Its owner is [`SHEKYL_P2P_PROTOCOL.md`](SHEKYL_P2P_PROTOCOL.md), which
is the wire spec and is already on `dev`. Target: pre-genesis. D13 is
what that row deletes.

---

## 0. Status

The design round is closed. D6 is ruled: a socketless `io_context` is a
bounded interim that ends when the timing engine lands, not at LV-3.
The seam note (2026-09-28) is the construction contract for the build
that sits between the connectors and the harness. It measures nothing
and deletes nothing.

What is not a number yet is named in the section that owns it: deadline
values (D9) and the executor's thread budget (D6), both measured on
the cutover build and written as run records before the deletions, and
the fixed-window size and whether
every-record rekey is affordable (D14 item 4), measured in step 7.
Those measurements do not reopen the direction. Step 7 is option
evaluation. It is not an identifier family; this document mints none.

The wire spec is `SHEKYL_P2P_PROTOCOL.md`. It carries the framing
direction. This document does not.

Three requirements from the parked pipe branch (`190cbdc3b`) are in
force. The transport layer does not repeat the mistakes:

1. **Failure causes cover the whole connection, both directions** (D12).
2. **One source for the cause table** (D12).
3. **A descriptor test counts the socket, not the process** (D11).

## Pre-flight — DISCHARGED 2026-09-26

Rule 26, between design closure and the first production line. Pin:
`dev` `0aa207208`, the merge of #870. This is not a new round. The
record is this section, the same shape as the timing-engine pre-flight:
the findings are a substrate confirmation and a sequence, not a
redesign, so they do not mint `R0-D` ids.

**The rulings are sufficient to start.** D1 through D15 are closed.
The engine-service addendum in
[`P2P_TIMING_ENGINE.md`](P2P_TIMING_ENGINE.md) is the concurrency
contract the first line calls. C5 is recorded: the responder handshake
is 685 µs, one rekey is 5.06 µs, seal and open of a 65,535-byte record
is 889 µs. No accept-rate (D10.3), no per-connector deadline (D9), no
transport-runtime thread count (D5), and no every-record rekey (D14
item 4, decided with C9's window) is written. The implementation does
not invent those numbers.

**The tree matches the citations that the first line will rely on.**
Fifty-six `file:line` citations in this document fall inside their
files at this pin. Re-read, and still the values the design states:
`P2P_DEFAULT_CONNECTION_TIMEOUT` is 5,000 at `cryptonote_config.h:189`;
the 5 s at `:193` is `P2P_DEFAULT_HANDSHAKE_INVOKE_TIMEOUT`, and the
general invoke at `:192` is 2 minutes — D9 already refuses to copy
either into a transport deadline. `NEW_CONNECTION_TIMEOUT_LOCAL` is
1,200,000 with the comment still saying "2 minutes"
(`abstract_tcp_server2.inl:60-61`). The send queue is 1,000 messages
and 100 MiB (`abstract_tcp_server2.h:72-73`). The asio pool is 10
(`net_node.inl:1150`). The daemon-rpc runtime is still the default
multi-thread builder (`ffi_exports.rs:162`). Tor control still sets
`.worker_threads(1)` (`blocking.rs:120`). `Driver::next_wake` is
`driver/mod.rs:158`. `shekyl-p-fetch` and `shekyl-rpc-transport` dial
through `shekyl-socks`. `shekyl-p-transport` still enables ureq's
`socks-proxy`. D6's third falsifier does
not fire: the timing-engine round opened 2026-09-25.

**What is built, and what the first commit is.** The crypto core is
`shekyl-p2p-transport`: `noise`, `channel`, `prefix`, `aead`. HMAC is
`hmac_blake2s`. `read_message1` range-checks the encapsulation key and
`ResponderReady` stores the parsed key. `OnionPow`'s default is
`Enabled`. `InboundCeiling` is in `shekyl-peer-policy`. The timing
core is `shekyl-timing-engine`. *Records-was, at this pre-flight: the
service was not in that crate, and `Engine::register` minted
`OwnerId`.* The service has since landed as `EngineService`.
`IdSource::mint` returns an `OwnerMint` that `register` consumes, so
an id is not reused and a stale heap hint cannot match a new owner.
Connection deadlines are owners
of the service from the first transport line, so the service was the
first production commit. *Records-was, at this pre-flight:* a Rust
ban list was not in the tree. D3 already rules it; the logic-core
increment builds it and does not wire it. `pipe.rs` stays. The
pipe branch stays `fix/clearnet-pipe-option-testing` at `190cbdc3b`.
The `io_context` stays until the bridge after cutover. I2P removal is
the cutover's statement (D13), not this commit. *Records-was, at this
pre-flight:* the step-3 fuzz targets (`read_message1`, `read_message2`,
`open_one`) were not in the tree. D11 carries them as gates of this
implementation. They are not a reason to wait before the service.

---

## Logic core — LANDED (PR #875, 2026-09-26)

Rule 26 is cited. This is not a new round and not a second pre-flight.
The pass above is discharged. This note is the scope of the first
transport increment.

The crate is `shekyl-transport-layer`. It depends on
`shekyl-net-address`, `shekyl-p2p-transport`, and
`shekyl-timing-engine`. `shekyl-net-address` is the address union.
`shekyl-levin` implements the portable-storage codec for that union
and does not depend on the transport crate. The transport crate does
not depend on Levin. `shekyl-p2p-transport` stays the Noise layer: no
connector and no socket loop. `Responder::read_message1`,
`Initiator::read_message2`, and `RecvHalf::open_one` are public so the
D11 fuzz targets can call them. Those targets live beside that crate.

In this increment:

- Connector declarations are data (D7). The addressing cell selects
  the connector. I2P is a column and not a connector. A cell nobody
  has assessed reads "not assessed". The dial rule reads that cell:
  onion v3 for Tor, an IP address for clearnet, and anything else is
  `DialFailed`.
- The stack plan reads the encryption cell. Clearnet declares no
  native encryption, so the plan adds the Noise layer. Tor declares
  classical encryption, so the plan adds nothing. Levin is the session
  above that plan. It does not match on the connector, and adding
  Noise to a connector does not change how Levin reads the stream.
- Socket admission is a count, not a socket (D4, D8). Accept reserves
  one slot against `InboundCeiling` in the same step as the increment.
  Close releases that slot once. Occupancy is per connector and
  direction. The process-wide ceiling is the sum of every connector's
  inbound row, and that list is the connector list.
- The ban list holds IPv4 subnets and host addresses. Expiry is checked
  when an entry is looked up. A new ban closes live sockets to that
  host. Nothing in the RPC calls it yet. That call is the seam, when
  Rust owns the sockets.
- One `CloseCause` is the D12 table. The discriminants in
  `src/shekyl/close_cause.h` are generated from that enum, and the
  header's size and field offsets are the `repr(C)` struct's.
  `shekyl_ffi.h` includes it. The test fails if the header drifts, and
  the C++ build fails if the typedef no longer matches that layout.
  There is no second table to edit.

Not in that increment: sockets, a thread count, a deadline, an accept
rate, the seam, the differential harness, and cutover. The constructor
is the next section. Moving the daemon-RPC and Tor-control runtimes
onto it stays a follow-up of the constructor, not a precondition.

## Runtime constructor — this increment (2026-09-26)

The ledger is [`shekyl-thread-ledger`](../../rust/shekyl-thread-ledger/src/lib.rs).
It has no Tokio dependency. [`spawn_dedicated`](../../rust/shekyl-thread-ledger/src/lib.rs)
starts one OS thread and returns a `DedicatedThread`, which owns the
`JoinHandle`. Joining or dropping that value removes the row after the
thread has been joined. `join` takes `&mut self`, so a second caller
cannot return while the first join is still in progress. The row's kind
is `DedicatedThread`: one thread, and no blocking pool. A zero blocking
cap is not that fact. Tokio refuses a blocking cap of zero, and a
dedicated thread is not a Tokio runtime. [`LedgerId`](../../rust/shekyl-thread-ledger/src/lib.rs)
is the row's identity. The name is a [`ThreadName`](../../rust/shekyl-thread-ledger/src/lib.rs):
non-empty, no interior NUL, and it may be shared. The report orders a
shared name by budget, then by `LedgerId`.

[`runtime`](../../rust/shekyl-runtime/src/lib.rs) takes a
[`RuntimeBudget`](../../rust/shekyl-thread-ledger/src/lib.rs) — worker
count and blocking-pool cap, both required — and a `ThreadName`, and
builds one multi-thread runtime. The pool holds a `RuntimeRow`, which
has no join. [`Pool::shutdown`](../../rust/shekyl-runtime/src/lib.rs)
takes a timeout and waits at most that long for a blocking task, then
the row leaves. Drop is the unbounded fallback: Tokio waits forever for
a `spawn_blocking` task that is still running, and it panics if that
wait happens inside an asynchronous context. A pool is never dropped
from inside a task. On drop the runtime field is first, so the row
covers that wait too. The timeout is the caller's. This crate does not
contain one. A blocking task still running when `shutdown` returns
keeps its OS thread. That thread is detached and the row is already
gone, so the ledger undercounts until the thread exits. At process
exit that does not matter. A pool shut down and replaced while the
daemon keeps running omits those threads from the next total.

Tokio's unset worker count (one per core) and its blocking cap (512)
are the defaults D5 refuses, so neither number lives in either crate.
The runtime enables the I/O driver and the time driver. `net` and
`time` are on for that.

[`report`](../../rust/shekyl-thread-ledger/src/lib.rs) is the one line:
each row, then the total of workers, blocking caps, and dedicated
threads. The daemon prints it once every runtime it builds comes from
`runtime`. The daemon-RPC builder at `shekyl-daemon-rpc`
`ffi_exports.rs:162` and the Tor-control builder at
`shekyl-tor-control-daemon` `blocking.rs:120` still construct their own,
so the print is not wired. A total taken while those builders are off
the ledger would omit the pools the sum exists to count. The move and
the print are one FOLLOWUPS row, owned by this document. The clearnet
connector is the first caller that keeps a runtime. Its blocking cap,
shutdown timeout, and handshake span are the caller's, each labelled
unmeasured; measurement replaces those values.

## Clearnet connector — handshake cryptography (RULED 2026-09-27)

A responder handshake is 685 µs of CPU on the Pi 4 (C5). That work runs
on the runtime's blocking pool, not on an async worker. A worker that
computes the handshake holds that worker for most of a millisecond, and
under a flood the accept loop and every other connection's I/O wait
behind it. Worker threads stay on I/O and deadlines. The blocking cap is
the bound on how many handshakes compute at once, in addition to D10's
accept-rate bound. No accept rate is written here.

**The handshake queue is bounded by admission, not by Tokio.**
`spawn_blocking` queues without limit once the blocking cap is busy.
A handshake is queued only for a connection the inbound ceiling has
already reserved. The queue cannot outgrow those connections. A length
on the Tokio queue would refuse a handshake the ceiling had admitted,
or admit one the ceiling had refused, so the queue is not given a
length that rejects. The same shape as the timing engine's mailbox:
admission bounds how many owners exist, and the queue does not apply a
second cap.

**A dequeued job checks the deadline before it computes.** Under a
flood many connections pass their pre-channel deadline while the job is
still queued. A job that starts on a dead connection spends 685 µs for
nothing. The job checks at dequeue and skips. `HandshakeTally` counts
computed against skipped. D10's flood test reads that pair.

**The deadline includes the time spent queued.** One
`OwnerClass::Transport` owner per connection, armed at accept, not when
computation starts. The home awaits that owner's wake
(`wait_wake_async`). A Tokio timer on the transport runtime is not the
deadline. A deadline that started at dequeue would let a flood keep a
connection alive for as long as the queue held it.

One descriptor per socket is a test assertion (D11). The accept path
does not walk `/proc/self/fd`. A transient `accept` error
(`EMFILE`, `ENFILE`, `ECONNABORTED`) is recorded and the listener keeps
accepting. Shutdown is what ends that loop. The outbound queue is that byte cap and nothing else. It is not an
unbounded channel with a counter beside it. The caller passes the cap,
labelled unmeasured until PWD-T6's session-established limit plus
measurement names it. `shekyl-capped-stream` is that cap and the socket
copy. Clearnet and Tor both call it. A connector passes framing in;
this crate does not know which connector it is. A send that does not
fit is not stored, and a write already in progress is cancelled with
`SendQueueFull`. The inbound reader awaits space instead of closing:
a slow consumer on this side stops reading, and TCP pushes back on
the peer. Dropping the connection's queue hold closes the cap even
when the caller still holds the session.

The dialer checks the addressing cell, then `open_clearnet`. A direct
dial connects to the address. A proxy dial connects to the SOCKS5
endpoint and asks it to CONNECT. `shekyl-socks` is that handshake.
Every call passes an isolation: `Principal` offers only no
authentication, and `Persona` offers only username/password. A proxy
that selects any other method fails the handshake before CONNECT, so a
persona cannot be dropped onto the principal's circuits. The daemon's
p2p dials, `shekyl-rpc-transport`, and `shekyl-p-fetch` pass
`Principal`. The persona-username derivation stays in
`shekyl-p-transport`, which still dials through ureq. Moving that HTTP
client onto `shekyl-socks` is a FOLLOWUPS row. The handshake keeps the
proxy's reply byte, which `ProxyRefused` carries. A refusal is
`ProxyRefused` with that byte. `ExtendedErrors` on the operator's
`SocksPort` is what makes Tor's extended codes appear. That belongs in
the operator docs. The initiator handshake runs on the blocking pool
under the same engine owner, armed when the socket exists.

The Tor connector is `shekyl-tor`. The stream is the channel: no Noise,
no handshake on the blocking pool. It uses the same byte cap and the
same socket copy as clearnet. The gap is an arm of that wait. Holding
the session without `session_established` is the Levin handshake
timeout. Dropping the session ends the connection and releases the
admission slot. Outbound is SOCKS5 through `shekyl-socks`, and one
engine owner covers that exchange, the circuit build, and rendezvous.
Inbound is `accept_tor`, then that wait. A listener that stops
accepting reports the cause. A failed bind drops every listener that
succeeded, so the zone is not inserted. Onion-service proof-of-work
and `MaxStreams` are the accept bound. Publication is one `ADD_ONION`
through `DaemonTorControl` with proof-of-work on. `PowRefused` is not
followed by a publish without proof-of-work. Any other publish failure
leaves the zone outbound-only. The address is what the session layer
stores as `m_our_address`. That address is the listener's `ForwardAddr`,
minted from the loopback bind. An `--anonymous-inbound` bind is
`OperatorInbound`. It does not convert into `ForwardAddr`, so it is
not a publish target.

Before the flip, ruling 4's exception is still in force. The option off
omits the Noise layer the declaration adds, and the socket bytes are the
session bytes. The differential harness compares those Levin bytes and
the session result, as the seam section states.
The option on follows the stack plan: clearnet's plan is Noise, and that
is what step 7 evaluates. Neither arm matches on a network's identity.
The worker count, the blocking cap, the shutdown timeout, and the
handshake span are the caller's, labelled unmeasured until a measurement
names them.

## Seam — construction contract (RULED 2026-09-28)

Both connectors are in. The seam is the handler boundary they attach to:
one `Sockets` table, the connector's `Session`, and the posts onto that
connection's strand. A `Dial` is how a channel is born. Zone bind, which
installs the connector dialer and runs `drive_inbound` on the transport
runtime, is the cutover and is not in this change. The loopback dialer is
the strand harness: it admits on the hub's table and discards outbound
bytes. It is not a connector. epee still owns every production socket.
This note is the build before the differential harness and the cutover.
D4 and D6 stay the rulings. What follows is how those
rulings are built, including the three points the seam has to settle.
No measured thread budget, deadline, or accept rate is written here.
The executor's floor is counted from the lanes that block on it.

**Our types come first (2026-09-28).** Rust and the FFI are shaped by
the rulings: the typed address, the observed endpoint, "this zone, no
address", the D12 causes, and the capped queue. An IPv4 address on
the FFI is its four octets in network order. The C++ adapter copies
those bytes into the address word the code above the seam reads.
`seam_link`, those conversions, and the `i_service_endpoint` methods
are interim translation. They stay thin, and they go when LV-3
replaces what sits above the seam. Nothing in the adapter shapes a
Rust type.

**Harness parity is the wire and the session result (2026-09-28).**
The differential harness checks that a peer sees the same Levin bytes
and gets the same session result. Its document lists these
divergences first, and a difference on one of them is expected:

- deadlines derived per connector;
- typed close causes, the first cause wins, and FIN after zero bytes
  written;
- admission in Rust, the check and the reservation in one step;
- no local/remote timer split;
- no TOS knob;
- send and receive bounds in bytes.

**A decision cites a ruling (2026-09-28).** The strand exists because
D4 requires one delivery at a time, in order. The executor exists
because C++ still runs above the seam until the timing-engine bridge.
A reason that can only be stated as what the stack being replaced
did is where the design stops.

The id that crosses the boundary is the admission `SocketId`. C++
learns it when the channel exists. A socket that dies before that
never publishes an id. Rust holds no C++ pointer. C++ holds no Rust
pointer. The pipe's `ctx` callback, invoked on the reader thread, is
the arrangement this contract replaces.

**Close.** The transport layer owns the socket. C++ owns the Levin
handler and the connection context. Neither side's destructor calls
the other. The executor owns the per-connection strand and the
`seam_link`. The link owns the handler until the destroy post. That
post drops the handler only: it is not the last owner of the link,
and it does not free the strand. The executor drops the link after
the post has finished. A walker whose `add_ref` returned true still
holds a count, so the destroy post has not run.

- Rust records the D12 cause through `Sockets::close`. The first
  `CloseResult::Recorded` wins. `AlreadyClosed` leaves that cause
  where the first call put it.
- Rust then drops the socket and posts `closed(id, cause)` onto that
  connection's strand. The post carries the id and the cause. After
  the socket is gone, a C++ `send` or `close` for that id finds no
  socket and returns false.
- The strand runs `closed` only after every `deliver` already posted
  to it. `closed` calls `release_protocol`
  (`levin_protocol_handler_async.h:390`). That swaps out the invoke
  list and `cancel` runs `finish_outer_call` on this stack
  (`:271-277`). The outer-call count and the adapter's `add_ref` /
  `release` are one pair: `start_outer_call` (`:371`) does both,
  `finish_outer_call` (`:382`) undoes both.
- Destruction is one later post on the same strand. `closed` posts it
  when the count is zero after that inline cancel. A completion that
  was already queued still holds the count, and the
  `finish_outer_call` that lands on zero posts destruction, once.
  The strand runs one handler at a time, so `handle_recv` has
  returned before the destroy post starts. Nothing sleeps on the
  count. Sleeping inside `closed` would hold the strand the
  completion has to run on, which is the deadlock the floor exists
  to keep off the idle lane. A timeout that destroys a handler still
  inside `handle_recv` is not added.
- A `deliver` posted before `closed` runs first, and the handler
  parses those bytes. A `deliver` that finds the handler already
  destroyed is refused and is not parsed. A test that posts a
  `deliver` before `closed` and finds it refused has found an
  ordering bug.
- C++ `close` is an id lookup into Rust. It does not free the handler
  inside that call. The closing bit and the call count are one atomic
  word. `add_ref` fails when the bit is set, so a new outer call does
  not start. `begin_closed` sets the bit and reads the count at that
  instant. Destruction stays the post above. The adapter does not keep
  epee's `shared_ptr` bump (`abstract_tcp_server2.inl:1461`).
- `handle_recv` returns false when it refuses the buffer, and also
  when its own response send fails
  (`levin_protocol_handler_async.h:596`). A false return records
  `SessionRefused` only when `Sockets::close` returns `Recorded`.
  `AlreadyClosed` leaves the earlier cause. The bytes are not
  delivered again. A true return, including a short read the parser
  has buffered, releases the read window.

**One strand per connection.** The executor is one `io_context` with
several threads. asio does not order two posts onto that context:
two `deliver`s for one connection can run together or out of order,
and `closed` can run before the last `deliver`. The Levin reader
needs the bytes in order. D4 requires one delivery at a time, in
order, which is why each connection has its own strand. *Records-was:
the stack being replaced posted on a strand
(`connection_basic.hpp:115`, `abstract_tcp_server2.inl:416`).*

Each connection gets its own strand on this executor. `established`,
every `deliver`, and `closed` are posted to that strand. The handler
is created, called, and destroyed on it. `request_callback` and an
invoke-timer completion that touches the handler are posted there
too. Two connections may run at once, on two strands. The send
writer stays the transport's. Callers enqueue. D3's refusal to copy
the strand is the send path: C++ does not write the socket. The
delivery strand stays.

Handler state is touched on that strand. That is `start_outer_call`,
the invoke map, and the invoke timer. `do_handshake_with_peer` reaches
`async_invoke_remote_command2` (`levin_abstract_invoke2.h:98`), which
calls `invoke_async` (`levin_protocol_handler_async.h:882`) on the
idle thread and mutates the handler there. On the seam the idle
thread posts that install onto the connection strand and waits until
the strand has armed the timer. `start_outer_call` runs on the
strand. The idle thread then waits at `ev.wait()` (`net_node.inl:1323`).
The callback that raises `ev` runs on the strand, from `deliver` or
from the timer completion posted there. The handshake function stays
on the idle thread: posting it onto the strand would wait for a
completion the strand cannot start. The waiter holds no lock the
strand needs.

`foreach_connection` (`levin_protocol_handler_async.h:890`) is epee's
walk, unchanged. It collects handlers under the registry lock, then
calls each callback outside that lock, on the walking thread, and
hands it `get_context_ref()`, a mutable reference to the connection
context. The connection's strand reads and writes that same context.
That is a data race, and in C++ it is undefined behaviour. epee has
had it all along: the walkers and the handlers already share one
thread pool. The seam does not create it and does not make it worse.
The seam does not fix it either. Posting each read onto the
connection's strand and waiting for the answer would block a walker
on a strand from inside executor work, which is the deadlock the
floor and close-by-posting keep off this path. The fix is LV-3 step
c, the registry: the strand is the only writer, walkers read an
immutable snapshot, and a walker that must change a connection posts
that change to the strand. Step c is the first LV-3 work and it
follows the transport cutover. It does not wait behind steps a and b.
The call sites at this pin are 15 in `net_node.inl` and 2 in
`levin_notify.cpp` (`:190`, `:232`). A third mention in
`levin_notify.cpp:472` is a comment, not a call.

The transport thread's only act toward C++ is the post onto that
strand. Idle handlers stay on the context. They are not per
connection.

**One server per zone.** A zone whose server is the seam does not
construct `boosted_tcp_server`. Public and Tor switch in the same
cutover (D14). A bind failure, a publish failure, or a seam error
does not start epee for that zone. Tor bind failure still drops the
zone. Publish failure still leaves it outbound-only. The epee server
stays in the tree as the harness reference until D13, and production
keeps calling it until the cutover replaces that call. The reference
is a separate server. It is not a branch inside a zone that already
started on the seam. I2P gets no seam server and no new epee server.
The cutover states that I2P support is removed until an I2P connector
exists.

**The FFI is the posts, the completions, and the synchronous connect.**

`shekyl_seam_bind` takes the ceiling the caller already resolved
(`shekyl_inbound_ceiling_resolve`). It does not resolve a second one.
Replacing a binding closes the previous hub and joins its harness
threads before the next hub is published. The admission table is one
for the process, so a `reap` of an old id does not name a new
connection. One bind serves every zone: zone bind installs its dialer
with `Hub::install_dial` on that hub and does not bind a second seam.
`shekyl_seam_set_ceiling` replaces that bound when the reservations
change. `shekyl_seam_open` asks the installed dialer for a channel,
posts `established`, and waits until the handler is armed or the arm
fails. With no dialer the cause is `DialFailed`. The opener drives
inbound on a thread `reap` joins. That thread is the synchronous
connect's reader until zone bind moves the drive onto the transport
runtime, which is already a `RuntimeRow`. The loopback harness is
`shekyl_seam_install_loopback`; zone bind does not call it.

Rust posts these onto the connection's strand, and the strand runs them:

- `established(id, observed endpoint, direction, connector)` creates
  the handler and the context and inserts the id. The endpoint is the
  one the connector observed: a clearnet address, or Tor's zone with
  no address (`tor_address::unknown()`). The adapter fills
  `m_remote_address`, `m_is_income`, and the zone from that record
  before `after_init_connection`.
- `deliver(id, bytes)` runs `handle_recv`. The bytes are valid for
  the callback. C++ copies what it keeps. A true return releases the
  read window, including a short read the parser has only buffered.
  A false return records `SessionRefused` only when the id is still
  open, as the close rule above says. The next delivery is not
  posted until this one has returned.
- `closed(id, cause)` runs the inline cancel. The destroy post
  follows as the close rule above says. `cause` is the `repr(C)`
  `CloseCause` already in the FFI header.

The strand calls back:

- `handler_armed(id, ok)` — `ok` false records `LocalClose` and wakes
  the opener. A failed arm does not leave the opener parked.
- `delivery_finished(id, accepted)` — a refusal records `SessionRefused`
  only when no cause is recorded yet and `closed` has not started.
- `handler_gone(id)` — `closed` has started. A later refusal records
  nothing.
- `reap(id)` — the executor dropped the link. The row is removed and
  the harness threads are joined. The cause already rode the `closed`
  post; the table does not keep it.

C++ calls these:

- `open` keeps the synchronous shape `net_node` already uses. The
  address is the connector plus the address bytes, the same union
  peer exchange uses, decoded once into `Endpoint`. It returns after
  the channel exists and the strand has constructed the handler, or it
  returns the D12 cause. The waiter holds no lock the strand needs.
  The caller is often an executor thread. See the floor below.
- `send(id, bytes)` is exactly one whole Levin message, copied into
  the byte cap as a single unit during the call. C++ frees its buffer
  after the return. More than one context sends on the same
  connection: the handler's responses run on the connection's strand,
  and `levin_notify`'s relay sends run on that zone's strand
  (`levin_notify.cpp:464`). Concurrent senders interleave whole
  messages only. The single writer then seals those buffers in queue
  order, which is the nonce order. A message that does not fit is not
  partly queued. `send` records `SendQueueFull` with `Sockets::close`
  before it returns, so `handle_recv`'s false return finds the id
  already closed and leaves that cause in place.
- `close(id)` records `LocalClose` when no cause is recorded yet,
  then drops the socket.

Nothing else is a per-connection call. Keys, the handshake hash, and
the transcript stay in the connector.

The vtable still has the methods Levin calls. `get_io_context`
returns the one socketless context. `request_callback` posts
`handle_qued_callback` onto that connection's strand. `send_done`
returns true and does not touch the queue, which is what
`connection::send_done` does today.
`call_run_once_service_io` returns false and does not poll. D3
deletes its caller. A new caller is D15's second falsifier.

**The executor.** One `io_context`, with no acceptor and no socket.
Its threads run that context.
[`runtime`](../../rust/shekyl-runtime/src/lib.rs) is the transport's
reactor: one Tokio pool, worker count and blocking cap, recorded as
one `RuntimeRow`. The executor is a second row on the same ledger.
Its budget is [`ExecutorBudget`](../../rust/shekyl-thread-ledger/src/lib.rs),
from `ExecutorBudget::above_floor`
(`shekyl-thread-ledger/src/lib.rs:190`). The row is
[`record_executor`](../../rust/shekyl-thread-ledger/src/lib.rs)
(`shekyl-thread-ledger/src/lib.rs:474`). `ExecutorRow` does not spawn
or join. These threads have no `RuntimeRow` and no `DedicatedThread`
row. A dedicated row is one thread `spawn_dedicated` joins. A runtime
row counts a blocking cap this pool does not have. A second row for
the same threads would count each worker twice. The hard-coded `10` at
`net_node.inl:1150` is the worker count `above_floor` replaces. The
measured count stays unwritten until the cutover record.
`above_floor` is what refuses a count below the floor. Shutdown
stays D6's order: the transport stops accepting, the transport
cancels its tasks, the executor drains, the executor stops.

**The floor.** An executor thread may block on work the executor
itself performs only when another executor thread is free to do that
work. Otherwise the blocked thread is waiting for a post that nothing
will run. `idle_worker` (`net_node.inl:2217`) is that lane today. It
is an idle handler on the context (`:1146`), and it calls
`connections_maker` (`:2220`). `connect` returns only after the
strand runs `established`. `do_handshake_with_peer` (`:1243`) then
waits at `ev.wait()` (`:1323`) for the strand to deliver the
handshake response. epee has the same dependency. The hard-coded 10
hides it. A measured count that replaces 10 can expose it.

The floor is one more than the number of lanes that can block on the
executor. Today that lane is the idle lane, so the caller passes
`BlockingLanes::new(1)` and `above_floor` accepts a worker count of
2 or more. The 1 is `idle_worker`. `on_idle` returns without waiting
for a strand post, so it is not a second lane. The 1 is counted, not
measured. The floor check lives on `ExecutorBudget`. That budget has
no blocking cap, and `shekyl-runtime::runtime` does not apply it. A
test runs
`connect` and then `do_handshake_with_peer`'s `ev.wait()` from an
executor thread on a pool of that size, and both return because the
other thread runs the strand. One worker below the floor is
`ExecutorBudgetError::BelowFloor` and does not start. When the
timing-engine bridge moves `idle_worker` onto the transport blocking
pool, the lane count passed to `above_floor` drops, and this note
records the new count.

**Configuration the six calls leave to the side.**

- `block_host`, `unblock_host`, and `get_blocked_hosts` call the Rust
  ban list. A ban closes the sockets the list returns. It does not
  walk the Levin registry. RPC speaks in durations: `setbans` takes
  seconds, and `getbans` returns seconds remaining. At cutover the
  conversion is `now + duration` onto the monotonic clock, and the
  remaining time is computed back from it. No `time_t` crosses the
  boundary. A duration that does not fit a `Tick` is refused. The
  session layer is the second writer, through the same duration: ban
  this host for this long. A transport close does not write the list
  and does not call `add_host_fail`.
- Socket admission reserves inside `accept_clearnet`
  (`admission.rs:273-283`) and `accept_tor` (`:310-312`): the ceiling
  check and the mint hold one table lock. `socket_count` is the
  per-connector, per-direction snapshot `get_info` reads. It is not
  the accept decision. `census_inbound` stops being that decision.
  The ceiling's `inbound_held` is `Sockets::inbound_held`
  (`admission.rs:384`), the sum of every connector's inbound row.
  Outbound sockets stay in the process fd count. Their cap is what
  `reserved` subtracts (D8).
- A `Published` onion is written to the Tor zone's `m_our_address`.
  `OutboundOnly` leaves the address unset. `OperatorInbound` is not
  a publish result and is not written there.
- `get_info` keeps `incoming_connections_count` and
  `outgoing_connections_count` as the public zone's session counts,
  from the Levin registry. Socket counts
  (`public_incoming_socket_count`, `public_outgoing_socket_count`,
  `tor_incoming_socket_count`, `tor_outgoing_socket_count`) are not
  on `get_info` until the daemon binds the seam. A zero while epee
  still holds the sockets would read as no connections. A restricted
  caller receives zero for the session counts, as it does today.

The seam's tests are the close races and the floor. Recording a
transport cause, including `PrefixMismatch`, `RecordRejected`,
`TransportTimeout`, and `SendQueueFull`, leaves the host unbanned.
A `send` after
Rust has dropped the socket returns false. A simultaneous close keeps
the first cause. A full send records `SendQueueFull` before
`handle_recv` returns, and the false return leaves that cause.
A refused delivery with no cause yet is `SessionRefused`. A true
`handle_recv` on a short read keeps the connection. One connection's
bytes arrive in order, on its strand, with the read window stopped
until the callback returns, and `closed` runs after those
deliveries. `closed` cancels invokes inline and posts destruction.
It does not sleep. A delivery posted before `closed` is parsed.
`connect` and the handshake `ev.wait()` called from the executor on
a floor-sized pool both complete. `above_floor` with one worker
below the floor returns `BelowFloor` and records no row.
`inbound_held` counts inbound rows and leaves outbound out. The
differential harness is
[`P2P_DIFFERENTIAL_HARNESS.md`](P2P_DIFFERENTIAL_HARNESS.md), crate
`shekyl-p2p-harness`. Seed 1 is the handshake invoke. `run-seeds` drives
every seed against both hosts; `epee-host` is the C++ recorder and
takes the typed plan on its command line. The cross-build run waits
on the zone-binding commit. Cutover waits on the thread budget and the per-connector
deadlines, measured on this build and written down. The budget is
at least the floor.

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
in step 7.

The peers-monitor thread starts at `net_node.inl:1114` and walks
`foreach_connection` once a second (`:1113-1138`). It is not removed
by this round (D8). `is_host_limit` is `net_node.inl:231`. Both read
the Levin registry today. Connections that have no channel yet are
invisible to that walk.

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
ceiling, enforced in Rust at accept and before dialing. The ceiling
comes from `shekyl-peer-policy`. The ban list has two writers, both
in durations (corrected 2026-09-28): the operator, through RPC, and
the session layer, through one call that bans a host for a duration.
The session layer judges misbehaviour. The transport layer enforces
the ban. It does not score a host, and a transport close does not
call `add_host_fail`. The session layer (Levin framing and the p2p
protocol) owns session admission: may this peer have a session? That
is `network_id`, the self-detection nonce, support flags, and
PWD-B3's per-command caps, in `handle_handshake`, plus the judgment
that issues the ban call. Neither layer reads the other's state to
decide. No wall-clock time crosses that call.

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
| Accept loop, connection filter, connection limit | Filter type `i_connection_filter` in `abstract_tcp_server2.h`; admission walk `net_node.inl:231` | **Enforce socket admission at accept, in Rust, with no C++ call.** The ceiling comes from `shekyl-peer-policy`. Ban entries come from the operator and from the session layer's ban call. The transport layer does not own those values and does not score. It does not call into C++ admission. |
| Ban list | `block_host` at `net_node.inl:256`. The registry sweep that drops live connections is `foreach_connection` at `:302`. RPC callers: `core_rpc_server.cpp:193`, `:997` (`get_blocked_hosts`), `:1101`, `:1103`. Discovery's pre-dial check is `is_remote_host_allowed` at `net_node.inl:1902`. Automatic scoring is `add_host_fail` at `net_node.inl:413` | **Move the list to Rust**, keyed on the observed host, carrying IPv4 subnets and expiry. Two writers, both in durations (corrected 2026-09-28): the operator's RPC (`block_host`, `unblock_host`, `get_blocked_hosts`) and the session layer's call to ban a host for a duration. A ban closes existing sockets to that host directly. It does not sweep the Levin registry. Discovery's pre-dial check reads the same list. A transport close does not write the list. |
| Outbound dial | `P2P_DEFAULT_CONNECTION_TIMEOUT` = 5 s (`cryptonote_config.h:189`); remote new-connection timer = 10 s (`abstract_tcp_server2.inl:61`) | Carry the dial. Re-derive both clocks (D9). They are not one number. |
| SOCKS dial clock | A SOCKS dial is the proxy handshake, then the overlay circuit build and rendezvous. `src/net/socks*` has its own timeout | **Its own per-connector clock, derived under D9.** It does not inherit the timeout from `src/net/socks`. |
| SOCKS dial; `add_connection` | `net_node.inl:3618`; `src/net/socks*` (1,241 lines) | Carry in Rust through `shekyl-socks`. `shekyl-p-fetch` and `shekyl-rpc-transport` call it with `Isolation::Principal`. `shekyl-p-transport` still enables `ureq/socks-proxy` (`socks` 0.3.4). Moving that HTTP client is a FOLLOWUPS row. |
| Overlay inbound attribution | `set_default_remote` at `net_node.inl:678` (`--anonymous-inbound`) and `:885` (`tor_address::unknown()`); applied at `abstract_tcp_server2.inl:1905-1908` | **Carry for Tor now, and for I2P when an I2P connector exists (D14 item 2).** Do not attribute from the socket. Inbound arrives on the local router's loopback socket. The observed endpoint is "this zone, no address", never `127.0.0.1`. Attributing from the socket would collapse admission's per-host view into one host. This is where LV-3's OBSERVED endpoint originates. |
| Tor forward listener | `net_node.inl:863-880` | Carry. Bound to `127.0.0.1` on port 0. The OS-assigned port is read back with `get_binded_port` (`:881`) and handed to Tor control. Bind failure erases the zone (`:878`). |
| Local versus remote timers | `m_local` at `abstract_tcp_server2.inl:992`; timers at `:100-112` and `:1001-1004`. Local new-connection is 1,200,000 ms (20 minutes), not the "2 minutes" comment on `:60` | **Refuse (D14).** D2 already refuses a timeout whose only justification is that epee uses it. The class is loopback or RFC 1918, so any LAN host gets 20 minutes before a Levin session, against 10 seconds for everyone else. Container port-forwarding makes this worse: inbound peers arrive from the bridge gateway's private address, every peer looks local, and admission's per-host view collapses to one host. A test rig that needs a longer timer sets it explicitly. |
| Gap from channel established to session established | Outbound Levin invoke is 5 s (`cryptonote_config.h:193`). Inbound has the 256 KiB pre-session byte cap and then the idle timer | **A per-connector timer, derived under D9.** Once the C++ object exists, epee's new-connection timer no longer covers this gap. An inbound peer that finishes the transport handshake and then sends nothing holds a slot until the idle timer (5 minutes on the path that remains after D14 refuses the local split). Each connector owns one deadline for its peers, beside PWD-B3's byte cap for command 1001. |
| Dual-stack bind and port 0 | `init_server` at `net_node.inl:1065` takes IPv4 and IPv6 ports and addresses plus `m_use_ipv6` / `m_require_ipv4` | Carry. A port-0 bind reads the assigned port back. The Tor listener above is the port-0 case that must not abort the rest of the boot. |
| Worker pool | `run_server`'s thread count; `set_threads_prefix` | Carry the pool as a stated size, not as "however many epee used". D6 sizes the socketless executor separately. |
| Graceful stop | `send_stop_signal`, then connections drained, then `deinit_server` (`net_node.inl:1187` is one `deinit_server` site) | Carry the order: stop accepting, drain or cancel live connections, then tear the listeners down. |
| `call_run_once_service_io` | Called from `levin_protocol_handler_async.h:753`. The synchronous `invoke_remote_command2` (`levin_abstract_invoke2.h:60`) has no caller under `src/` at this pin. p2p uses `async_invoke_remote_command2` only (`net_node.inl:1270`, `:1351`, `:2802`). Tests call the async form too | **Delete**, not carry. The sync invoke path goes with it. A test-only caller found later reopens this row. |
| New-connection, idle, bytes, and aggressive timers | `abstract_tcp_server2.inl:59-63` | Re-derive each. Channel-established and session-established bound different waits. The inherited values are inputs, not the answer. |
| Rate limit and per-connection speed stats | `network_throttle*`; the pipe's `on_wire` path on the parked branch | **Operator link budget, default unlimited (ruled 2026-09-28).** The four jobs are below. Stats stay observed facts reported upward. *Records-was "Carry the limit."* |
| Send-queue bounds | 1,000 messages and 100 MiB (`abstract_tcp_server2.h:72-73`) | **Carry the mechanism, with one source, and re-derive the value.** The value is PWD-T6's session-established limit (the largest legitimate message) plus measurement. It is not 100 MiB. That inherited round number gives no memory bound once it is multiplied by the inbound ceiling. The pipe's `PIPE_PLAINTEXT_BUDGET` was a second copy and is not repeated. |
| Send backpressure and strand order | `do_send` at `abstract_tcp_server2.inl:823-870` takes `m_state.lock` and posts on `m_strand`. C++ calls it from more than one executor thread | **One writer per direction, owned by the transport layer.** Callers enqueue. They do not write the socket. Nonce order is wire order because that writer is the only one. The strand is not copied. A full queue closes with `SendQueueFull` (D4, D12). |
| `--proxy` | `daemon.cpp:156-157` passes `arg_proxy` (`command_line_args.h:97`). `net_node.inl:926-935` sets the public zone's `m_connect = socks_connect` | **Carry as a dial duty.** The clearnet connector can dial through a SOCKS proxy the operator configures. The daemon speaks SOCKS. How the operator reaches that proxy, including a non-loopback address, is the operator's job (D14, settled: accept). It changes no declared capability. Clearnet still needs the Noise layer because its declaration has no native encryption. |
| `--tos-flag` / IP Type of Service | `net_node.cpp:182`, default `-1`. Applied at `net_node.inl:597` and `set_tos_flag` `:3378-3383` (a `-1` returns without storing). Every socket still calls `setsockopt` at `abstract_tcp_server2.inl:966-976`. The static `m_default_tos` (`connection_basic.cpp:121`) is zero-initialized, so the default path sets TOS to 0 | **Refuse (D14).** TOS is the Type of Service byte, DSCP plus ECN, in cleartext on every packet. A chosen value is an operator-made fingerprint. Do not call `setsockopt`. Packets carry the operating system's default. Step 7 records the DSCP that leaves today, when the default path sets TOS to 0. |
| `no_delay(false)` (Nagle) | Set on every socket at `abstract_tcp_server2.inl:977-982` | **Measure before deciding**, in step 7. Nagle changes the record sizes an observer sees, so it is part of the record-length evidence. It is not fixed before that evidence exists. |
| FIN versus RST, linger | epee close / shutdown | **One behaviour for every failure before the channel exists:** close after zero bytes written, FIN, no linger and no RST variant. Step 7 asserts those failures are indistinguishable from the far side. |
| `add_ref` / `release`, `request_callback`, `send_done` | `i_service_endpoint` | The adapter's contract (D4). Not a copy of epee's refcount. |
| Executor for invoke timers and idle handlers | `levin_protocol_handler_async.h:229` takes `get_io_context()` for the invoke timer. The pool is 10 threads (`net_node.inl:1150`) | **D6, ruled.** A socketless `io_context` is the interim until the timing engine lands. Its pool is a measured budget, not 10. |
| Serial outbound dialing | `connections_maker` at `net_node.inl:2009`, call at `:1917` | **Stays serial through cutover.** The transport layer exposes an asynchronous dial and does not choose the schedule. When and how many to dial is discovery policy, P2P-3 slice 3. The extra round trip is measured in step 7. |
| SSL | `m_state.ssl` on the connection | **Refuse.** |

## Rate limit is four jobs (RULED 2026-09-28)

One name has been covering four jobs. Each has its own threat, its own
unit, and its own owner. The cutover carries the operator's budget.
Class priority is an argument on that writer; the class list is the
open design.

| Job | Threat or need | What is counted | Owner | Mechanism |
| --- | --- | --- | --- | --- |
| Operator link budget | The operator's link is metered, shared, or small | Wire bytes, per direction, for the whole node, across every connector. Once the flip lands, the count includes Noise overhead | Transport layer | Backpressure against a budget refilled from the engine's clock. Connections share it. Unlimited unless the operator sets one |
| What a peer can make us do | A peer inside a session | Work, per connection, charged on every dispatch before the payload is decoded | Session layer | PWD-B1. Its refill, capacity, initial fill, per-command cost, and exhaustion action stay owed in that section. This row does not settle them. PWD-B3 is the per-command size cap, which is a different bound |
| Who can reach us | Anyone who can open a TCP connection or a Tor rendezvous | Connections, and the cryptographic work before a session exists | Transport layer | The accept-rate bound before cryptography, the admission ceiling, pre-channel deadlines, and Tor proof-of-work (D4, D10). Already built |
| What goes first when the link is full | Saturation, under a budget or at the link's own limit | Message class | The session layer names the class. The transport writer schedules it | The writer takes a class on each send. New blocks and relay go ahead of bulk such as historical sync replies, and relay-lane conformance holds under saturation. The class list, who assigns a class, and the order among classes are the open design |

**The operator's budget is the carried duty.** `--limit-rate-up`,
`--limit-rate-down`, and `--limit-rate` (`net_node.cpp:184-186`) keep
working. The default is unlimited. `P2P_DEFAULT_LIMIT_RATE_UP` (8192)
and `P2P_DEFAULT_LIMIT_RATE_DOWN` (32768) are inherited numbers, not
the policy. An operator sets a budget when the link needs one. The
budget is the operator's bandwidth preference. It has no security role.

A token bucket per direction, for the whole node. The refill is the
operator's rate, computed from the engine's clock when the bucket is
used, so the bucket has no timer. Capacity is one second of that rate,
and the bucket starts full: the operator can use the link at once, then
stays at the rate. Unlimited means there is no bucket. When more than
one connection wants the direction, the writer serves them in turn, one
queued chunk each, so one connection cannot empty the bucket while
another is waiting. An empty bucket stops that connection until a
refill. It does not close the connection, and it does not drop the
bytes. `SendQueueFull` remains the close for a queue that cannot hold
another message.

Each send names a class. Until the class list exists there is one
class, and the turn above is the schedule. Naming further classes fills
that argument. It does not replace the bucket.

`core_rpc_server.cpp`'s `get_rate_*` / `set_rate_*`,
`rpc_facts_ffi.cpp`'s read of the throttle, and
`cryptonote_protocol_handler-base.cpp`'s accounting reach this limiter
(D13). Per-connection speed stats are observed facts reported upward.

The test runs in virtual time. With rate R and capacity C equal to R
over one second, starting full, bytes through one direction over an
interval T are at most C + R × T. A connection is not closed, and bytes
are not dropped.

The differential harness raises epee's P2P throttle, whose unset target
is 16 KiB/s, so that run compares Levin bytes. It does not test this
budget. A seam host without a limiter in that run is not a divergence.

**A peer is bounded by PWD-B1.** That bucket is per connection, charged
on every invoke and every notify before the payload is decoded,
including a malformed payload. Its exhaustion action is still unruled
there, and this section does not rule it. A byte budget is a different
job: it prices a cheap large message like an expensive small request,
and one shared budget is a lever against every other peer.

**Reachability is already built** (D4, D10).

**Saturation scheduling is the open design.** The cutover writer takes
a class on each send and, while one class exists, serves connections in
turn under the bucket. What remains is the class list, who assigns a
class, and the order among classes. That row is in `docs/FOLLOWUPS.md`,
owned by this section. The cutover does not wait for the list. Adding
a class fills the argument the writer already takes.

**Cutover order, after the harness merges.** One branch, one merge,
when the run records are in: the zone binding, this budget, the call
sites that move with them, the cross-build run and the measurements on
that build, then D13's deletions, the epee goldens, I2P recorded as
removed, and the pipe branch deleted.

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
  A transport cause (`PrefixMismatch`, `RecordRejected`,
  `TransportTimeout`, `SendQueueFull`, and every other transport
  close) does not ban the host and does not call `add_host_fail`.
  Scoring is the session layer's judgment, issued as its own ban
  call, not by this close.
- **The ban list has two writers (corrected 2026-09-28).** The
  operator writes through RPC. The session layer writes through one
  call, ban this host for this long, after it has judged
  misbehaviour. Both pass a duration. The transport layer enforces
  the entry at accept and before dialing.
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
(`shekyl-daemon-rpc` `ffi_exports.rs:162` builds a multi-thread runtime
and does not set a worker count, so it takes one worker per core;
`shekyl-tor-control-daemon` `blocking.rs:120` sets `.worker_threads(1)`).
On a 4-core Pi-4 those two are five workers. A third runtime that also
took the default would make nine, plus blocking pools. The transport
layer does not add one that way. The constructor is
`shekyl-runtime::runtime(RuntimeBudget { workers, blocking }, name)`.
Both counts are inputs, and `name` is a `ThreadName` (non-empty, no
interior NUL). Tokio's 512 blocking cap is not left in place.
The ledger is `shekyl-thread-ledger`, which does not depend on Tokio.
It sums every live pool, including the timing engine's dedicated
thread. The daemon prints that sum once at startup once the two call
sites above construct through `runtime`. Printing before that move
would omit the pools the sum exists to count. The move and the print
are one FOLLOWUPS row, owned by this document. `Pool::shutdown` bounds
the wait for a blocking task. Drop remains the unbounded fallback and
is never taken from inside a task.

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
   - its pool is one `io_context` whose worker count is an
     `ExecutorBudget` on D5's ledger (seam construction, 2026-09-28).
     That budget counts toward the Pi-4 total and replaces the
     hard-coded 10. `shekyl-runtime::runtime` stays the transport's
     Tokio reactor. It is a different row, and it carries the blocking
     cap this pool does not;
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
- Timer lateness under load. Step 7 measures how
  late relay timers fire under peer-driven load, taken both on the
  interim and after the timing engine lands. The interim's pool budget
  and the blocking pool's budget both come from it.

**The register.** P2P-3 §4.2's timing-engine row is two pieces
(updated 2026-09-25). The core precedes the transport layer, so
connection deadlines are owners from the first line. The bridge
follows the transport cutover and deletes the `io_context`. Relay
dispatch stays the row after the bridge. LV-3 keeps steps a–c: the
connection type, ownership transfer, and the registry. LV-3 §6.3
falsifier 3 has already fired, and this extends that record. The cryptonote handler (3,213 lines, the
register's "(open)" row) runs on the Rust-owned blocking pool once the
timing engine lands, so deleting the executor no longer waits on it.
Its replacement still has no owner, and the row stays visible.

**Falsifiers (rule 21). Reopen this ruling if:**

- any C++ component must block on a timer or an event loop, and so
  cannot be simply called;
- the relay conformance grades degrade after the sleep moves to Rust;
- the timing-engine round has not opened by the time transport-layer
  implementation starts. The interim is bounded only if its end has
  been scheduled. **Opened 2026-09-25:**
  [`P2P_TIMING_ENGINE.md`](P2P_TIMING_ENGINE.md), Round 1.

---

## D7 — capabilities are data (RULED 2026-09-25)

**Context.** Tor, I2P and clearnet were handled in the C++ as named cases:
about 62 zone-identity comparisons (`src/p2p` 53, `src/cryptonote_protocol` 7,
`src/net` 2), and a selection policy hidden in `enum class zone`'s ordering
(`enums.h:53`). Each network is instead a **connector** that declares what its
network natively provides. The transport layer assembles each connection's
stack from that declaration, so a future network (Nym, Lokinet) is a new
declaration, not a new set of branches.

**Ruling.**

1. **Each connector declares its native capabilities as data.** A connection's
   stack is assembled in a fixed, tested order: **the connector (with its dial
   method, direct or SOCKS), then added layers, then the contract.** Whatever
   the contract needs and the network lacks, a layer supplies. If no layer can,
   the connector is not usable. There is no separate routing element: how an
   operator routes traffic is the operator's configuration, and the daemon
   knows only its configured capabilities and speaks SOCKS.

2. **Above the transport layer, the network is an opaque partition key and
   never a branch condition.** Relay, peerlists, nonce windows and admission
   use it to keep networks apart. Any behaviour that differs between networks
   reads a declared capability, never the network's identity.

3. **The address type selects the connector.** The connector declarations own
   that mapping, and it is the single source for every consumer — the dialer,
   the peerlist (Part 2 of this ruling, in
   [`P2P_3_SLICE_1_PEERLIST_BRIEF.md`](P2P_3_SLICE_1_PEERLIST_BRIEF.md)), and
   the relay lane's per-network properties (`RelayZone` / `LinkSecrecy` in
   `rust/shekyl-relay-privacy/src/zone.rs` reads the declaration rather than
   keeping a second table; recording that requirement is this round's job,
   changing the relay lane is not).

4. **One stated exception, until the flip.** A clearnet stack without the Noise
   layer fails the contract's encryption clause. It is permitted while the
   option exists, and **the flip deletes this exception**. There is no mode
   that accepts both the Noise prefix and plaintext on one port.

5. **No network is a magic bullet.** No connector, capability or declaration
   carries an unqualified "protected", "secure" or "anonymous". Every declared
   capability names **the property**, **the adversary it holds against**, and
   **what remains exposed** — and who owns that remainder, or "unowned". A cell
   nobody has assessed reads **not assessed**; it never inherits a default from
   another network or from reputation. Encryption hides the content of the
   bytes; it benefits confidentiality and does not create it. No deep
   assessment is owed in this round.

6. **A precondition we can check is checked.** The Tor connector's "no exits"
   is enforced, not asserted: **the Tor connector dials onion addresses only**
   and refuses anything else with `DialFailed`. A completed transport handshake
   is checked the same way. What cannot be checked — an overlay's own
   cryptography — is a trust assumption with its concession (Tor's is
   classical-only, accepted). The daemon does not police the path an operator
   uses to reach a SOCKS router.

**The declaration table.**

| Declared per connector | Clearnet | Tor | I2P — no connector until one is built (D14 item 2); this column tests the interface |
| --- | --- | --- | --- |
| Addressing | IPv4/IPv6 + port. No assumption about how the operator routes it | onion v3. Peers are onion services; the connector dials onion addresses only, so traffic does not leave Tor onto clearnet | `.b32.i2p` |
| Encryption of the byte stream against the network observer | none native — **Noise layer added** (hybrid PQ). Encryption only: the peer's address and port stay visible, and traffic patterns stay observable | native, end to end to the peer's onion service, classical only (accepted) | not assessed |
| Destination authenticated to the dialer | no — Noise NN gives no peer authentication | yes, one way: an onion address is the service's public key, so completing the rendezvous means the dialer reached the holder of that key. The service learns nothing about the client | not assessed |
| This node's address hidden from the peer | no | yes | not assessed |
| Destination hidden from an observer at this node's end | no | yes — that observer can see Tor is in use, not the destination | not assessed |
| This node's address hidden from an observer at the peer's end | no | yes | not assessed |
| Correlation by an observer at both ends (timing, volume) | **not provided** | **not provided** | not assessed |
| Connection existence, timing, volume and sizes visible to an observer at this node's end | **visible.** Record framing is ruled fixed-window, with the window size from step 7's measured size distribution; until then BOLT-8 framing hides only the length field | visible as Tor traffic (cell-quantised sizes) | not assessed |
| Origin of relayed transactions, against peers | **not provided by any connector** — taxed by Dandelion++, not eliminated | same | same |
| Inbound peer has a bannable address (D4) | yes | no — "this zone, no address" | not assessed |
| Stream semantics | TCP | Tor stream | not assessed |
| Observed identity of an inbound peer | the socket address | "this zone, no address" | not assessed |
| Deadline inputs (D9) | measured per connector | measured per connector | when a connector exists |
| Rendezvous arrival priced by onion-service proof-of-work | not applicable — clearnet has no rendezvous | enabled by default (D10). Residual: streams inside an established circuit, bounded by `MaxStreams`. Flood resistance is **not assessed** until the Tor flood test | not assessed |

**Consequences.**

- **Clearnet is plain clearnet, plus the Noise layer.** The declaration is what
  clearnet provides natively. The stack includes Noise because clearnet
  declares no native encryption. `noise.rs`, `channel.rs`, `prefix.rs` and
  `aead.rs` are that layer. The option-off path is the exception in ruling 4;
  the flip is "enforce the contract". `--proxy` is a D3 dial duty and changes
  no declared capability.
- **Tor is a complete overlay, not a VPN.** The Tor connector speaks onion to
  onion. Encryption is end to end to the peer's service, classical only,
  accepted. The destination is authenticated to the dialer, one way.
- **Deadlines are per-connector data** (D9). A network with seconds of mixing
  delay would break one global handshake deadline.
- **Stream semantics are a capability.** A future message-shaped network would
  need a stream layer (ordering, reliability, framing). That is the
  interface's stress test; this round does not design that layer.
- **Meeting the contract** is encryption of the byte stream, and integrity of
  those bytes, against the network observer. It is not confidentiality, and it
  says nothing about traffic analysis, peer graphing or origin privacy; those
  rows name their owner or say "unowned".
- **Behaviour is uniform within a connector** (the TCP-option and close
  decisions in D3), even where connectors differ from each other.

**Falsifiers (rule 21). Reopen D7 if:**

- code above the transport layer **branches on a network's identity** rather
  than reading a declared capability;
- **two connectors serve the same address type**, so the address type no
  longer selects a connector (the peerlist brief's falsifier is the same
  event);
- a declaration cell is **filled from reputation or another network** rather
  than assessed, or reads "protected", "secure" or "anonymous".

---

## Network partitions (RULED 2026-09-25)

Decoupling must not erase separations that are privacy properties.
These partitions exist today, and each one stays:

- Relay and Dandelion++ run per zone.
- Self-detection nonce windows are zone-scoped (PWD-I1).
- `m_our_address`, and what is advertised, are per zone.
- Admission counts are per zone.
- Peerlists, and what peer exchange returns, are per connector. The
  rule is the slice 1 brief
  ([`P2P_3_SLICE_1_PEERLIST_BRIEF.md`](P2P_3_SLICE_1_PEERLIST_BRIEF.md),
  amended 2026-09-25). This section does not restate it.
- Seed nodes are per connector, declared in that same amendment.

Separately, origin-zone priority is hidden in `enum class zone`'s
ordering (`enums.h:53`: "order from here changes priority of selection
for origin TXes"). That is a cross-network selection rule, not a
partition. It survives decoupling as explicit, named policy.

**Every partition survives as explicit policy keyed by the session's
network, not as a duplicated protocol stack, and a test proves none of
them leaks across networks.** A single registry with one broadcast loop
over every session would be a cross-network leak.

Through cutover, Levin framing stays C++ (D14). The harness compares
the Levin bytes a peer sees and the session result. The design input for LV-3
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

## D8 — two counts (RULED 2026-09-25)

There are two counts, and each layer owns its own. This is the same
principle as admission.

**Sockets** belong to the transport layer. That is every live socket,
per connector and direction, including ones with no channel yet. It is
what socket admission and the descriptor ceiling need.

**Sessions** belong to the session layer: established Levin sessions,
per network key and direction. Until LV-3 that count is the Levin
registry's. It is what the outbound-fill logic is really about.

Today the C++ blurs them. `get_outgoing_connections_count` and
`census_inbound` both walk the Levin registry and count whatever
contexts are in it (`net_node.inl:2021-2069`, `:2117-2129`, `:3158`).
Once pre-channel sockets never appear in the registry, that walk
cannot serve socket admission.

The check and the increment are one step. Today's ceiling compares a
snapshot: a live walk, plus a separately maintained atomic rewritten
once a second (`:233-235`, `:1113-1138`). Concurrent accepts can all
read the same count, all pass, and overshoot the ceiling. Accept
reserves a slot with an atomic compare-and-increment against the
ceiling. Close releases it exactly once. That matches D4: close is
idempotent and records one cause. The parked pipe branch's
`37a0e0b` fixed a count that never came back down when a connection
died mid-handshake. The reservation does not repeat that.

- The transport layer owns socket counts per connector and direction,
  including pre-channel sockets.
- The session layer owns session counts, held in the Levin registry
  until LV-3.
- Neither layer derives its count from the other's state.
- Socket admission reserves under the table lock, in the same step
  as the ceiling check. There is no snapshot and no recount on the
  admission path. `socket_count` is the later read.
- The ceiling's `inbound_held` input is `Sockets::inbound_held`, the
  sum of every connector's inbound row (`InboundCeiling::resolve`).
  `socket_count` stays the per-connector, per-direction read.
  Outbound rows are not part of that sum. The sum is valid because
  D11 asserts one descriptor per socket.
- The transport layer exposes outbound socket counts per connector.
  Which count governs filling outbound slots is discovery policy,
  slice 3's decision.
- The once-a-second monitor thread (`:1113-1138`) is not removed by
  this round. Its remaining consumers are the out-peers check at
  `:1556` and discovery's fill loops at `:2021-2069`, all slice 3's.
  It goes when slice 3 lands.
- RPC reports both counts, each under its own name. Sockets and
  sessions are not one number.

**Test.** Under churn — including connections that fail before the
channel exists, and simultaneous closes — the socket count always
equals the number of live sockets, and returns to zero once they are
gone.

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

Pi-4 C5 run, 2026-09-26, the floor device (aarch64, 4 cores), about 90 seconds:
[`p2p_c5_pi4_20260926T005507Z.txt`](../benchmarks/p2p_c5_pi4_20260926T005507Z.txt).
Initiator 928 µs, responder 685 µs, one rekey 5.06 µs, seal/open of
65,535 bytes 889 µs. The responder figure is the per-connection cost
D10.3's clearnet accept-rate bound is derived from. The bound waits on
a stated CPU budget. No rate is written here. Deadlines are not written
here either.

One rekey is 5.06 µs against 889 µs to seal and open a 65,535-byte
record, under one percent at that size. Fixed windows are smaller than
that record, and the ratio grows as the window shrinks. Whether
every-record rekey is affordable is decided with the window size from
C9, not from this size alone.

---

## D10 — bounds before a session exists (RULED 2026-09-25)

**Context.** A connection costs the node before it has earned anything, in
two phases: before the channel exists (the transport handshake), and
between channel established and session established (before the Levin
handshake completes). The earlier text bounded only clearnet's
pre-channel state and left the rate to the FOLLOWUPS row on admission
before the channel exists. Socket admission is this layer's (D4), so
the rate is this layer's. Tor inbound is a different shape: accepting
on the forward listener is channel established, so an onion flood lands
in the gap, and Tor has its own defence.

**The adversary.** On clearnet, a flooder sends the public 8-byte prefix
and a 1,216-byte message 1. The encapsulation key must pass ML-KEM's
range check (all 768 coefficients below 3,329). Random bytes almost
never do. One valid key can be reused, so each connection costs the
attacker a TCP handshake and some bytes, and costs us one X25519, one
ML-KEM encapsulation, a task, and a slot. The inbound ceiling bounds how
many connections exist at once, not how fast they churn. Per-host caps
are gone, and a /24 supplies 256 hosts. On Tor, every inbound peer looks
the same ("this zone, no address"). Each rendezvous circuit can open up
to `MaxStreams` streams. Each stream is an accept on the forward
listener, and so a connection in the gap phase.

**Ruling.**

1. **What a connection may hold before its channel exists, per
   connector.** Clearnet: one task, one descriptor, one reserved slot
   (D8), at most one flight of buffered bytes, and a per-connector
   deadline (D9). Tor outbound: the pre-channel phase is the SOCKS
   exchange plus circuit build and rendezvous, bounded by the Tor
   connector's dial clock (D3). Tor inbound: there is no pre-channel
   phase. Its first bound is the gap timer (item 5).

2. **Cheapest rejection first.** The responder checks the 8-byte prefix,
   then exact lengths, then the ML-KEM encapsulation-key range check.
   Only after all three does it run X25519 and the encapsulation.
   *Records-was, at the 2026-09-25 pin:* `ResponderReady::finish` ran
   the X25519 Diffie-Hellman before validating the encapsulation key.
   **Landed:** the range check is in `read_message1`, and a malformed
   key returns before any responder Diffie-Hellman. `ResponderReady`
   stores the parsed key, so `finish` does not parse it again. Every
   failure still
   closes the same way: FIN after zero bytes written. Step 7 measures
   that.

3. **Clearnet accept rate is owned here.** This document owns the
   FOLLOWUPS row on connection admission before the channel exists. The
   mechanism is an accept-rate bound at accept, before any cryptographic
   work, per connector and per host, because clearnet's declaration says
   inbound peers have an observable address. Whether to aggregate hosts
   by subnet is a policy question for measurement. The values come from
   the measured per-connection crypto cost against a stated CPU budget.
   No number is written before that measurement (rule 26 B9). The
   responder side of a handshake is 685 µs on the Pi 4 (C5, 2026-09-26).
   That is the per-connection cost. The accept-rate values still wait
   on the stated CPU budget. The handshake's cryptography runs on the
   runtime's blocking pool (clearnet connector, RULED 2026-09-27), so
   the blocking cap bounds how many handshakes compute at once. The
   flood test measures that, in addition to the accept-rate bound. No
   rate is written. The bound is clearnet-only: Tor inbound
   does no Noise work on our side.

4. **Tor is defended by Tor's proof-of-work, not by a daemon-side
   limiter.** Onion-service PoW is enabled on every onion service we
   publish: the daemon's p2p onion and the wallet's serving personas.
   PoW is a property of the service we host. Outbound clients solve a
   puzzle only when the far service escalates, at a capped cost
   (SPIKE-F-17). *Records-was, at the 2026-09-25 pin:* the daemon did
   not do that. `ephemeral.rs` built `AddOnion` with no PoW, `publish`
   took ports and `max_streams` only, and `OnionPow`'s `Default` was
   `Disabled`. **Landed:** `publish` takes the setting explicitly, the
   default is `Enabled`, and the daemon's onion is published with
   `OnionPow::Enabled`. `PowRefused` is a 512 or 513 whose reply names a
   PoW argument. Any other 512 is an ordinary publish failure. Neither
   is retried without PoW.
   `Disabled` stays as an explicit choice for measurement arms. The
   type's doc comment is corrected, and the crate's KAT is updated so
   the default renders `PoWDefensesEnabled=1`. If the operator's Tor
   refuses the PoW arguments, `ADD_ONION` fails. The daemon reports a
   typed operator error (rule 82) and does not publish. It never
   retries without PoW. Streams inside an established circuit are
   bounded by `MaxStreams` per circuit. `MaxStreamsCloseCircuit` is a
   candidate, decided with the flood test. There is no daemon-side
   accept limiter on the Tor connector: every Tor inbound peer is
   indistinguishable, so a limiter an attacker can trip denies service
   to every honest Tor peer. PoW charges the attacker. Honest clients
   pay nothing until the service is under attack (SPIKE-F-18). The
   wallet's serving personas already run with it
   (`shekyl-tor-control-wallet/src/onion_service.rs:146-163`).

5. **The gap between channel established and session established.**
   Every connection that has a channel but no session gets a
   per-connector gap timer, derived under D9. It is never the idle
   timer. The byte limit in this phase is PWD-B3's cap for command
   1001. It replaces the inherited 256 KiB
   (`LEVIN_INITIAL_MAX_PACKET_SIZE`). On Tor inbound, this timer is the
   first bound a connection meets, beneath PoW and `MaxStreams`.

**The Tor declaration (D7)** adds rendezvous arrival priced by
onion-service PoW, enabled by default, with the residual that streams
inside an established circuit are bounded by `MaxStreams`. Flood
resistance stays **not assessed** until measured. The analysis that
volumetric flooding is expensive (`ARCHIVAL_SHARD_FETCH.md`, around
lines 1370-1406) was written for shard serving. Its strongest argument,
a large response the attacker must receive under Tor flow control, does
not apply to p2p, where a flooder wants slots and CPU.

**Evidence.** Under a flood in step 7, connections that fail before
the channel exists never leak a D8 slot, and cryptographic work per
second stays inside item 3's bound. The Tor flood test is deferred
until after implementation and is owned by this document: a controlled
load against the daemon's onion, for rendezvous flooding and for
streams within one circuit. SP-T3 recorded this as unmeasured. It
decides `MaxStreamsCloseCircuit` and whether the default queue
parameters stay. Tuning before that measurement is refused.

**Falsifiers (rule 21). Reopen D10 if:**

- a clearnet pre-channel failure performs cryptographic work that a
  cheaper check would have rejected;
- an onion service we publish runs without PoW, by default, by
  fallback, or by omission;
- the Tor flood test shows PoW plus `MaxStreams` plus the gap timer
  failing to keep honest Tor peers served;
- any connection in the gap phase is bounded only by the idle timer.


## D11 — test gates (RULED 2026-09-25)

These are the gates for the implementation PR, written now so the
round can reject them.

- **Differential harness, before any deletion (UPDATE 2026-09-28).**
  The same Levin traffic through both transports, option off, on
  loopback. The harness compares the Levin bytes a peer sees and the
  session result. *Records-was: compare close causes and timeout
  behaviour.* Deadlines per connector, typed first-wins causes, FIN
  after zero bytes, Rust admission, no local/remote timer split, no
  TOS knob, and byte bounds are listed in
  [`P2P_DIFFERENTIAL_HARNESS.md`](P2P_DIFFERENTIAL_HARNESS.md) as
  expected. The scripted peer and the seam host are
  `shekyl-p2p-harness`. Seed 1 is a handshake invoke, the response,
  and the session established when that response is back. `run-seeds`
  is the ctest driver: it owns the seed list, runs the seam in-process,
  and diffs it against `epee-host`. `epee-host` is the C++ recorder
  and is not linked into that crate. The transcript format is version
  1 in the harness document; version 2 is the backpressure event log,
  written for that seed. The cross-build run waits on the zone-binding
  commit, not on this harness. Seed 32's send-queue suffix is classified
  `byte-bounds` when the handshake prefix still matches; the other
  listed divergences are post-cutover CI invariants, not a comparator
  swallow list. The current server stays in the tree as the wire
  reference until this passes. It is not a test host for the option.
- **Cross-build interop.** A connector node and an epee node, option
  off, peering on testnet through sync, relay, and both dial
  directions. It waits on the zone-binding commit: production still
  uses epee, so a daemon whose zones use the seam does not exist yet.
  The in-process harness is not what blocks it. The loopback harness
  is one build. The claim that cutover is not a flag day is about two
  builds talking to each other.
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
- `connection_basic.hpp` / `connection_basic.cpp` and `network_throttle*`, after the rate-limit calls move in this same cutover. Today `core_rpc_server.cpp` calls `connection_basic::get_rate_*` / `set_rate_*`, `rpc_facts_ffi.cpp` reads `network_throttle_manager`, and `cryptonote_protocol_handler-base.cpp` sleeps and accounts through the global out-throttle. Those three call the operator link budget in "Rate limit is four jobs": default unlimited, backpressure, no close. The files go only once that `rg` is empty.
- the SOCKS dial: `socks_connect.cpp`, `socks_connect.h`, and the client `net_node` calls. Not a wildcard over `src/net/socks*`. `parse.cpp` parses a proxy URL (`src/net/parse.cpp:34`, the `socks` parser at `:260`), and `tests/unit_tests/net.cpp` exercises that API. The endpoint type those use stays, or moves with them in this cutover. The deletion gate is no remaining dial, not an empty `socks.h` while the parser still includes it.
- `network_pipe_ops` and `set_network_pipe`
- `rust/shekyl-p2p-transport/src/pipe.rs`, and its module and re-export in `rust/shekyl-p2p-transport/src/lib.rs`
- `rust/shekyl-ffi/src/clearnet_transport_ffi.rs`, and `pub mod clearnet_transport_ffi` in `rust/shekyl-ffi/src/lib.rs`
- the C++ call sites of those headers, in the same `rg`
- the epee transport unit tests that exist only to drive that server

`noise.rs`, `channel.rs`, `prefix.rs`, and `aead.rs` are not in this
list. They are the crypto core.

Deleting the SOCKS dial removes the C++ I2P path (`zone::i2p` and the
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
   Framing is fixed-window. The window size is derived from the
   measured size distribution. Until that measurement, the option uses
   BOLT-8 framing, which hides the length field and still leaves a
   burst visible as a message size. Fixed windows hide the size down
   to a count of identical windows, and make one window one record:
   no cleartext length, one nonce per record. The plaintext of each
   window starts with an authenticated occupancy, a 2-byte count of
   the stream bytes that follow; the rest of the window is padding.
   The count is inside the AEAD, so a trimmed tail cannot be mistaken
   for stream data. The channel has its own framing.
   `fragment.rs` stays the message-level tool for cover traffic: it
   works on Levin messages, and this layer never sees a command
   (D1, D14 item 3). That split is the decoupling, not a leftover of
   the occupancy encoding. When a window is only partly filled, the
   sender either seals it at once or waits for more bytes. Sealing at
   once makes a message end a window boundary with a time, so an
   observer reads boundaries and approximate sizes from window counts
   and timing. Waiting puts that delay on relay latency, including
   Dandelion++. The flush policy is part of this framing decision. It
   is measured in step 7 with the window size and Nagle, and it is not
   chosen before that measurement. The
   PWD-T8 vectors are re-minted when the window size is derived.
   Rekey is every record if the Pi-4 benchmark shows three
   HMAC-BLAKE2s per record are affordable beside seal cost. A
   count-based interval lets a quiet link keep one key for a session,
   and a later memory capture then exposes every transaction that key
   sealed. If that benchmark shows the cost is a meaningful fraction
   of seal cost, the interval is derived from the measured record
   rates instead. C5 (2026-09-26) measured one rekey at 5.06 µs and
   seal/open of a 65,535-byte record at 889 µs, under one percent at
   that size. Fixed windows are smaller, so that ratio is not the
   decision. Every-record rekey and the window size (C9) are decided
   together. Neither is chosen in this record.
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
