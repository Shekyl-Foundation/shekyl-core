# The p2p remnant cutover — brief (`RC-Q`)

**Family (registered in `IMPLEMENTATION_INDEX.md` §2, rule 94):** **`RC-Q`** (the rulings below). Grep surface: `rg -n -e '\bRC-Q[0-9]'`; the consensus-census family `RC-` is a different family and never carries a `Q`.
**Ground:** `dev` at `1aed454dd` (2026-11-04); the branch is off PR #1267 (the CS-5 tune-up, `fix/cs5-tuneup`) at `fbadf38a36`, and every anchor below was read at that commit.
**Status: OPEN — implementing.** Round 0 RULED, Rick 2026-11-04 (§0). The sessions crate (§4 step 1) is being written to §7, which is this document's specification of it.
**Replaces** in [`P2P_3_IMPLEMENTATION_ROUND.md`](P2P_3_IMPLEMENTATION_ROUND.md) §4.2: slice **4**, **RD**, slice **5**'s remainder (LV-3 step a, the registry) and the timing-engine bridge in **TE**. They are one move because they share one C++ host.
**Parent:** [`P2P_3_IMPLEMENTATION_ROUND.md`](P2P_3_IMPLEMENTATION_ROUND.md) §4.2.

Sections 0–6 are the brief as ruled (Rick, 2026-11-04), recorded here so
the rulings have a document. §7 is the implementing agent's specification
of the sessions crate, written before the crate (rule 05), and §8 records
what the implementation found.

## 0. Ruled (Rick, 2026-11-04)

- **RC-Q1:** one PR. Build the Rust owners, route the last four messages
  to them, and delete the C++ host.
- **RC-Q2:** **one coherent, integrated stack, not patches.** A clear
  path, clearly defined responsibilities and proper structural boundaries
  (§2 is that structure).
- **RC-Q3:** relay dispatch as RD designed it. Tests and measurements are
  post-implementation evidence (§5).
- **RC-Q4:** all timing in Rust. The asio `io_context` goes.
- **RC-Q5:** the wire is unchanged.
- **RC-Q6:** network identity's PR 3 (the handshake rules check, the Noise
  prologue version) comes after this PR and is built in the Rust session
  layer.

## 1. What this PR ends

There are about 5,800 lines of C++ on the p2p path, and they handle four
messages:

- **1001 and 1002**, in `net_node`: the inbound handshake and timed sync;
- **2002 and 2010**, in the handler and `levin_notify`: transaction
  ingress, relay dispatch and complement serving.

Every decision behind them is already Rust. The C++ hosts the Levin
handler on asio strands and runs timers. Rust composition that exists only
because C++ called it sits in `shekyl-ffi`: `zone_ffi` (connectors and
managed Tor), `seam_ffi` (bans and the bind), `dialer_ffi`, `link_ffi`,
`tor_link`, `chain_sync_ffi`, `pool_ffi`, `relay_zone_ffi`, `remnant_prep`,
`inbound_ceiling_ffi`. `shekyl-node` and `shekyl-daemon` depend on
`shekyl-ffi` for all of this.

**When this PR lands, `shekyld` links no C++, and neither the node nor the
daemon depends on `shekyl-ffi`.**

## 2. The stack

The names are the brief's; the responsibilities and boundaries are fixed.

| Layer | Crate | Owns | Does not |
|---|---|---|---|
| Connectors | `shekyl-clearnet`, `shekyl-tor`, with `shekyl-p2p-transport` (Noise), `shekyl-capped-stream`, `shekyl-socks` | sockets, accept, dial, the Noise layer, byte caps | parse Levin |
| Admission | `shekyl-transport-layer` | the socket table, ceilings, the ban list, `SocketId` | hold sessions |
| Framing | `shekyl-levin` | buckets and every command's payload codec | know a peer |
| **Sessions** | **`shekyl-p2p-session`** (new; replaces `shekyl-seam` and takes the router from `shekyl-chain-sync-runtime`) | one session per connection: the bucket split; **the handshake, both directions**; the self-connection nonces; timed sync on its interval; request/response correlation and timeouts; the per-command caps; **the dispatch table**; the board (session facts) | decide anything about a message's content beyond protocol state |
| Owners | `shekyl-peerlist` + `shekyl-dialer` (peers); `shekyl-chain-sync-runtime` (sync); `shekyl-relay` (transactions) | each command's meaning, and the state behind it | touch sockets or bytes |
| Network | **`shekyl-p2p`** (new) | composition: starts the connectors per config (managed Tor included), builds the session layer and the owners, wires the dispatch table, owns stop order; facts for RPC (`connections`, `net_stats`) read from the board | hold policy |
| Node | `shekyl-node`, `shekyl-daemon` | build the `Network` with the node's store, pool and tip, and stop it | reach `shekyl-ffi` |

**The boundary rules.** Each is a fact the code enforces, not a convention:

1. **Each command has exactly one owner,** declared in the dispatch table
   as an exhaustive `match` over a `Command` enum. An unknown command is
   refused by the session layer under PWD-B7. There is no fall-through.
2. **Nothing but 1001 reaches a session before its handshake completes.**
   That is slice 4's PWD-B1/B2, held by type: an owner's handler takes an
   `Established` session.
3. **Owners get typed messages and a `SessionHandle`.** They send typed
   messages through it and ask for a close with a typed cause
   (`shekyl-peer-policy`). Only the session layer closes.
4. **One writer per state:** the board, the session layer; gray and white,
   `Peerlist::apply`; the sync state, the sync owner; relay state, the
   relay zone; the pool, the mempool.
5. **Dependencies point down.** The session layer depends on framing,
   admission, the timing engine and the connectors' channel type, and
   never on an owner. Owners depend on the session layer's handle. The
   composition (`shekyl-p2p`) is the only crate that sees all of them.
6. **Backpressure per session.** Each session's next frame is read only
   after its owner has taken the last one, through a bounded per-session
   queue. That is the strand's `delivery_finished`, made Rust. Memory per
   session stays bounded under a slow owner.
7. **Every wake is a timing-engine owner:** handshake deadlines, invoke
   timeouts, the timed-sync interval, relay epochs, the embargo, cover and
   noise cadence, the stem watch.

### 2.1 Where each piece lands

- **Handshake (both directions).** The session layer runs it.
  - **Outbound:** the dialer asks the session layer to dial an endpoint
    with an aim (confirm or keep), and gets back an outcome. The outcome
    carries the peer's node data, received list and sync payload. The
    dialer applies it: the peer list admits or refuses, and the aim
    decides keep or close.
  - **Inbound:** the network check, inbound-only, double-handshake refusal
    and the self nonce. The reply carries the peer-list disclosure from
    `shekyl-peerlist` and the node's tip from `TipChanged`. There is one
    tip source for both directions, which closes CS-5's F4.
  - **The nonce set moves from the dialer to the session layer,** because
    the session layer both sends outbound handshakes and checks inbound
    ones.
  - The dialer keeps only policy: the fill, candidates, seeds, pace and
    retries.
- **Timed sync (1002).** The session layer sends it on its interval and
  answers it. Peer lists go to the peers owner. Sync payloads go to the
  sync owner as typed claim events; the claim tap is deleted.
- **2002.** The relay owner decodes the batch. The session must be
  established and the node `Synced` (the node's watch). The batch is
  admitted to the pool, then the arrival is recorded with the zone.
- **Relay dispatch.** `shekyl-relay`'s `Driver` sends through
  `SessionHandle` by session id, with messages built in `shekyl-levin`.
  The callbacks that `levin_notify.cpp` hosts (`on_stem`, `on_fluff`,
  `on_noise`, carrier verdicts) become direct calls inside `shekyl-relay`.
- **2010.** The relay owner serves it from the pool. The request is
  already the sync owner's.
- **2008, 2009, 2011–2014.** Unchanged: the sync owner, now reached
  through the dispatch table instead of the router.
- **RPC facts.** `get_connections` and `net_stats` read the board through
  `shekyl-p2p`, with no FFI.

## 3. Deletion

Every row is checked by name: `rg -n -e` before and after, with the gate
asserting its subject exists first (rule 47).

- **C++:** `src/p2p`, `src/cryptonote_protocol`, `src/cryptonote_core`,
  `src/daemon`; the remnant parts of `src/rpc` (`core_rpc_ffi`,
  `rpc_facts_ffi` and their headers); `shekyld_remnant` and its CMake;
  epee's Levin handler and asio net code where `shekyld` was their only
  user; the C++ unit tests of all of the above.
- **`shekyl-seam`,** whole. What is kept moves to `shekyl-p2p-session`,
  and the strand protocol (`Post`, `deliver`, `delivery_finished`,
  `handler_armed`) goes.
- **`shekyl-chain-sync-runtime`'s router and claim tap.**
- **`shekyl-ffi`:** every module whose caller was the remnant. At least:
  `seam_ffi`, `seam_board_ffi`, `seam_ban_ffi`; `zone_ffi`, `dialer_ffi`,
  `link_ffi`, `tor_link`; `chain_sync_ffi`, `pool_ffi`, `relay_zone_ffi`,
  `dandelionpp_ffi`; `notify_ffi`, `levin_ffi`, `peerlist_ffi`,
  `rpc_peerlist_ffi`, `peer_policy_ffi`; `inbound_ceiling_ffi`,
  `remnant_prep`, `daemon_snapshot_ffi`, `executor_ffi`, `origin_verdict`,
  `network_id_ffi`. The logic in them that the node still needs moves to
  `shekyl-p2p` or its owner crate; it is not deleted with the export. The
  rest of `shekyl-ffi` is walked and reported: what is left and who calls
  it (§8).
- **`shekyl-daemon`'s `remnant` module** and the `RunFn`/`StopFn` hooks.
  `main` builds the node and the network directly.
- **The freeze file's rows** for the deleted files.

## 4. Order of work inside the PR

1. `shekyl-p2p-session`: the session, handshake both ways, timed sync,
   dispatch, board, backpressure, all on the timing engine.
2. Owners on the dispatch table: peers, sync (moved off the router), relay
   (2002, dispatch, 2010).
3. `shekyl-p2p`: composition, with the connectors and managed Tor moved
   out of `shekyl-ffi`.
4. The node and daemon build the `Network`. The remnant goes.
5. The deletion (§3).
6. Docs (§6).

Each commit is pushed as it lands. Only the PR's final head has to build.

## 5. Evidence (after implementation)

- **Black-box against a spawned `shekyld`,** over real sockets:
  **handshake:** an other-network peer is dropped and never banned; a
  second handshake is refused; a self-connection is detected; nothing but
  1001 is accepted before the handshake. **Transactions:** refused before
  the handshake, ignored while unsynchronised, admitted and relayed after.
  **Peer lists:** a received list is admitted under the same limits
  inbound and outbound; an unknown session is never closed. **2010:** the
  complement is served. **Backpressure:** a slow owner holds the session's
  reads without growing memory.
- **The existing walks,** unchanged and green: the CS-5 sync tests, the
  relay embargo and origin walks, the slow lane.
- **The fleet:** a Tor run with `DAEMON_RELAY_PRIVACY.md` §97's
  relay-timing rows measured on the Rust path (`RustPath`), as CS-5's §10
  did.
- **The build:** `shekyld` builds with no C++ target. Report what C++
  remains in the tree and what still builds it.

## 6. Docs

- **`P2P_3_IMPLEMENTATION_ROUND.md`:** slices 4 and 5, RD and TE closed,
  and the stack table (§2) recorded as the architecture of record.
- **`DAEMON_RELAY_PRIVACY.md`:** §97's rows carry their `RustPath`
  measurements.
- **`SHEKYL_P2P_PROTOCOL.md`:** PWD-B1/B2 record how they are held (the
  type, §2 rule 2).
- **`CHANGELOG`:** one entry: `shekyld` is all Rust.

## 7. The sessions crate — specification

Written 2026-11-05 against the anchors at `fbadf38a36`, before
`shekyl-p2p-session` existed. Where the crate and this section disagree,
the crate is the defect until this section is amended with the reason.

### 7.1 What a session is

A **session** is one admitted connection from the moment a connector
hands over its channel (`OpenSocket`, the capped-stream `Session`, the
`Endpoint`, the connector's gap disarm) to the moment its socket is
released. It is identified by the admission's `SocketId` (there is no
second id), and it is in exactly one of these states:

| State | Entered | Leaves on |
| --- | --- | --- |
| `Handshaking` | adoption | the handshake completing (→ `Established`) or failing (→ `Closed`) |
| `Established` | the handshake's last step: inbound, the response is queued; outbound, the response is decoded and the dialer kept it | a close (→ `Closed`) |
| `Closed` | the first end recorded (`DialEnd`, with its D12 cause) | the socket's release; the row leaves the board |

Only the session layer moves a session between states (§2 rule 4). A
confirm dial (`DialAim::Confirm`) never enters `Established`: it closes
on the response, as the dialer brief ruled.

### 7.2 The command set and the dispatch table

`shekyl-levin` carries one closed `Command` enum of the ten live commands
(1001, 1002, 2002, 2008, 2009, 2010, 2011, 2012, 2013, 2014), replacing
its `DefinedCommand` (six) and `SyncCommand` (four). Each arm names its
wire id and its payload cap; `from_wire` is the one place an unknown id
becomes `None`.

The **dispatch table** is the session layer's exhaustive `match` over
`Command`, with these arms:

| Command | Owner | Form the owner receives |
| --- | --- | --- |
| 1001 `Handshake` (request) | the session layer | — (§7.4) |
| 1001 (response) | the session layer | — (§7.4) |
| 1002 `TimedSync` (request and response) | the session layer; then the **peers** owner gets the received list and the **sync** owner gets the claim | `PeerEvent::ListReceived`, `SyncEvent::Claim` |
| 2002 `NewTransactions` | **relay** | the decoded batch (`NewTransactions`), with the session's established handle |
| 2008 `NewCompactBlock` | **sync** | the encoded payload, as the router handed it |
| 2009 `RequestCompactMissingTx` | **sync** | the encoded payload |
| 2010 `GetTxpoolComplement` | **relay** | the decoded request (`TxpoolComplementRequest`) |
| 2011–2014 | **sync** | the encoded payload and the `Command` arm |

A Q- or S-flagged bucket whose command is not a `Command` is refused
before the match: `Error::UnknownCommand` at ingress, closed under
PWD-B7 as a form failure. A response (S flag) on 2002–2014 is a form
failure too: those are notifications. An unflagged bucket (noise, a
fragment) is the framing layer's and reaches no owner.

The owners are three traits the session layer defines and never
implements — `PeerOwner`, `SyncOwner`, `RelayOwner` — bundled in one
`Owners` value the composition hands the layer at construction. Every
method takes an `&Established` (§7.3) or a `SessionFacts` and returns
nothing the session layer interprets except a `Taken` acknowledgement
(§7.7). The traits are the whole of what the session layer knows about an
owner (§2 rule 5).

### 7.3 `Established`, `SessionHandle`, and the close

`Established` is a proof type minted by the session layer alone, after
the handshake completes, and carried by every owner-facing call. It
dereferences to a `SessionHandle`. There is no constructor an owner can
reach, so a handler that takes `&Established` cannot be called on a
handshaking session (§2 rule 2, PWD-B1/B2 held by type).

`SessionHandle` is `Clone + Send + Sync` and offers:

- `id() -> SocketId`, `connector() -> ConnectorId`,
  `direction() -> Direction` (`Inbound | Outbound`),
  `endpoint() -> &Endpoint`;
- `send(Message) -> Result<(), SendRefused>`: encodes the typed message in
  `shekyl-levin` and queues the bucket on the connector's `SendHalf`. The
  queue's byte bound is the connector's (`send_queue_bytes`); a full queue
  is `SendRefused::QueueFull`, and the session layer closes the session
  with the stamped end, as the seam did. A send on a closed session is
  `SendRefused::Closed`;
- `close(CloseCause)`: asks for a close. The cause is
  `shekyl-peer-policy`'s typed value; the session layer records it as the
  first end if none is recorded, and only the session layer closes the
  socket.

`Message` is the typed outbound set: `NewTransactions`, `NewCompactBlock`,
`RequestCompactMissingTx`, `GetTxpoolComplement`, `RequestHeaders`,
`ResponseHeaders`, `RequestBodies`, `ResponseBodies`, and the two
session-layer-only forms the handle refuses to send on an owner's behalf
(a handshake or timed-sync request or response). The 1024-byte padding
the C++ `make_tx_message` could add is **not** carried: `pad_txs` is
`false` at its only construction (`net_node.inl:277`), so the padding
code never ran; the field stays empty on the wire (RC-Q5).

### 7.4 The handshake, both directions

**Shared checks** (both directions, in this order, every failure a
`CloseCause` the peer-policy crate names and a `DialEnd` the row keeps):

1. the response or request decodes as `COMMAND_HANDSHAKE` under
   `CAP_HANDSHAKE`;
2. `node_data.network_id` equals ours; a mismatch is **dropped, never
   banned** (`CloseKind::NetworkMismatch`);
3. the sync payload's fields are read as a claim, not judged (the sync
   owner judges claims).

**Inbound.** A session enters `Handshaking` with a deadline
(`handshake_within`, the connector profile's) armed on its timing-engine
owner. Until the handshake completes, the ingress cap is the pre-handshake
cap (256 KiB) and the only bucket the session accepts is a 1001 request;
any other bucket, a 1001 response, or the deadline firing closes the
session (`SessionRefused`, PWD-B1). On a 1001 request:

4. a second 1001 on a session that already handshook is a double
   handshake: refused and closed;
5. the request's nonce is taken against the **nonce set** (§7.5):
   `SelfConnection` closes both ends (the dialer's outbound attempt learns
   it through its outcome); `Probe` resolves the dialer's reachability
   probe and the session is closed as a probe; `MisroutedProbe` is a form
   failure; `NotOurs` continues;
6. ~~the peer's advertised endpoint (`my_port`) is recorded on the row as a
   claim (`Claimed<AdvertisedEndpoint>`), observed only under the redial
   rule the seam carried (`observes`)~~ — **SUPERSEDED 2026-11-05 (F4):**
   the handshake carries no address (ruled 2026-10-09; `basic_node_data`
   is the network id alone), so there is no claim to record and the
   seam's claim machinery is deleted, not moved. The step is a no-op;
   numbering kept so the later steps' citations hold;
7. the response is built: our `basic_node_data` (network id only), our
   `CORE_SYNC_DATA` from the **tip source** (§7.6), and the **disclosure**
   the peers owner supplies (`PeerOwner::disclosure(connector)`), and
   queued ahead of anything else;
8. the session is `Established`; the board republishes; the connector's
   gap disarm fires; the owners are told (`on_established`); the peers
   owner gets `ListReceived { id, list }` and the sync owner `Claim { id,
   sync }`; the first timed sync is drawn (§7.6).

**Outbound.** `dial(endpoint, aim) -> DialOutcome` is the session layer's
one entry for the dialer. It dials through the connector (the dial's own
deadline is the connector's, as today), writes the 1001 request with a
nonce inserted in the set **before** the bytes are written, arms the
invoke timeout (§7.6), reads until the response, runs the shared checks,
and returns the outcome with the peer's node data, received list and sync
payload. `Confirm` closes the channel on the response — as built
(2026-11-05, F5): `DialEnd::local_close_after_channel()`; ~~`Reached::Response`~~
does not exist and is not minted. `Keep` enters `Established` and does step 8. A response with no pending
invoke, or anything but a 1001 response before the response, is a form
failure.

The nonce rule, the network check, inbound-only (an inbound session
never dials back on the strength of `my_port`; the redial rule is the
dialer's, from the row's claim) and the double-handshake refusal are the
whole of what RC-Q6's successor builds on: the handshake rules check and
the Noise prologue version slot into step 2 later, in this crate.

### 7.5 The nonce set

`HandshakeNonceSet` moves from `shekyl-dialer` to the session layer
unchanged in shape: one map per connector, `nonce → Kind`
(`SelfConnection | Probe { minted_at }`), `take` returning `NonceTake`,
an in-flight guard that erases the nonce when the attempt ends. The
dialer keeps `mint_probe` as policy (when to probe) and asks the session
layer to insert the minted nonce; the session layer alone reads the set.
As built (2026-11-05): the set is reached through `SessionLayer::nonces()`;
`mint` is the layer's own (each `dial` inserts before it writes), and
`mint_probe` is the managed Tor supervisor's call. A probe that arrives
is reported to a fourth member of `Owners`, `probes: Arc<dyn ProbeSink>`
(`ProbeArrival { minted_at, arrived_at }`), not to a command owner: a
probe is a handshake this node sent itself, and the session closes as
soon as the nonce is read.

### 7.6 Timing: every wake an owner

Each session registers one timing-engine owner under `OwnerClass::TimedSync`
at adoption and deregisters it at release. The owner is armed for the
earliest of the session's live deadlines:

| Deadline | Armed | Fires |
| --- | --- | --- |
| handshake | inbound, at adoption; `handshake_within` | close, `LevinHandshakeTimeout` (as built 2026-11-05, F5; ~~`SessionRefused`~~ is the bucket-shape refusal, not the deadline) |
| invoke | at each request sent (1001 outbound, 1002); `INVOKE_TIMEOUT` = 120 s, the Levin handler's `LEVIN_DEFAULT_TIMEOUT_PRECONDITION` kept | close, `InvokeTimeout` |
| timed sync | at establishment and after each of this session's own 1002 responses; the draw below | send a 1002 request with our `CORE_SYNC_DATA`, arm the invoke deadline |

One invoke is outstanding per session at a time: the session layer never
sends a 1002 while one is pending, and a response (S flag) with no
pending invoke is a form failure.

**The timed-sync draw (PWD-B2).** Per session, independently:
`min + U(0, jitter)`, re-drawn only when this session's own 1002 fires,
`0` a valid draw. PWD-B2 fixed the mean at `P2P_DEFAULT_HANDSHAKE_INTERVAL`
(60 s) and left the `min`/`jitter` split owed. **This PR's first mint,
posed as an `Assumption` (Ruling B), not a derivation:** `min = 45 s`,
`jitter = 30 s`, so `U[45 s, 75 s)`, mean 60 s. The basis: the width is
half the mean, so two sessions' cadences drift a full period apart within
a few cycles; the longest interval (75 s) stays under the invoke timeout
and under two mean intervals, so the transport brackets' basis in
`profile.rs` (about two received messages a minute per session, δ = 15 s)
is unchanged; and the shortest (45 s) keeps the per-session send rate
within 4/3 of today's. Rick rules the split; the constants are
`TIMED_SYNC_MIN` and `TIMED_SYNC_JITTER` in this crate, and the §97
`RustPath` run reads the realised distribution.

**The tip source.** The session layer holds one `watch::Receiver` of the
node's `CORE_SYNC_DATA` (height, top id, cumulative difficulty, the
pruning seed as the wire still carries it) that the node publishes on
`TipChanged`. Both handshake directions and both timed-sync directions
read it; the dialer's `SnapshotSource` and `publish_chain_tip` are
deleted (CS-5 F4 closes).

### 7.7 Backpressure: the per-session queue

A session's reader takes the next frame only after the owner has taken
the last one. Mechanism: a per-session `tokio::sync::Semaphore` of
`SESSION_QUEUE_DEPTH` permits (1: the strand's `delivery_finished`
semantics). Before reading a frame the session acquires a permit; the
permit travels inside the owner's event as `Taken`, and the owner drops it
when it has taken the message (dequeued it into its own state, or
finished with it: the owner's choice, and the sync owner's serving queue
is its own bound as today). Memory held by one session on an owner's
behalf is therefore at most `SESSION_QUEUE_DEPTH × payload_cap(command)`,
whatever the owner does. Session-layer-handled buckets (handshake and
timed-sync responses) take no permit. A permit outstanding at close is
dropped with the event; it holds nothing.

### 7.8 The board

`Board` is the session layer's published view: `Arc<[Row]>` sorted by id,
republished on adopt, establish and close, as the seam's. A row carries
`id`, `connector`, `direction`, `endpoint`, `established`, `started_unix`,
`started_mono`~~, and the claims the row holds (`claimed_height`,
`accepted_chain_length`, `last_known_hash`, `advertised`)~~ —
**SUPERSEDED 2026-11-05 (F4):** a row carries no claims. Height claims
reach the sync owner as `SyncOwner::claim(session, sync, carrier)` and
live in its view, which is the one place they are judged; the advertised
endpoint does not exist on the wire. The board is
what `shekyl-p2p` reads for `connections` and `net_stats` and what the
relay reads for its established-outbound candidate set. It has one
writer.

### 7.9 Bans and the ceiling

The ban list and the ceiling stay in admission (`shekyl-transport-layer`),
where the seam's `bans` module put them; the session layer reads
`is_banned` at adoption and closes a banned peer's session as the hub did.
`ban_*`/`lift_*`/`subscribe_bans`/`listed_bans` keep their shape and move
with the module into the admission crate's surface the composition
exposes to RPC. As built (2026-11-05, F6): the list verbs are
`Sockets`' (`shekyl-transport-layer`, `admission::bans`); the session
layer adds the four `ban_*` verbs on `SessionLayer`, each of which
records the ban in admission and then closes every live session the
ban covers (`local_close_after_channel`), because only the session layer
closes (§2, rule 3). `lift_*`, `is_banned`, `subscribe_bans` and
`listed_bans` are reached through `SessionLayer::sockets()`.

### 7.10 What the session layer does not do

It does not admit a transaction, judge a claim, choose a peer, decide a
relay, read the pool, or close for any cause but its own protocol state
(a form failure, a deadline, a queue full, a banned host, a stop). Those
are owners' calls through `SessionHandle::close`.

## 8. Findings during implementation

Recorded as they are found; each names the anchor it corrects.

- **F1 (2026-11-05):** `pad_txs` is `false` at its only construction
  (`net_node.inl:277`), so `make_tx_message`'s 1024-byte padding never
  ran; the Rust `NewTransactions.padding` stays empty (§7.3). RC-Q5 holds
  on the wire as it is actually sent.
- **F2 (2026-11-05):** PWD-B2's per-session timed-sync draw had no Rust
  implementation at the branch point (`rg -n 'TIMED_SYNC' rust/` found
  codecs, the router and tests only); `profile.rs` reads the 60 s mean as
  its bracket basis. The split is minted in §7.6 as an `Assumption`.
- **F3 (2026-11-05):** "neither the node nor the daemon depends on
  `shekyl-ffi`" reaches past the p2p modules: `shekyl-daemon` also reads
  `harden`, `panic_hook`, `platform`, `network_id_ffi`,
  `pow_randomx_ffi::{check,record}_seed_epoch` and
  `archival_ffi::{check,arm}_settlement_schedule` from `shekyl-ffi`.
  Each is pure Rust with no C++ caller on the daemon path; they re-home
  to the crate that owns their subject (§3's "moves to its owner crate")
  so the dependency edge can go.
- **F4 (2026-11-05):** §7.4 step 6 and §7.8's claim columns were written
  from the seam as it stood, which still carried `Claimed<AdvertisedEndpoint>`
  and the `observes` redial rule. The handshake has carried no address
  since 2026-10-09 (`basic_node_data` is the network id alone, PWD-B1), so
  the claim is unrecordable: the seam's `endpoint.rs`/`registry.rs` claim
  machinery is deleted in step 5, not moved, and the board row has no
  claim fields. The sync owner remains the one holder of height claims.
- **F5 (2026-11-05):** the brief named two `DialEnd`s that do not exist:
  `Reached::Response` (§7.4) and `SessionRefused` for the handshake
  deadline (§7.6). As built, `Confirm` closes with
  `local_close_after_channel()` and the deadline closes with
  `DialEnd::levin_handshake_timeout()` (`CloseKind::LevinHandshakeTimeout`,
  kind 7); two kinds are minted, `NetworkMismatch` (18, a `Gap`) and
  `InvokeTimeout` (19, `ChannelExists`). `SessionRefused` stays the
  bucket-shape refusal.
- **F6 (2026-11-05):** a ban that admission records does not close the
  sessions it covers; the hub did that. Since only the session layer
  closes, the `ban_*` verbs are on `SessionLayer` (§7.9) and return the
  ids they dropped.
- **F7 (2026-11-05), §3's walk of the rest of `shekyl-ffi`:** after the
  p2p modules go, it holds `difficulty_ffi`, `chain_digest_ffi`,
  `pow_randomx_ffi` (the hash only), `curve_tree_replica_ffi`,
  `tx_extra_ffi`, `tx_extra_codec_ffi`, `txid_ffi`, `tx_signing_ffi`,
  `archival_ffi`, `ct_balance_ffi`, `economics_ffi`, and the `legacy_*`
  crypto, FCMP, KEM, proof, transaction and FROST modules. Its C++
  callers are `src/cryptonote_basic` and `src/fcmp` (libraries),
  `contrib/epee/src` (`mlog`, `mlocker`, `memwipe`), `cn_deserialize`,
  and the C++ tests (`unit_tests`, `difficulty`, `randomx_v2_parity`, a fuzz
  target). `cargo tree -e normal,build -i shekyl-ffi` finds no edge from
  `shekyld`, `shekyl-node`, `shekyl-daemon`, `shekyl-p2p` or
  `shekyl-daemon-rpc`.
- **F8 (2026-11-05), §5's C++ that remains and what builds it:** under
  `src/`, `common`, `crypto`, `fcmp`, `cryptonote_basic`,
  `serialization`, `device`, `platform` and `shekyl` (the FFI headers),
  about 40,000 lines with `contrib/epee`'s 11,000. CMake compiles them for
  the C++ tests and, with `BUILD_DEBUG_UTILITIES` (on by default only in a
  Debug build), for `shekyl-utils-deserialize`, until `shekyl-cli`'s
  `tx decode` replaces it (IG-Q26). A release build stages only the three
  Rust binaries into `bin/`, which is what the release archives carry:
  `shekyld`, `shekyl-cli` and `shekyl-wallet-rpc` are cargo builds with no
  C++ in their links.
