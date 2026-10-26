# RT-W10 — the daemon side of the channel: rule-26 pre-flight

**Status:** Round 0 pre-flight — **POSED 2026-10-25, awaiting the
maintainer's ruling and RT-W10's authorization.** It records the substrate
re-check (§2), what was and was not executed (§3), and the questions the
slice cannot proceed without (§4), each with a recommendation. RT-W10 is
not authorized, and no implementation commit lands before this document
is ruled and the slice authorized (rule 26).
**Ground:** `shekyl-core` `dev` **`66619c4b9`**. Every `file:line` below was
read at that commit.
**Parent:** [`RPC_CHANNEL.md`](RPC_CHANNEL.md) (round R1, ruled 2026-10-09)
§5, §6, §7, §7.1, §11.2 and the RT-W10 row of §13; the RT-W9 pre-flight
([`RPC_CHANNEL_RT_W9_PREFLIGHT.md`](../completed/RPC_CHANNEL_RT_W9_PREFLIGHT.md)) and
the close-out's items for this one (§13, RT-W10 row).
**Family:** `RT-` (registered). This document mints items **RT-O30…RT-O35**
inside it, and **RT-O36**, posed here.
**Decision authority:** Rick.

---

## 1. What RT-W10 is, and is not

RT-W10 is where the channel exists: the daemon accepts it. It builds the
same-user socket or pipe and its rendezvous, the channel listener that
drives the `hybridXK` handshake RT-W9 built, the daemon's static key,
enrolment and revocation, per-connection grants in place of today's
listener-wide `restricted` flag, and the resource policy (§6.3). The
Foundation daemon reaching the website needs this slice and RT-W11, the
tunnel (§13, order ruled 2026-10-25).

It is not:

- **service mode** (RT-W14). The `service` row is reserved until RT-W14
  builds the dispatcher (`shekyl-daemon-config/src/table.rs:149-160`), so
  `RunMode::Service` is unreachable today (F-14). §5's console key, the
  enrolment at install and the console-key reset are service-mode
  machinery (RT-O35);
- **the clients** (RT-W11 and RT-W12). The tunnel and the wallet, CLI and
  GUI clients move onto the channel in their own slices;
- **the sweep** (RT-W13).

---

## 2. Substrate re-check

What the slice builds on, read at source. Three read-only passes over the
tree; every claim cited.

| # | Claim the slice rests on | Where read | Finding |
|---|---|---|---|
| F-1 | The restricted listener and its C++ flags still exist to delete | `src/rpc/`, `src/common/`, the option table | **Already deleted.** `rpc_args.{h,cpp}` went in `60fac704d` and `removed_flags.{h,cpp}` in `69f83b862` (2026-10-15, the daemon-configuration cutover). Today there are two plaintext loopback presets, `rpc-admin-listen` and `rpc-view-listen` (`shekyl-daemon-config/src/table.rs:266-267`), each loopback-only at parse (`shekyl-options/src/kind/mod.rs:611-631`). What remains to delete is the `restricted: bool` that runs from the Rust handlers through the FFI into C++ (F-3) |
| F-2 | A listener's grant reaches the handlers | `shekyl-daemon-rpc/src/server.rs:51-68`, `:450-505`, `:533-577` | **Per router, not per connection.** `AppState.restricted` (`server.rs:56`) is set once per router; `serve_presets` builds an admin router and a view router (`:496-500`). Nothing about the connection reaches a handler: axum's `Router<()>` ignores the incoming stream (`axum-0.8.8/src/routing/mod.rs:561`) |
| F-3 | Where `restricted` is read | `server.rs:336-340`; `handlers/json_rpc.rs:55-59`, `:88-97`; `handlers/json.rs:47-48`, `:156-174`, `:232`, `:304`; `handlers/binary.rs:66`; `handlers/submit.rs:47`; `methods.rs:829-833`, `:1015`, `:1077`; `info.rs:120-127`; `src/rpc/core_rpc_ffi.h:59-72`; `src/rpc/core_rpc_server.cpp:98-118`, `:299-341` | A REST route missing from the view router is a **404**. A gated JSON-RPC method is **HTTP 403 with -32601, "Method not allowed in restricted mode"**. §6.2 asks for the grant class, which exists (`ErrorClass::OutsideTheGrant` = -32002, `shekyl-rpc-types/src/errors.rs:29`, `:58`) and is not used here. The flag also reaches C++ as an origin (`rpc_origin`) for the pool's sensitive entries |
| F-4 | The method table carries §6.1's grants | `shekyl-rpc-types/src/methods.rs:24-35`, `:106-176` | **Two values, `Any` and `HostOnly`,** standing in "before RT-W10's grants exist" (`:24-28`), plus an `armed` flag. §6.1 has twelve grants: `health`, `status`, `chain`, `pool`, `peers`, `submit`, `mining-work`, `mining-control`, `bans`, `node`, `config`, `enrol`. The table needs a grant column, and the resource-bound column it says is RT-W10's (`:18-19`) |
| F-5 | Today's view listener matches §6.1's `view` preset | `shekyl-rpc-types/src/methods.rs:128-131`, `:155` | **No.** `/submit_transaction`, `submit_block`, `get_block_template` and `get_miner_data` are `Any`, so the view listener serves them. Under §6.1 a `view` connection is refused them (`submit`, `mining-work`). §6.1's own change list names `get_coinbase_tx_sum`, `calc_pow` and `/get_alt_blocks_hashes`, not these four |
| F-6 | Who uses plaintext loopback today | `shekyl-gui-wallet` `src-tauri/src/daemon_manager.rs:116-118`; `shekyl-daemon-config/src/table.rs:266`; `shekyl-cli/src/main.rs:172`, `:534`; `shekyl-wallet-rpc/src/main.rs:138`; `shekyl-daemon-rpc/src/ctl_client.rs:89-146`; `shekyl-engine-core/src/engine/regtest_e2e.rs:308`, `:422`; `utils/python-rpc/framework/daemon.py:36-37` | **Every client.** The GUI starts its daemon with `--rpc-admin-listen none --rpc-view-listen 127.0.0.1:<port>` and submits and mines through the view listener. `rpc-admin-listen` defaults to `127.0.0.1` on the network's RPC port, which is the default target of `shekyl-cli`, `shekyl-wallet-rpc` and the engine, so they submit through the admin listener. `shekyld <command>` reaches `node` and `mining-control` over the same admin endpoint (`ctl_client.rs`). The regtest harnesses use both listeners, and the Python framework and the CT-2 fixture generator call `/pop_blocks`. Re-scoping plaintext loopback to `view` (RT-15's off-by-default option at the least grant) would cut submission and mining-work for all of them until their slices move them (RT-O33) |
| F-7 | The armed test-lever switch gates the levers | `shekyl-daemon-config/src/table.rs:235`, `:68`; `shekyl-daemon-rpc/src/mining_methods.rs:7-10`, `:110-125`; `src/rpc/core_rpc_ffi.cpp:181`, `:258-259` | **Parsed and not routed.** `dev-rpc` is stored (`shekyl-node/src/lib.rs:192`, `:434`), and `admit_armed` exists, but its only callers are tests; the module says "built and not routed". `/pop_blocks` is served on the admin listener with no arming check, against the ruling of 2026-10-14 that it is an armed lever. `generateblocks` and `inject_archival_serve_credit` are gated by a C++ `FAKECHAIN` branch, not the switch. No start-time log line was found, though §6.1 asks for one |
| F-8 | The armed switch is network-uniform | `table.rs:235` (`TEST_NETWORKS`); `INPUT_GRAMMAR.md` IG-Q49 and its option row | **No, by a later ruling.** `dev-rpc` is accepted only on `testnet`, `stagenet` and `regtest`. `INPUT_GRAMMAR.md` IG-Q49 (ruled 2026-10-19) rules the armed levers "never on mainnet". `RPC_CHANNEL.md` §6.1 (ruled 2026-10-09) rules the override "never selected by nettype". The two disagree (RT-O36) |
| F-9 | §6.3's resource policy has a substrate | `methods.rs:565-580`; `handlers/json.rs:157`, `:232-238`; `handlers/binary.rs:66`, `:89-91`; `handlers/json_rpc.rs:186-188`; `middleware.rs:34`; `shekyl-daemon-rpc/Cargo.toml:23` | **Caps per listener, not per grant.** Four `RESTRICTED_*` caps apply to the view listener only, refused with -19 or a 200 with a status, not `OverResourceBound` (-32003, which nothing uses). `fill_pow_hash` is **silently blanked** on view for two methods (`pow_hash_entitled`), which §6.3 forbids. `calc_pow` and `get_coinbase_tx_sum` have no cost bound. **There is no server timeout:** no `TimeoutLayer`, no header-read or keep-alive setting; tower-http is built with `cors` and `limit` only. The body limit, 10 MiB, applies to both listeners; `ServerConfig.body_limit` is never read |
| F-10 | Connection limits carry over to the channel | `shekyl-daemon-rpc/src/conn_limit.rs:61-65`, `:156-189`, `:266-305` | **TCP and IP only.** `LimitedListener` is concrete over `TcpListener` and admits by `IpAddr`. Production sets the per-IP caps to 0 (`ffi_exports.rs:184`) and the total to 25. A channel connection needs its own admission: the handshake budget, then a per-client limit keyed on the authenticated fingerprint |
| F-11 | The router can serve a non-TCP stream | `axum-0.8.8/src/serve/mod.rs:97-100`; `axum-0.8.8/src/serve/listener.rs:9-24`; `shekyl-rpc-stream/src/lib.rs:647`, `:677`; `shekyl-rpc-stream/src/tests/mod.rs:497-498` | **Yes.** `axum::serve` needs only `AsyncRead + AsyncWrite + Unpin + Send + 'static`, which `RecordStream` meets, and rpc-stream's own tests serve hyper per connection over it. Per-connection state needs a layer that stamps a request extension (RT-O32) |
| F-12 | The handshake's daemon side is usable from a listener | `shekyl-rpc-channel/src/handshake.rs:534-1048`; `budget.rs:106`, `:147`; `deadline.rs:18-32` | **Yes, with gaps.** `Daemon::new` → `read_message1(wire, &HandshakeBudget, Instant)` → … → `AuthenticatedSession { client, request, send, recv, handshake_hash }` (`handshake.rs:926`). The budget is reached only through `read_message1`. The deadlines are constants, and `deadline.rs:18` names RT-W10 as their enforcer. The crate has no production consumer yet |
| F-13 | Message 3 and message 4 have fixed lengths | `handshake.rs:465`, `:716`, `:738`, `:770-803`, `:931` | **No.** Messages 1 and 2 are exact-length (`:566`, `:363`). Messages 3 and 4 check a **minimum only**, write any payload length, and `AuthenticatedSession.request` is an unbounded `Vec<u8>`. §6.2 rules both payloads fixed-length (RT-O31) |
| F-14 | The daemon has a static key to load | `shekyl-rpc-channel/src/identity.rs:104-145` | **No key exists, and none can be saved.** `StaticKeypair` has `generate()` and `public()` only; its secret halves are `pub(super)`, with no to-bytes or from-bytes. No daemon key file and no enrolment store exist anywhere (RT-O34) |
| F-15 | A same-user socket or pipe exists to reuse | `shekyl-wallet-rpc/src/server.rs:549-566`, `:713`, `:741-754`; `shekyl-win-sec/src/pipe.rs:83`, `:176`, `:405`; `shekyl-win-sec/src/sddl.rs:142` | **The wallet RPC's.** An owner-only Unix socket in a 0700 directory (0600 socket), and an owner-only Windows pipe with a verified open. Nothing for the daemon: no socket, pipe, rendezvous file, watcher, socket-directory option or instance option. `rpc-listen` is reserved for this slice (`table.rs:254-265`). No `notify` or `inotify` crate is in the lock file |
| F-16 | The rendezvous name is computed | `shekyl-rpc-channel/src/lib.rs:158`, `:189`, `:236`; `shekyl-daemon/src/run.rs:58-63` | **Yes.** `rendezvous_name(network_id, instance)` (12 bytes, hex) and `InstanceName::parse` (1–16 of `[a-z0-9-]`, `default` refused) exist from RT-W8, and the daemon already resolves its network id |
| F-17 | The run mode and data home are resolved | `shekyl-daemon-config/src/platform.rs:17-22`; `paths.rs:28-46`; `resolve.rs:49-65`; `shekyl-ffi/src/data_dir_ffi.rs:24`, `:94`; `shekyl-daemon/src/run.rs:144` | `RunMode::{User, Service}` and the per-mode root exist, but `Service` is unreachable (the `service` row is reserved for RT-W14; `data_dir_ffi.rs` hard-codes `User`). The data-home lock §5's console-key reset needs is `shekyld.lock`, taken at `run.rs:144` |
| F-18 | `get_info` is native (RK-5c) | `docs/design/IMPLEMENTATION_INDEX.md:672`; `shekyl-daemon-rpc/src/info.rs:70-133`, `:150` | **Yes, since 2026-10-13.** `Disclosure::from_listener(restricted)` (`info.rs:120-127`) is the seam RT-W10 replaces with the connection's grant. The §13 row and the index still list RK-5c as a dependency |
| F-19 | `option_set` and `option_show` exist | `shekyl-daemon-rpc/src/options.rs:28-49`, `:405-437`; `shekyl-daemon/src/run.rs:268` | **Yes.** `option_show` filters rows by `Disclosure`, so it follows the grant once `Disclosure` does |
| F-20 | `submit_transaction` can read the record shape | `shekyl-daemon-rpc/src/handlers/submit.rs:28-75`; `shekyl-rpc-stream/src/frame.rs:41-58` | **Once it reaches the handler.** The body is extracted in full before the handler runs, which is when `InboundShape::ends_in_submission` is meant to be read. The handle must come from the connection (RT-O32) |
| F-21 | Where the RPC server starts | `src/daemon/main.cpp:183-193`; `shekyl-daemon/src/run.rs:322`; `src/daemon/daemon.cpp:205`; `shekyl-daemon-rpc/src/ffi_exports.rs:173-223` | The C++ remnant calls `shekyl_daemon_rpc_start` after building the core; `start` builds a dedicated runtime and spawns `serve_presets`. A channel listener and a socket listener join there |
| F-22 | §11.2 still lists what RT-W10 removes | `RPC_CHANNEL.md` §11.2; `Dockerfile:71`; `README.md:686`; `docs/DAEMON_RPC_RUST.md:201-257`; `shekyl-daemon-rpc/src/bind.rs:64-83`, `:224-263`; `ctl_client.rs:89-146` | **Partly stale.** The flag rows name deleted files. The `bind.rs` remedy text and its one onion test, `ctl_client.rs`'s plaintext loopback TCP, and the CLI's `info.restricted` refusal (`shekyl-cli/src/commands/mine.rs:78-84`) still exist. Not listed: `Dockerfile:71` still passes `--restricted-rpc` and other removed names, which today's daemon refuses |

---

## 3. What was and was not executed

- **Read, not run:** everything in §2. No build, test or measurement was
  made for this pre-flight.
- **Not done, because the artifact does not exist:** every listener, the
  key file, the enrolment store, the grant column. They are this slice's
  output.
- **Cannot be done from this lane alone:** §6.3's floor-device
  measurement, which needs the floor device under a quiet claim and is
  registered before it runs; RT-P8 item 1, which needs the rendezvous
  this slice builds and the Windows lane to run it.

---

## 4. The questions — POSED 2026-10-25

### RT-O30 — What does message 4 carry?

§6.2 left this open for this pre-flight. When message 4 is written, the
daemon holds the claimed fingerprint and nothing the client asked for: the
handshake withholds the request until the first transport record opens.

- **(a) The ceiling.** It depends on the identity alone, which is all the
  daemon has. Both sides compute the effective grant, the request clamped
  to the ceiling, once the first record opens. A clamped client still
  knows at connect time, because it knows what it asked for.
- **(b) The effective grant.** The handshake hands the request to one
  function whose only output is message 4's payload. The request is then
  in daemon code before authentication, and keeping it out of logs and
  counters there is a convention.

**Recommended: (a).** Nothing computed from an unauthenticated request
leaves the daemon, and the handshake's types already enforce that.

### RT-O31 — The message-3 and message-4 payload encoding

§6.2 rules both payloads fixed-length, one length for every grant. The
handshake checks only a minimum (F-13).

**Recommended:** both payloads are the same 16 bytes. Byte 0 is a version
(1). Bytes 1–2 are a little-endian bit set over §6.1's twelve grants.
Bytes 3–15 are zero. Which bit is which grant is a code constant pinned by
a known answer (rule 30), with §6.1's table as its source, so editing the
document never changes the wire. Message 3 carries the request;
message 4 carries the ceiling (RT-O30). The handshake takes the exact
lengths as constants and refuses any other, so message 3 and message 4 are
each one size on the wire, and the listener knows how many bytes to read.
An unknown version, a set bit past the twelfth or a nonzero reserved byte
is refused like any malformed message.

### RT-O32 — How a connection's grant reaches a handler

Today a grant is a router (F-2).

**Recommended:** each connection is served by its own hyper connection
(`serve_connection`), wrapping the one router in a layer that stamps a
request extension: the connection's effective grant, its host flag
(§6.1's host-only classes), and, on a channel connection, its
`InboundShape`. `AppState.restricted` goes; every gate in F-3 reads the
extension. The plaintext listeners stamp their preset's grant. The C++
origin carries the host flag only, which is what the pool reads use it
for.

### RT-O33 — When plaintext loopback loses `submit` and `mining-work`

The row says plaintext loopback is re-scoped to `view`. The view listener
serves submission and mining-work today, and the GUI uses only it (F-5,
F-6). Re-scoping in RT-W10 would cut the GUI's submissions and mining until
the GUI moves to the same-user socket in RT-W12, which the slice order puts
after RT-W11.

- **(a)** Keep plaintext loopback's present method set in RT-W10, named
  for what it is, and re-scope it to `view` in RT-W12 with the GUI's move.
- **(b)** Re-scope in RT-W10, and move the GUI to the admin preset until
  RT-W12.
- **(c)** Move the GUI to the same-user socket inside RT-W10.

**Recommended: (a).** Nothing breaks between slices; the deletion lands
with the consumers that no longer need it. The console is the exception:
it moves to the same-user socket inside RT-W10 (§5 step 5), because it is
the daemon's own. (b) widens the GUI's grant to admin and leaves the
wallets where they are; (c) pulls a client slice's work into this one.

The question covers every consumer F-6 names, not the GUI alone: the
wallet clients reach the admin listener by default, so a re-scope in
RT-W10 cuts them too.

### RT-O34 — Where the daemon's static key and the enrolments live

No key file and no enrolment store exist (F-14). §5: the enrolled set is
daemon state changed only through `rpc-enrol` and `rpc-revoke`, with no
file to edit behind the daemon's back.

**Recommended:**

- **The key:** `shekyl-rpc-channel` gains a serialised form for
  `StaticKeypair`, into and out of `Zeroizing` bytes only (rules 35, 36).
  The daemon generates its bundle on first start and keeps it in its data
  home, readable only by the daemon's own user (owner-only on Unix;
  `OwnerOnlyDescriptor::private_file` on Windows).
- **The enrolments:** a redb store of their own in the data home (redb is
  the daemon's backend), owned by the RPC channel. They are not chain data, and the chain store is the chain's.
  One record per fingerprint: its ceiling, and when and by whom it was
  enrolled.

### RT-O35 — The console key and the other service-mode pieces

§5's console key, the enrolment at install and the console-key reset
exist for a service-mode daemon, which is unreachable until RT-W14 (F-17).
A run-as-me daemon needs none of them: its owner reaches it over the
socket or pipe.

**Recommended:** they land in RT-W14, beside the dispatcher that makes
service mode reachable. RT-W10 builds run-as-me only, and its owner enrols
the first key over the socket.

### RT-O36 — The armed switch and nettype: two rulings

`INPUT_GRAMMAR.md` IG-Q49 (2026-10-19) rules the armed levers never on
mainnet, and the option table carries that as `dev-rpc` accepted on the
test networks only. `RPC_CHANNEL.md` §6.1 (2026-10-09) rules the
override "never selected by nettype" (rule 71).

- **(a)** IG-Q49 stands. §6.1 names it as the ratified divergence rule 71
  allows: named, ruled, and loud (the switch is refused on mainnet with
  its own diagnostic, and logged when armed).
- **(b)** §6.1 stands. `dev-rpc` is accepted on every network, armed only
  by its explicit switch, and IG-Q49's row changes in the grammar round.

**Recommended: (a).** It is the later ruling, made with the option table
in view. The levers roll back or mint chain state, and "never on mainnet"
is the operator's protection against arming them there by mistake. The
change to §6.1 is one paragraph; either way, it is relayed to the grammar
round, which owns the option table.

---

## 5. Plan

One pull request per step, each a draft off `dev`, each reviewable alone.
This document is step 0 and is the only content of the first.

| # | Step | Depends on | Notes |
|---|---|---|---|
| 0 | This pre-flight | — | Docs only |
| 1 | Grants as types, on today's listeners | RT-O32 | The method table gains §6.1's grant column. A connection's grant reaches handlers by request extension; `restricted` goes from Rust and from the FFI. A refusal is `OutsideTheGrant` (-32002). The armed switch is routed (`admit_armed` on every armed lever, `/pop_blocks` included) and logged at every start; its network rule follows RT-O36. Plaintext loopback keeps its method set (RT-O33) |
| 2 | The resource policy | step 1 | §6.3's bounds per grant, not per listener, refused as `OverResourceBound`; `fill_pow_hash` refused, never blanked; cost bounds for `calc_pow` and `get_coinbase_tx_sum`; server timeouts. The floor-device measurement is registered before it runs |
| 3 | The same-user socket or pipe | step 1 | The rendezvous (§7.1), the instance-name rule, the operator-named socket directory, the daemon watching its rendezvous and stopping when it goes. Built on the wallet RPC's owner-only socket and `shekyl-win-sec`'s pipe (F-15). Owner connections stamp the owner's grant |
| 4 | The key, the channel listener and enrolment | steps 1–3; RT-O30, RT-O31, RT-O34 | The key file; `rpc-listen` (the reserved row); the handshake driven with the 4 s and 11 s deadlines, mac1, the budget and busy; the fixed payloads; `RecordStream` into the router; per-client admission by fingerprint; the enrolment store, `rpc-enrol` and `rpc-revoke` (RT-O9.1's bounds), revocation closing live sessions; the `submit_transaction` route refusing a body whose `InboundShape` is not a submission (close-out F2) |
| 5 | The posture's remainder | step 4 | §11.2's rows that this slice owns, `bind.rs`'s remedy text and its test, `ctl_client.rs` onto the socket, `Dockerfile:71`, `DAEMON_RPC_RUST.md`'s restricted-mode text. RT-W13's check runs after |

**Named edits, fixed now so they are not improvised later.**

- *Grant gate:* serve a `view` connection a `submit` method with the gate
  removed; the gate test must fail.
- *Armed switch:* call `/pop_blocks` unarmed with `admit_armed` removed
  from its route; the test must fail.
- *Payload length:* give `read_message3` a payload one byte long; the
  handshake must refuse it.
- *Submission shape:* send an unpadded `submit_transaction` over the
  channel with the shape check removed; the route test must fail.
- *Revocation:* revoke a fingerprint with the session index removed; the
  live-session test must fail.

**What stops the slice.** The parent design describes what is built. If
building a step shows the design is wrong anywhere, the work stops and
that is reported; the code is not bent to fit.

RT-W11 is not started from this slice.
