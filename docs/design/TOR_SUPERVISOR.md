# The managed Tor supervisor — one owner, usable rather than alive, never gives up

**Status: OPEN — Round 0, posed 2026-10-14; `TSV-Q1`…`TSV-Q12` await Rick's
rulings.** The rulings in §1 are Rick's of 2026-10-14, carried in the
daemon-configuration lane's brief to the Tor lane; nothing else here is ruled.
Identifier families (registered at birth, rule 94): `TSV-1…TSV-N` findings
from grounding, `TSV-F1…TSV-FN` places where the brief or a ruled document
disagrees with the code or the specification, `TSV-B1…TSV-BN` the bounds
to be measured (§5), `TSV-Q1…TSV-QN` the questions this round poses. Rule 26 is cited: this changes a process lifecycle that
every connector depends on, an FFI boundary, and the threat posture of the
node's Tor identity.

Code anchors are verified at `dev` `e4d100fb1`. The brief's pin `1b7803f69`
is its ancestor, and no commit between them touches the three Tor crates or
`src/p2p`. PR #1056 (P2P PR-3) is cited at its head `44f5548c1` and its rig at
build `19863b044`; PR #1066 (daemon configuration) at `dc614386b`. Anchors on
those branches name the PR beside the path, as in `path` lines N-M (#1056).

This round amends, on ratification, three ruled positions and restates none:
[`P2P_2_ENDPOINT_ROUND.md`](P2P_2_ENDPOINT_ROUND.md) PWD-E7's seam rows
"Restart" and "tor control unavailable" (`:605-606`);
[`TOR_BUNDLE_DISTRIBUTION.md`](TOR_BUNDLE_DISTRIBUTION.md) `TB-3`; and the
no-respawn disposition in `rust/shekyl-tor-control-daemon/src/lib.rs:40-46`
with its FFI echo (`rust/shekyl-ffi/src/daemon_tor_ffi.rs:320-323`).
[`ARCHIVAL_BOND_2D2_SP_T0_TOR.md`](ARCHIVAL_BOND_2D2_SP_T0_TOR.md) §3b's
retraction stays true for the wallet; §3.4 says why it does not bind the
daemon.

---

## 0. The standard

The managed Tor works all the time on every supported machine. The test is
**usable**, not alive: the daemon reaches the Tor network through it, and
peers reach the daemon's onion through it, continuously. Every failure has a
name, an announcement and a fix, and every failure the node can recover from
itself, it recovers from. Nothing is called "24/7" before §9's matrix and
soak pass.

## 1. Rulings this round is built on (Rick, 2026-10-14)

| Ruling | Content |
| --- | --- |
| Supervisor | One Rust owner holds the managed Tor's state machine `Bootstrapping → Usable → Degraded → Restarting`. Inputs: the child process; Tor's status events; `HS_DESC` events; a periodic end-to-end probe that dials our own onion through our own Tor. *Usable* is defined by the probe. Every other component (dialer, hop-0 draw, posture line, RPC health) subscribes to this owner and none reads Tor state on its own |
| Start is iteration one | No separate bootstrap-failure path. The supervisor runs from the first launch with capped backoff and never gives up. A Tor-only node waits and announces (hop-0 fail-closed: send nothing rather than fall back); a dual-posture node runs clearnet meanwhile |
| Respawn | On death, or on *Degraded* past a bound: reap, fresh `DataDirectory`, fresh ephemeral onion (`DiscardPK`); the dialer pauses the connector and resumes on the new SOCKS address; each death and recovery announced; a crash loop reaches the backoff cap with a loud announcement. Backoff with resume for an operator's Tor |
| Teardown | Close the owning control connection (`TAKEOWNERSHIP`: Tor exits when it closes, without waiting for circuits; a non-`Detach` onion dies with it), wait within `SHUTDOWN_GRACE` (5 s), kill and reap, **then** tombstone-rename the `DataDirectory`; delete it off the runtime under a bound; the start sweep matches tombstones before Tor starts. `SIGTERM` and `DEL_ONION` are dropped. One routine serves stop and respawn |
| Launch | `__OwningControllerProcess=<daemon pid>` on the command line, `TAKEOWNERSHIP`, then `RESETCONF __OwningControllerProcess` |
| Disk | `AvoidDiskWrites 1` on every platform. No memory-backed `DataDirectory` |
| Requirements | The brief's §2 items 3 to 7 (rule-82 states, one log stream, suspend and resume, floor-device resource bounds, Windows first-class) are requirements of this round, not follow-ups |
| Acceptance | §9's matrix on Linux, Windows and macOS, then a seven-day soak on each, with a Pi 4 as the Linux host |

The brief's own pointer (`TAKEOWNERSHIP` "without waiting for circuits") is
the control specification's text: "As of Tor 0.2.5.2-alpha, Tor does not wait
a while for circuits to close when shutting down because of an exiting
controller" (control-spec, *Commands*, `TAKEOWNERSHIP`).

## 2. What exists today (findings)

| Id | Finding | Anchor |
| --- | --- | --- |
| **TSV-1** | **Health is one bootstrap poll.** Readiness is `GETINFO status/bootstrap-phase` every 500 ms until `Ready`, then nothing. No production code issues `SETEVENTS`; the daemon passes `EventSink::unsubscribed()`, whose own doc says the first production `SETEVENTS` must replace it | `control/bootstrap.rs:10-11`; `control/actor.rs:211-239`, `:668`, `:1117-1153`; `shekyl-tor-control-daemon/src/ephemeral.rs:253` |
| **TSV-2** | **Death is seen only as the control connection ending.** There is no watcher on the child after spawn: `child.wait()` runs in the spawn race and inside shutdown only. A Tor that wedges with its control socket open is not seen at all | `control/actor.rs:1011`, `:616`, `:1260-1266`, `:1306-1313` |
| **TSV-3** | **The one death notice is filtered out at the default log level.** `check_ephemeral_tor_liveness` polls every 60 s and on the death edge writes one `MERROR` under `net.p2p`; the default filter is `net.p2p:FATAL` | `src/p2p/net_node.inl:71`, `:2297-2315`; `net_node.h:756`; `contrib/epee/src/mlog.cpp:127` |
| **TSV-4** | **The no-respawn premise is half gone.** `lib.rs:40-46` forbids respawn because "the C++ consumer's zone/proxy configuration is init-time static". The Rust dial path already reads the SOCKS address per dial from `Host.tor_proxy`; only its writer is init-time. The C++ copy `zone.m_proxy_address` is static and leaves with the daemon-configuration cutover | `rust/shekyl-ffi/src/zone_ffi.rs` lines 63 and 172-178 (#1056); `src/p2p/net_node.inl:979` |
| **TSV-5** | **The launch names no owner, and its argument surface is closed by a test.** `TAKEOWNERSHIP` is sent after `AUTHENTICATE`; `__OwningControllerProcess` is not passed, so a daemon that dies between spawn and that command leaves Tor running. `the_managed_launch_surface_is_the_typed_options` pins the argument list; this round widens it on purpose (§3.8), and the test is edited in the same change | `control/actor.rs:854-861`, `:874-954`, `:1485-1497` |
| **TSV-6** | **Teardown today is `DEL_ONION`, `SIGTERM`, 5 s, `SIGKILL`, reap, then a synchronous wipe, and it is slow.** `REAP_TIMEOUT` (15 s) bounds the graceful stop and reap only; `kill()` and the wipe are unbounded. PR-3's rig measured the managed Tor's teardown at p50 0.1 s, p90 20.5 s, max 54.9 s over 99 stops, with the dialer redialling through the dying proxy (up to 56 `LocalClose` dials in one stop) | `control/actor.rs:611-632`, `:783-798`; `ephemeral.rs:66`, `:395-415`; `data_dir.rs`; `docs/FOLLOWUPS.md` line 1035 (#1056) |
| **TSV-7** | **The wallet already has the supervisor's shape.** A plain owned task: spawn, await death or shutdown, classify, publish posture on a `watch`, back off, respawn, never give up; every spawn re-runs the pin gate; `SocksPort auto` and a fresh `GETINFO net/listeners/socks` per incarnation. Its defaults: 1 s base, 60 s cap, `Degraded` after 5 failures, 600 s of `Ready` resets the count. PWD-E9 forbids sharing the supervisor *instance* or its state with the daemon; library reuse is allowed | `shekyl-tor-control-wallet/src/service.rs:289-303`, `:541-648`; SP-T0 §3c (`:572-656`); PWD-E9 `:756` |
| **TSV-8** | **Cold starts fail and cold dials are slow, measured.** PR-3's run A (x86 client on the measurement host, fresh data directory per sample, pinned 15.0.24 bundle): 5 of 100 managed Tors did not bootstrap within 120 s, and the daemon log said nothing; Tor dial start to SOCKS success p50 4.51 s, p99 8.47 s over the 66 sessions, and 26 of 100 cold dials exceeded the 9.1 s dial deadline. Censored at both ends; not floor-device figures | `docs/benchmarks/p2p_tor_gap_cold_20261014.md` (#1056) (run A); `docs/FOLLOWUPS.md` line 1038 (#1056) |
| **TSV-9** | **The daemon cannot reap its own children while `tools::spawn` ignores `SIGCHLD`.** `signal(SIGCHLD, SIG_IGN)` makes the kernel reap every child, the managed Tor included: tokio's wait fails with `ECHILD` on Linux and never completes on macOS and FreeBSD. Respawn depends on reaping; DC-F12's fix ("the Rust runner reaps its own children and never changes a signal disposition") is a prerequisite of this round's implementation | `docs/design/DAEMON_CONFIG_CUTOVER.md` line 800 (#1066) (DC-F12) |
| **TSV-10** | **Windows and macOS have no managed Tor yet.** Both are `unavailable` with `"pending": "TB-11"` in `config/tor_pins.json` until each has a launch test. §9's matrix on those platforms needs TB-11's pins adopted first | `TOR_BUNDLE_DISTRIBUTION.md` TB-11, §5 step 2 |
| **TSV-11** | **`get_info` carries no Tor fact.** `InfoHealth` has no Tor field; the per-connector Tor socket counts are `peers`-grant facts | `rust/shekyl-rpc-types/src/info.rs:97-122`, `:214-220` |
| **TSV-12** | **The only dialer lever is the per-connector target, and the owner loop lives as long as the dialer.** `set_target(0)` is legal and dials nothing; `claim_owner` refuses a second loop. A pause and resume therefore changes the target and the proxy slot, and never restarts the loop. A closed SOCKS port is `LocalClose`, which by design does not implicate the address and does not back off | `rust/shekyl-dialer/src/owner.rs` lines 226-232 and 258-266 (#1056); `rust/shekyl-tor/src/drive.rs` lines 217-218 (#1056); `rust/shekyl-transport-layer/src/cause.rs` lines 215-218 (#1056) |

### Where the brief or a ruled document disagrees with the source

| Id | Disagreement | Resolution proposed |
| --- | --- | --- |
| **TSV-F1** | The brief puts `CLOCK_SKEW` and `DANGEROUS_VERSION` under `STATUS_CLIENT`. The control specification (*Replies*, Status events) lists them under **`STATUS_GENERAL`**, with `CLOCK_JUMPED` (Tor's own suspend detection), `TOO_MANY_CONNECTIONS` (the descriptor limit) and `DIR_ALL_UNREACHABLE`. `STATUS_CLIENT` carries `BOOTSTRAP`, `ENOUGH_DIR_INFO`, `NOT_ENOUGH_DIR_INFO`, `CIRCUIT_ESTABLISHED`, `CIRCUIT_NOT_ESTABLISHED` | The supervisor subscribes to both classes and to `NETWORK_LIVENESS` (§3.4) |
| **TSV-F2** | The brief asks for a rule-82 state for "DNS failure". A Tor client bootstraps from the fallback directories and authorities it ships with, by IP address; the daemon's Tor dials are onion-only; and IG-Q6 removed hostnames from peer endpoints. The managed Tor has no DNS step to fail | Posed as `TSV-Q10` rather than minted as a state |
| **TSV-F3** | The brief exposes "state, since when, respawn count this boot" in `get_info`'s `health` fields. [`RPC_CHANNEL.md`](RPC_CHANNEL.md) §6.1 admits a `health` fact only if a client needs it to decide whether it can use this node now **and** it says nothing lasting about the node. The state passes. "Since when" and a respawn count describe this host's history: they are `status`-grant facts, as the node's start time already is | Relayed to the RPC lane as `TSV-Q11` |
| **TSV-F4** | The brief has the supervisor "stopped in step 9 in parallel with the core stop". #1066's step 9 is sequential ("stops the dialer and the zone host, stops the RPC, calls the remnant's `stop()`, joins the `run` thread, stops the managed Tor"), and PR-3's rig shows the dialer must stop **before** the Tor teardown (TSV-6) | The ordering constraint is the dialer before Tor; Tor may stop in parallel with the core after that. Relayed to #1066 (§6) |
| **TSV-F5** | SP-T0 §3b withdrew a `STATUS_CLIENT` subscription because `SETEVENTS` is "a shared, replace-not-add resource the consumer also uses". On the daemon there is no second consumer: the ruling makes the supervisor the only reader of Tor state, so it is the only writer of `SETEVENTS` on its connection | §3.4. The retraction stands for the wallet, unamended |

## 3. The design

### 3.1 Owner and placement

`shekyl-tor-control-daemon` gains one owned task, the **daemon Tor
supervisor**, which replaces the one-incarnation `DaemonTorControl` handle as
the crate's public surface. It follows the wallet supervisor's shape (TSV-7)
and shares no instance, connection, directory or state with it (PWD-E9). Where
both need the same arithmetic (backoff, the failure classes), that code moves
into `shekyl-tor-control-client`, which both already name. The task owns:

- the child process and its one owning control connection;
- the `SETEVENTS` set on that connection (§3.4);
- the probe (§3.5);
- the backoff, the respawn and the one teardown routine (§3.6, §3.7);
- one `watch` channel carrying the state below, which is the only Tor fact any
  other component reads.

The FFI's process singleton (`daemon_tor_ffi.rs:61`) and the C++ liveness poll
go (§10). Under #1066 the supervisor is started by the Rust `main()` in step 6
and stopped in step 9; there is no C++ caller.

### 3.2 The state machine

| State | Carries | Meaning |
| --- | --- | --- |
| `Bootstrapping` | attempt, progress (telemetry only), the current operator-fixable cause if any | An incarnation is starting. The connector is paused |
| `Usable` | SOCKS address, onion (`ServiceId`), since | §3.3's definition holds. The connector runs on this SOCKS address |
| `Degraded` | cause, since | The incarnation is up and §3.3's definition does not hold. The connector stays paused if outbound is the failing direction, and runs if only inbound is |
| `Restarting` | attempt, retry in, cause | The incarnation is torn down; the next starts after the delay. The connector is paused |

There is no terminal state. A clean stop ends the task and drops the sender,
as the wallet's does (`service.rs:88-91`).

| From | Input | To |
| --- | --- | --- |
| `Bootstrapping` | `CIRCUIT_ESTABLISHED`, SOCKS listener found, onion published, first probe succeeds | `Usable` |
| `Bootstrapping` | bootstrap bound passes (`TSV-B3`) | `Restarting` |
| any | the child exits, or the control connection ends | `Restarting` |
| `Usable` | a §3.3 condition fails (`NOT_ENOUGH_DIR_INFO`, `CIRCUIT_NOT_ESTABLISHED`, `NETWORK_LIVENESS DOWN`, upload failed past `TSV-B5`, probe failed past `TSV-B6`, a local check fails) | `Degraded` |
| `Degraded` | the condition clears | `Usable` |
| `Degraded` | the condition persists past `TSV-B7` | `Restarting` |
| `Restarting` | the delay passes | `Bootstrapping` |

A transition announces (§3.11). A transition into `Restarting` raises the
attempt count; `TSV-B2` of continuous `Usable` resets it, as the wallet's
`stable_reset` does.

### 3.3 What "usable" means

*Usable* is defined by the probe (§1). The probe needs a published onion, and
the ruled degrade for a failed publish is outbound-only (`ephemeral.rs`
publish doc; PWD-E7 `:606`), so the definition is per direction:

- **Outbound usable:** a SOCKS listener exists, the last status is
  `CIRCUIT_ESTABLISHED` with no later `NOT_ENOUGH_DIR_INFO`,
  `CIRCUIT_NOT_ESTABLISHED` or `NETWORK_LIVENESS DOWN`.
- **Inbound usable:** the onion is published, the last `HS_DESC` for it is
  `UPLOADED` or a failure younger than `TSV-B5`, and the last probe succeeded
  within `TSV-B6`.
- **Usable** is both. A node whose publish failed is `Degraded` with that
  cause, and §3.6 decides whether that cause respawns (`TSV-Q2`).

A probe success implies outbound usable, since it leaves through our own SOCKS
port. Outbound usable never rests on a probe to a third party's onion: dialling
a fixed destination on a period is a beacon (§7, objective 2).

### 3.4 Events

After `AUTHENTICATE` and `TAKEOWNERSHIP`, the supervisor sends one
`SETEVENTS STATUS_GENERAL STATUS_CLIENT HS_DESC NETWORK_LIVENESS NOTICE WARN ERR`
and nothing else ever sends `SETEVENTS` on that connection. That is what
dissolves SP-T0 §3b's objection for the daemon: the union it had to manage was
two consumers' sets on one connection, and here there is one (TSV-F5). The
inbound events are parsed by a sans-IO parser beside `stream.rs`, pinned by
known-answer tests on the specification's grammar, tolerant of unknown actions,
arguments and order as the specification requires.

Progress comes from `BOOTSTRAP` events, seeded by one
`GETINFO status/bootstrap-phase` sent after `SETEVENTS` so a phase that
completed before the subscription is not missed. The 500 ms poll stays in the
client crate for the wallet and is not used on the daemon path. `BOOTSTRAP`
`WARN` events carry `REASON` (the `ORCONN` reasons) and `RECOMMENDATION`; the
supervisor names a cause from them only when `RECOMMENDATION=warn`, which Tor
sends from the tenth problem at a phase onward, so a few refused connections at
startup do not raise a state.

### 3.5 The probe

Every `TSV-B6` period, with jitter, the supervisor opens a SOCKS5 `CONNECT` to
its own onion through its own SOCKS port, using `shekyl_socks::connect`
(`rust/shekyl-socks/src/lib.rs:148`) with a fresh isolation principal per
probe so that every probe builds a fresh rendezvous circuit rather than
reusing one (`Isolation::Principal`, `:52`; the launch already sets
`ExtendedErrors`, `actor.rs:900-901`).

- **Success** is the SOCKS reply `0x00`. The onion service's side answers the
  client's `BEGIN` only after it has connected to its local target, so success
  means: our Tor fetched or held the descriptor, introduced, rendezvoused, and
  the forward reached the loopback listener.
- **Failure** is classified by the reply byte, so `Degraded` names a cause:
  `0xF0` descriptor not found, `0xF1` descriptor invalid, `0xF2` introduction
  failed, `0xF3` rendezvous failed, `0xF7` introduction timed out, a timeout at
  `TSV-B8`, or our SOCKS port refusing the connection.
- **What it does not test:** that a stranger's Tor can reach us through a guard
  that is not ours. Both legs of a self-dial leave through one guard set
  (one process, one guard set: `SP_T3_SKELETON_MEASUREMENT.md` SPIKE-F-12). The descriptor's
  freshness is `HS_DESC`'s job, not the probe's: the client side caches the
  descriptor across probes.
- **Where it lands** is `TSV-Q1`: the P2P virtual port, which the zone host
  must then recognise and close without counting it as a peer, or a second
  virtual port forwarding to a listener the supervisor owns, which writes
  nothing and reads only the probe's nonce.

The probe's timeout cannot be borrowed from the dialer's 9.1 s dial deadline:
26 of 100 cold dials on the measurement host exceeded it (TSV-8). It is
measured uncensored on the floor device (§5, `TSV-B8`).

### 3.6 Respawn

On an input that moves to `Restarting`:

1. Publish `Restarting`. The connector pauses: the zone host sets the Tor
   target to 0 and clears `Host.tor_proxy` (TSV-12), so no dial runs through a
   proxy that is going away. Every Tor session dies with the incarnation; the
   hidden-address pool is therefore empty, and `RelayPlan::NoOwnEdge` fires for
   a local origin (`rust/shekyl-relay/src/graph/mod.rs:265-278`): hop-0 is
   fail-closed by the existing rule, with no new one.
2. Run the teardown routine (§3.7).
3. Wait the backoff delay: `base · 2^(attempt−1)`, capped at `TSV-B1`. At the
   cap, announce loudly with the attempt count; repeat that announcement once
   per cap interval for as long as the loop runs, never more often.
4. Re-run the binary pin gate (as the wallet does, SP-T0 §3c). A pin failure at
   runtime means the file changed under a running daemon: `Degraded` with that
   cause, retried at the slow trust interval, never a refusal of the running
   node (TB-2 refuses at startup only).
5. Create a fresh `DataDirectory`, launch (§3.8), authenticate, take ownership,
   subscribe (§3.4), discover SOCKS, publish a fresh onion with `DiscardPK` and
   proof-of-work.
6. Publish `Bootstrapping`, then `Usable` when §3.3 holds. On `Usable` the
   zone host writes the new SOCKS address into `Host.tor_proxy` and restores
   the target. The new onion replaces the old one as the node's own address in
   the session layer, and the next disclosure carries it.

Peers holding the old onion lose us until gossip carries the new one. That
follows from ephemeral-per-boot and is accepted (brief §2.8); PWD-E8's
volatility measurement now counts respawns as well as restarts.

### 3.7 Teardown, the one routine

1. Close the owning control connection. Tor exits on its close (`TAKEOWNERSHIP`)
   without waiting for circuits; the onion, published without `Detach`, dies
   with it. No `DEL_ONION` and no `SIGTERM`.
2. Wait for the exit within `SHUTDOWN_GRACE` (`actor.rs:97`, 5 s).
3. If it has not exited, kill it and reap. On Windows the kill is
   `TerminateProcess`.
4. Rename the `DataDirectory` to a tombstone name in the same parent
   (`ephemeral-tor-<id>.tomb`). A rename in one directory is one metadata
   operation; it runs after the reap, so on Windows no Tor handle holds a file
   inside it.
5. Hand the tombstone to a blocking task that deletes it under `TSV-B9`. The
   routine returns at step 4: the stop path and the respawn path never wait on
   a recursive delete (TSV-6).
6. At start, before Tor launches, the sweep removes every `ephemeral-tor-*`
   entry, tombstones included (`data_dir.rs` already matches the prefix).

If the rename fails (a scanner holding a file on Windows), the directory stays
under its live name and the next start's sweep removes it; the failure is
logged with its cause. The same routine serves a daemon stop, a respawn and a
failed start.

### 3.8 Launch

The launch adds, to `managed_tor_command` (`actor.rs:874-954`):

- `__OwningControllerProcess <daemon pid>`, then after `TAKEOWNERSHIP`,
  `RESETCONF __OwningControllerProcess`, the control specification's recipe.
  Tor polls for the PID only between spawn and that `RESETCONF`, which is the
  window in which the daemon can die without closing a connection that owns
  Tor;
- `AvoidDiskWrites 1`;
- `MaxMemInQueues <TSV-B10>`, once measured;
- the file log moved out of the `DataDirectory` (§3.10).

`the_managed_launch_surface_is_the_typed_options` (`actor.rs:1485-1497`) is
edited in the same change, so the widening is visible to a reviewer as one
test diff. `TSV-Q3` poses the specification's other route,
`__OwningControllerFD`.

### 3.9 Time, suspend and resume

Backoff and probe timers run on the monotonic clock. Every supervisor tick
compares elapsed wall-clock time with elapsed monotonic time; a difference
beyond `TSV-B11`, or a `CLOCK_JUMPED` event from Tor, is treated as a resume:
the probe runs at once rather than at the next period. Whether a platform's
monotonic clock advances across suspend differs: Linux's `CLOCK_MONOTONIC`
does not, so after a long suspend a pending timer has *not* expired, and the
jump check is what notices. That per-platform behaviour is a §9 case, not an
assumption. A network change needs nothing of the supervisor: Tor handles the
address change, and the next probe confirms it did.

### 3.10 One log stream

`NOTICE`, `WARN` and `ERR` arrive over the control connection (§3.4) and go to
the daemon's log under a `tor` category. Tor's own `SafeLogging` stays at its
default, so addresses in those lines are scrubbed. Tor's file log moves out of
the `DataDirectory` to `tor-<incarnation>.log` in the parent, and the routine
keeps exactly the previous incarnation's file: a crash loop then keeps the last
dead incarnation's evidence when the tombstone deletes its directory, and the
next start's sweep removes it, so no Tor log survives into another boot's run.

### 3.11 Announcements

Every transition is an announcement in the IG-14 sense (`INPUT_GRAMMAR.md`
IG-14): it reaches the log and standard error whatever the log level, which
TSV-3's death notice does not today. The posture line (#1066 step 5) reads its
Tor clause from the current state. A Tor-only node in `Bootstrapping`,
`Degraded` or `Restarting` says that it is waiting, why, and that it sends
nothing meanwhile. Rule 81 applies: the words name what the operator sees and
can do, not Tor's vocabulary.

### 3.12 An operator's Tor and no Tor

With `tor = operator` the supervisor spawns nothing and holds no control
connection. Its inputs are a TCP connect to the operator's SOCKS endpoint and,
when `tor-onion` is set, the self-dial probe of that onion. A failure pauses
the connector, and the supervisor retries with the same capped backoff and
resumes when the endpoint answers. Its rule-82 messages say the operator's Tor
is not answering. With `tor = off` there is no supervisor.

## 4. The rule-82 table

Each row is a named cause carried by `Bootstrapping`, `Degraded` or
`Restarting`, announced, shown in the posture line, and present in the RPC's
Tor state (§6).

| Cause | Detected by | What the operator is told |
| --- | --- | --- |
| Clock wrong | `STATUS_GENERAL CLOCK_SKEW` with `SKEW` (seconds) | The clock is off by the offset, and Tor will not work until it is set; set the system clock or enable time synchronisation. The figure comes from an unauthenticated source, so the node never sets the clock itself |
| No network | `BOOTSTRAP WARN` with `RECOMMENDATION=warn` and `REASON` in `CONNECTREFUSED`, `NOROUTE`, `TIMEOUT`, `CONNECTRESET`, `IOERROR`; `NETWORK_LIVENESS DOWN`; `DIR_ALL_UNREACHABLE` | The node cannot reach the Tor network; check the connection and any firewall that blocks outbound connections. Tor-only: nothing is sent meanwhile |
| Disk | the supervisor's own check, before each launch and on every tick: it creates and removes a file in the parent and reads the free space | The directory cannot be written, or the disk is full, with the path. Tor's own warning text is not parsed: the specification tells controllers not to rely on its format |
| Too many open files | `STATUS_GENERAL TOO_MANY_CONNECTIONS` | The process limit on open files is reached, with the figure; raise it. Platform-specific wording |
| Tor version flagged | `STATUS_GENERAL DANGEROUS_VERSION` | The network no longer recommends this Tor; the fix is a Shekyl release with a new pin (TB-10), so the message says to upgrade Shekyl, never Tor |
| Onion not reachable | `HS_DESC FAILED` past `TSV-B5`; probe failure past `TSV-B6`, with its reply code | Peers cannot reach this node over Tor right now; the node is retrying, and restarts its Tor past a bound |
| Tor keeps failing | the attempt count at the backoff cap | The managed Tor has failed N times; the node keeps trying every `TSV-B1`; the last cause; where Tor's previous log is |
| Tor binary changed | the pin gate at respawn | The Tor files beside Shekyl changed while it ran; reinstall Shekyl |
| Publish refused | `ADD_ONION` refused, including `PowRefused` | Inbound over Tor is off this boot, with the reason (`TSV-Q2`) |

## 5. Bounds, measured before they are set

No row below has a value yet. Each starting point is a place the measurement
begins, never the value (rule 76; rule 26 B9). The floor device is the Pi 4;
the measurement host is a diagnostic, never the source.

| Bound | What it bounds | Starting point | Measured by |
| --- | --- | --- | --- |
| `TSV-B1` | backoff cap | the wallet's 60 s (`service.rs:293`) | fresh-directory bootstrap time on the floor device: a cap shorter than a bootstrap respawns a Tor that was about to succeed |
| `TSV-B2` | `Usable` time that resets the attempt count | the wallet's 600 s (`:295`) | the soak's distribution of time between failures |
| `TSV-B3` | bootstrap bound before `Restarting` | 300 s today (`net_node.inl:892`); 5 of 100 cold starts exceeded 120 s (TSV-8) | 100 cold starts on the floor device, uncensored, data directories kept for the failures |
| `TSV-B4` | backoff base | the wallet's 1 s (`:292`) | the same run |
| `TSV-B5` | descriptor-upload failure before `Degraded` | none | `HS_DESC` traces over the soak |
| `TSV-B6` | probe period, jitter, and failures before `Degraded` | none | the probe's success distribution over the soak; the period is also priced against the floor device's circuit cost |
| `TSV-B7` | `Degraded` before `Restarting` | none | the soak: how long a `Degraded` that recovers by itself lasts |
| `TSV-B8` | probe timeout | not the 9.1 s dial deadline (TSV-8) | cold self-dials on the floor device, deadline lifted as in PR-3's measurement build |
| `TSV-B9` | tombstone delete | none; today's wipe is unbounded inside a stop that reached 54.9 s (TSV-6) | delete time of a used `DataDirectory` on the floor device's SD card |
| `TSV-B10` | `MaxMemInQueues` | Tor's own default, derived from system memory | Tor's resident memory on the floor device under the dialer's target and the inbound ceiling, over the soak |
| `TSV-B11` | wall-against-monotonic difference that counts as a jump | none | the §9 suspend case on each platform |
| `TSV-B12` | file descriptors Tor needs | none | Tor's open descriptors on the floor device at the same load; the result decides whether the daemon raises its limit or only reports `TOO_MANY_CONNECTIONS` |

`AvoidDiskWrites 1` is ruled; its effect on write volume is recorded in the
same floor-device run, not assumed.

**Pre-flight (rule 26).** `TSV-B3`, `TSV-B9`, `TSV-B10` and `TSV-B12` are
measured before the first production commit; they need only today's managed
Tor. `TSV-B5` to `TSV-B8` and `TSV-B11` need the supervisor's own probe and
events, so they are measured on the implementation branch before its PR leaves
draft, and the constants land in the commit that records the measurement.

## 6. Interfaces to other lanes

- **Daemon configuration (#1066).** The supervisor starts in step 6 and stops
  in step 9. Under "start is iteration one" step 8 does **not** wait for Tor:
  the zone host and the dialer start with the Tor connector paused, and resume
  on `Usable`. That also removes the SCM start's dependence on bootstrap time
  (#1066 `:117-125`). Step 9's order: the dialer stops before the Tor teardown
  (TSV-F4); the Tor teardown may then run in parallel with the core stop. The
  SOCKS endpoint is a value the supervisor publishes, never configuration. The
  `tor` posture (`managed`, `operator`, `off`) is the supervisor's input.
  DC-F12's own-children reaping is a prerequisite (TSV-9). Relayed to that
  round under the IG-12 shared-ownership convention.
- **P2P (#1056).** The zone host subscribes to the state and drives the
  connector: target 0 and an empty proxy slot while not `Usable`, the new SOCKS
  address and the restored target on `Usable` (§3.6). The own-onion address in
  the session layer follows the state. Hop-0 needs nothing new (§3.6 step 1).
  PR-3's two FOLLOWUPS rows on the silent bootstrap and the slow stop
  (`docs/FOLLOWUPS.md` lines 1035 and 1038 on #1056) are answered by §3.7 and §3.11;
  once both PRs are on `dev` their owner cell can point here.
- **RPC.** The state is a `health` fact. The cause, "since" and the attempt
  count are `status` facts by RPC_CHANNEL §6.1's line (TSV-F3, `TSV-Q11`); the
  RPC lane names the fields.
- **Tor bundle (TB).** §9's Windows and macOS cases are TB-11's launch tests;
  they need TB-11's pins adopted (TSV-10).

## 7. Threat-model addenda (rule 26 A3)

| Objective | How | Route |
| --- | --- | --- |
| 1. **Induce respawns to sample guards and churn the onion** | An adversary who can make the node `Degraded` from outside (refuse descriptor uploads at the HSDirs it runs, drop the probe's introductions at an introduction point it runs) drives `Degraded` past `TSV-B7` into a respawn, and with a fresh `DataDirectory` each respawn draws fresh entry guards. Repeated, it walks the node through guard samples until one is the adversary's, and each respawn also mints an onion the adversary sees appear | `TSV-Q4` and §8. Candidates: a respawn caused by a *remote* condition is rate-limited separately from one caused by a local death; or guards persist within a boot (§8, option b) |
| 2. **Read the probe as a signature** | The entry guard sees the client circuit and the service's circuits of one process. A self-dial on a fixed period is a periodic pair of circuit builds at that guard, and periodic introductions at our introduction points | Jitter (§3.5); the period priced in `TSV-B6`; `TSV-Q5` asks whether the signature is accepted and stated |
| 3. **Learn the onion from the log** | Tor's `NOTICE` lines over the control port, now in the daemon's log | `SafeLogging` stays at its default (§3.10); the daemon's own lines print the onion only where the operator's posture output already does |
| 4. **Plant in the parent directory** | The sweep removes `ephemeral-tor-*` entries; a symlink planted under that name | `std::fs::remove_dir_all` does not follow a symlink at the top level or below; the parent is daemon-owned and the `DataDirectory` 0700. A test plants a symlink to a directory outside and asserts the target survives |
| 5. **Outlive the daemon** | The daemon dies between spawn and `TAKEOWNERSHIP`, or under `panic = "abort"` | `__OwningControllerProcess` covers the window; `TAKEOWNERSHIP` covers the rest. §9's "daemon stop under each trigger" includes `SIGKILL` of the daemon |

## 8. The guard question (brief §2.9)

`ephemeral.rs:80-83` makes the `DataDirectory` unique per boot and wiped "so a
restart cannot reuse entry guards", and PWD-E9 (`:826-828`) gives the reason:
entry guards "cannot join onions". The wallet's Tor persists its guards
(DQ-T0.7; `WALLET_SIDE_STORE.md:634`). Respawn now multiplies incarnations
within one boot, and the ruled respawn takes a fresh `DataDirectory` each time.

**The two harms, with the adversary on each side.**

- **Fresh guards per incarnation (today's rule, extended to respawns).**
  Adversary: an operator of a fraction `f` of guard capacity. Capability: the
  guard learns the client's address and sees the timing of all that
  process's traffic, since one Tor process draws one guard set for every
  circuit ([`SP_T3_SKELETON_MEASUREMENT.md`](SP_T3_SKELETON_MEASUREMENT.md)
  SPIKE-F-12). Harm: over `n` independent guard samples the chance
  that at least one is hostile is `1 − (1 − f)^n`, which tends to 1 as `n`
  grows. Tor's guard design exists to keep `n` small. Under respawn `n` is
  restarts plus respawns, and objective 1 of §7 lets an outside adversary raise
  it.
- **Persisted guards (across respawns, or across boots).** Adversary: one who
  wants to link two of this node's onions. Capability: guard discovery against
  an onion service (forcing circuits until the service's guard is identified).
  Harm: two onions behind the same guard set are likely one host. Within a boot
  the old and new onion are already linked by time (one disappears as the
  other appears); across boots the per-boot onion exists to break that link.

**Options.**

| | Within a boot | Across boots | Cost |
| --- | --- | --- | --- |
| (a) the ruled respawn | fresh guards per incarnation | fresh | `n` grows with every respawn; objective 1 is open |
| (b) persist within a boot | the first incarnation's guard `state` carried into each respawn's fresh `DataDirectory` | fresh | respawns add no guard samples; the boot's onions share a guard set, which they would also share by timing |
| (c) persist across boots | as (b) | carried | undoes PWD-E9's reason for the per-boot directory |

**Recommendation: (b).** It keeps PWD-E9's per-boot unlinkability and closes
objective 1's guard amplification, and costs a linkage that the respawn's
timing already gives away. It amends the brief's "fresh `DataDirectory`" only
in what is carried: the directory is new, the guard file inside it is the
boot's. **Reopen** if a measurement shows a respawn's onions are *not* linkable
by timing (for example, if respawns become rare enough that the gap is longer
than gossip's horizon), or if Tor's own guard state turns out to hold anything
beyond guards and build-time statistics (`WALLET_SIDE_STORE.md:634` lists what
it holds). Posed as `TSV-Q4`.

## 9. Acceptance

Each case runs on Linux, Windows and macOS against the supervisor, and asserts
the announced transitions, the recovery, and the RPC's Tor state. Linux can
run them today; Windows and macOS need TB-11's pins adopted first (TSV-10). The respawn case is a launch test: it runs in the Windows CI job
beside the boot-and-stop smoke test (#1072), and in a macOS job once one exists.

| Case | Expected | Apparatus (per platform, to be built) |
| --- | --- | --- |
| Kill the Tor child | `Restarting`, a new onion published, the connector resumed on the new SOCKS address | a kill by PID: `kill -9`; `taskkill /F` |
| Block outbound, then unblock | `Degraded` naming no network; `Usable` after unblock without a respawn, or with one if `TSV-B7` passed | Linux: an unprivileged network namespace; Windows: a firewall rule (CI runners are administrators); macOS: a `pf` anchor under `sudo` |
| Skew the clock | the clock message with the offset | a VM or container with its own clock: Linux time namespaces do not offset the real-time clock, and TB-7's cleared environment refuses `LD_PRELOAD`-based fakes, so this case needs a guest whose clock is set |
| Fill the `DataDirectory`'s disk | the disk message; recovery when space returns | Linux: a small `tmpfs` in an unprivileged mount namespace; macOS: a small `hdiutil` image; Windows: a small VHD |
| Force a descriptor-upload failure | `Degraded`, then a respawn past `TSV-B7` | the owned test network (a mini Tor network built from the pinned bundle) with its HSDirs stopped; cannot be forced on the public network |
| A crash-looping binary | the backoff cap reached, the loud announcement, never gives up | a test binary that exits at once, through the test-only unchecked witness |
| Suspend and resume, or a wall-clock jump | the probe at once; `Usable` or a respawn | a laptop or VM suspend; a clock step in a VM. Records `TSV-B11` |
| Daemon stop under each trigger | the one stop routine, teardown inside its bound, the tombstone swept at the next start | each platform's stop signals and console events, the SCM stop on Windows, and `SIGKILL` of the daemon (objective 5) |

Then a seven-day soak on each platform, the Linux one on the Pi 4, with the
posture line and the RPC's Tor state as the record. PR-3's hundred-stop rig is
not an acceptance basis.

## 10. What this deletes

| Deleted | Where | Replaced by |
| --- | --- | --- |
| The no-respawn disposition and its FFI echo | `shekyl-tor-control-daemon/src/lib.rs:40-46`; `daemon_tor_ffi.rs:320-323` | §3.6 |
| `DEL_ONION` on stop | `control/actor.rs:783-798` (daemon path; the wallet keeps its own) | §3.7 step 1 |
| `SIGTERM` in the managed shutdown | `control/actor.rs:611-632` (`request_graceful_stop`) | §3.7 step 1 |
| The synchronous wipe in teardown and on drop | `ephemeral.rs:395-415`; `data_dir.rs` `wipe`, `Drop` | the tombstone (§3.7 steps 4 to 6) |
| `EventSink::unsubscribed()` on the daemon path | `ephemeral.rs:253` | §3.4 |
| The C++ liveness poll and its filtered `MERROR` | `net_node.inl:2292`, `:2297-2315`; `net_node.h:647`, `:756-758` | the state watch and §3.11 |
| `EPHEMERAL_TOR_BOOTSTRAP_TIMEOUT_SECS` and the start-failure branches | `net_node.inl:892-946` | `TSV-B3`, and §1's "start is iteration one" |
| The FFI singleton and its start, publish, alive and shutdown exports | `daemon_tor_ffi.rs:61`, `:142-341` | the Rust `main()` owns the supervisor (#1066) |

The C++ rows go with #1066's cutover of `net_node` start and stop; the order
is that round's.

## 11. Questions for this round

| Id | Question | Default |
| --- | --- | --- |
| **TSV-Q1** | Where the probe lands: the P2P virtual port, which the zone host must recognise and close without counting it as a peer; or a second virtual port on the same onion forwarding to a listener the supervisor owns, which writes nothing. The second is a second open port on every node's onion, which a scan of a known Shekyl onion learns nothing new from | the second port |
| **TSV-Q2** | Does a failed publish (`ADD_ONION` refused, `PowRefused`) respawn? The pinned Tor supports proof-of-work, so a refusal from it is a defect, not the network | `Degraded`, one respawn, then held with the announcement until the next boot |
| **TSV-Q3** | `__OwningControllerFD` starts Tor with an already-open, authenticated, owning control connection on an inherited socket: no spawn-to-ownership window, no control-port file and no cookie. It needs socket inheritance under TB-7's cleared environment on Windows, which is unverified | the ruled `__OwningControllerProcess` recipe; reopen with a measured Windows launch |
| **TSV-Q4** | The guard question (§8) | option (b), guards persist within a boot |
| **TSV-Q5** | Is the probe's timing signature (§7 objective 2) accepted and stated, given jitter? | accepted and stated in this document |
| **TSV-Q6** | A respawn caused by a remote condition (descriptor uploads, probe failures) is rate-limited separately from a local death (§7 objective 1) | yes, at a bound measured with `TSV-B7` |
| **TSV-Q7** | Bootstrap progress comes from `BOOTSTRAP` events on the daemon path, and the 500 ms poll stays only for the wallet (§3.4) | yes |
| **TSV-Q8** | The previous incarnation's file log is kept beside the `DataDirectory` until the next start sweep (§3.10) | yes |
| **TSV-Q9** | Where the supervisor lives: `shekyl-tor-control-daemon`, with shared arithmetic moved to `shekyl-tor-control-client` (§3.1) | yes |
| **TSV-Q10** | The brief's "DNS failure" state has no source in the managed Tor (TSV-F2). Withdraw it, or name the failure it was meant to catch | withdraw |
| **TSV-Q11** | `health` carries the state only; the cause, "since" and the attempt count are `status` facts (TSV-F3). For the RPC lane | as stated |
| **TSV-Q12** | The supervisor's own disk check (§4) runs on every tick as well as before each launch. Free-space reads are cheap; the write test is one small file | every tick |

## 12. Review denominator

Read for this round, at the pins above: the three Tor crates' public surfaces,
`actor.rs`'s launch, handshake, shutdown, event routing and readiness poll; the
wallet supervisor's loop and policy; `ephemeral.rs`, `data_dir.rs`,
`blocking.rs`; `daemon_tor_ffi.rs`; `net_node.inl`'s managed-Tor start,
liveness poll and teardown; `mlog.cpp`'s default categories; the dialer's owner
loop and target lever and the zone host's proxy slot on #1056; `shekyl-tor`'s
drive and publish; #1066's §2.2, its section table and DC-F12, DC-F13;
PWD-E7, PWD-E9, TB-1 to TB-13, SP-T0 §3b, §3c, DQ-T0.6, DQ-T0.7;
`RPC_CHANNEL.md` §6.1; `INPUT_GRAMMAR.md` IG-6, IG-13, IG-14 and its Tor rows;
the control specification's `TAKEOWNERSHIP`, `__OwningControllerProcess`,
`__OwningControllerFD`, Status, `HS_DESC`, `NETWORK_LIVENESS` and `LOG`
sections. Examined and found nothing to change: the pin gate and TB-7's
launch environment (the supervisor re-runs the gate as it stands); the
`shekyl-socks` client (it already keeps the reply byte the probe classifies
by). Not examined, and next round's scope: the Windows and macOS process and
filesystem behaviour this design assumes (rename after reap, kill semantics,
monotonic clock across suspend), which only §9's cases can settle; and the
wallet's Tor under the same standard, which is outside this brief.
