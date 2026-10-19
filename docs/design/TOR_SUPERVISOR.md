# The managed Tor supervisor — the link under the Tor connector

**Status: RULED 2026-10-15 — ratified as a whole by Rick. Increment 2 of §12
(the control client's groundwork: the bounded sink, the event parsers, the
`__OwningControllerFD` launch and the two death signals) is implemented;
increments 1 and 3 to 6 are not.** Every question is ruled: `TSR-Q1` to `TSR-Q4` and `TSR-Q6` on
2026-10-14, `TSR-Q5` and `TSR-Q7` on 2026-10-15. The brief was the
daemon-configuration lane's, carrying Rick's rulings of 2026-10-14; those and
the rulings on this round's questions are §1. Implementation follows §12's
increments, after §10's pre-flight measurements and the prerequisites
`TSR-F12` (DC-F12) and `TSR-F17` (#1083).
Identifier families (registered at birth, rule 94): `TSR-F1…TSR-FN` findings,
`TSR-Q1…TSR-QN` questions, `TSR-M1…TSR-MN` the measurements that set every
bound. Rule 26 is cited: the round changes a process lifecycle every connector
depends on, an FFI boundary, and the threat posture of the node's Tor identity.

**Read at:** `shekyl-core` `dev` `bd444b715`, the merge of PR-3 (#1056),
which carries the dialer this design binds to. Every code anchor is rooted
(`rust/…`, `src/…`) and current at ratification. An anchor into #1066, still
open, names the PR beside the path. Tor's control specification is the torspec book's *Commands* and
*Replies* chapters, cited by section name.

This round amends, and restates none of (each amended at ratification,
2026-10-15):
[`P2P_2_ENDPOINT_ROUND.md`](P2P_2_ENDPOINT_ROUND.md) PWD-E7's seam rows
"Restart" and "tor control unavailable" (`:605-606`);
[`TOR_BUNDLE_DISTRIBUTION.md`](TOR_BUNDLE_DISTRIBUTION.md) `TB-3`; PWD-E7's
*Tor is the onion key's only holder* (`DiscardPK` custody), which `TSR-Q1`
reverses for the life of a boot; and the no-respawn disposition in `rust/shekyl-tor-control-daemon/src/lib.rs:40-46`
with its FFI echo (`rust/shekyl-ffi/src/daemon_tor_ffi.rs:320-323`).

---

## 0. What "integrated" means here

The managed Tor is not a service beside the P2P stack. It is the **link**
under one connector. The connector system already has every seam a supervisor
needs, so the supervisor adds no path around it:

| The supervisor needs to… | The seam that already exists (PR-3, #1056) | What changes |
| --- | --- | --- |
| tell dials where to go | `ZoneDial::dial_tor` reads the Tor link's route at each dial (`TSR-F1`, `rust/shekyl-ffi/src/zone_ffi.rs`) | the supervisor becomes the link's publisher |
| stop the dialer drawing while Tor is down | `Dialer::choose` plans, then draws (`rust/shekyl-dialer/src/owner/mod.rs:574-601`, the draw at `:685-686`) | the plan reads the connector's link before it draws; the owner loop parks on the link |
| learn whether outbound works | every dial ends in a `CloseCause` that keeps the SOCKS reply (`rust/shekyl-transport-layer/src/cause.rs:202-246`) | each outcome is also evidence to the supervisor; no separate client probe |
| prove the onion is reachable end to end | the self-connection nonce: an inbound handshake carrying a nonce this node put in flight on this zone is recognised and dropped (`src/p2p/net_node.inl:969-982`) | a probe nonce kind; the probe is a dialer dial of our own onion |
| tell peers our address | `Dialer::set_own_addresses` (`rust/shekyl-dialer/src/owner/mod.rs:237`) → the partition's own member of the disclosure sample (`rust/shekyl-peerlist/src/partition.rs:521-535`) | called once per boot: the onion does not change at a respawn (`TSR-Q1`) |
| keep inbound working across a respawn | the forward listener is bound by the zone host on loopback, not by Tor (`zone_ffi::start_tor`) | nothing: a republished onion targets the same port |

The relay is deliberately absent from that table; see `TSR-F9`.

## 1. Rulings this round is built on (Rick, 2026-10-14)

| Ruling | Content |
| --- | --- |
| Supervisor | One Rust owner holds the managed Tor's state; its inputs are the child, Tor's status and descriptor events, and an end-to-end probe of our own onion; *usable* is defined by the probe; every other component reads this owner and none reads Tor state on its own |
| Start is iteration one | No separate bootstrap-failure path; capped backoff from the first launch; never gives up. A Tor-only node waits and announces (hop-0 fail-closed); a dual-posture node runs clearnet meanwhile |
| Respawn (as amended by `TSR-Q1` and `TSR-Q3`) | On a process fault (§4.4): reap; the `DataDirectory` and the onion are kept; republish the same onion; the connector parks and resumes on the new route; each death and recovery announced; a crash loop reaches the cap loudly. Backoff with resume for an operator's Tor |
| Teardown (as amended by `TSR-Q1`) | One routine for stop and respawn: close the owning control connection, wait within `SHUTDOWN_GRACE` (5 s), kill and reap. `SIGTERM` and `DEL_ONION` dropped. The directory's disposition follows why it ran: at boot end it is tombstone-renamed **after** the reap, deleted off the runtime under a bound, and swept at the next start; at a respawn it is kept |
| Launch (as amended by `TSR-Q7`) | Tor starts with `__OwningControllerFD`: an inherited socket that is already an authenticated, owning control connection (§4.7) |
| Disk | `AvoidDiskWrites 1` on every platform; no memory-backed `DataDirectory` |
| Requirements | The brief's items 3 to 7 (operator-fixable states, one log stream, suspend and resume, floor-device bounds, Windows first-class) are requirements of this round |
| Acceptance | §7's matrix on Linux, Windows and macOS, then a seven-day soak on each, a Pi 4 as the Linux host. Nothing is called "24/7" before that |
| `TSR-Q1`: a respawn is a repair | The `DataDirectory` is kept across respawns within a boot, so guards and the consensus cache survive. The daemon holds the hs-id seed for the boot in secure memory (rules 35, 36) and republishes the **same** onion; `ADD_ONION` still sends `Flags=DiscardPK`, since Tor need not hand back a key we hold. After a run of consecutive launch failures on a kept directory, the next launch uses a fresh one; the run length is set from `TSR-M2`'s failure distribution, not chosen |
| `TSR-Q2`: guards are per boot | Guards do not persist across boots, as today. Persisting them gains no reduction in expected exposure: a hostile guard exposes *f*·*B* boots in expectation either way, and persistence changes only the spread; the harm is per boot. It costs a guard file on disk and lets one hostile guard link every boot's onion. The one real re-roll attack, forcing respawns, is closed by `TSR-Q1` |
| `TSR-Q3`: remedy by cause | §4.4, with the SOCKS reply classification of §4.2: only a process fault respawns |
| `TSR-Q4`: Tor status in RPC | The unrestricted reply carries one boolean in Health, as `has_peers` does: this node can originate over an address-hiding connector now. State, cause, since and the respawn count are restricted Status fields; the RPC lane names them |
| `TSR-Q5`: one probe per descriptor upload round (2026-10-15) | The `HS_DESC UPLOADED` events of one upload round are coalesced into one trigger, and after a jittered delay the probe runs once (§4.5). No deadline of our own and no evidence-age bookkeeping |
| `TSR-Q7`: `__OwningControllerFD` on every platform (2026-10-15) | The launch hands Tor one end of a connected socket pair as its owning control connection; no control port, port file, cookie, `TAKEOWNERSHIP` or `RESETCONF` (§4.7) |
| `TSR-Q6`: the private-network cases | Best effort, not a gate. The private network is chutney or a hand-built `TestingTorNetwork` from the pinned bundle, at the implementer's choice; it runs §7's two cases if it can be made to work, is never a latency source, and its absence blocks nothing |

`TSR-F9` and `TSR-F10` propose amending parts of the brief's rulings; each
says which and why.

## 2. What the code does today

| Fact | Anchor |
| --- | --- |
| The daemon's Tor starts once, blocks init up to 300 s, and is never respawned; the crate says so and why (the static C++ proxy) | `src/p2p/net_node.inl` line 757 (at `d26148535e`); `rust/shekyl-tor-control-daemon/src/lib.rs:40-46` |
| Death is logged once and nothing else happens; the proxy stays installed at the dead port. The one log line is `MERROR` under `net.p2p`, which the default filter sets to `FATAL`, so at the default level it is not shown either (`TSR-F11`) | `src/p2p/net_node.inl:68`, `:1214-1232`; `contrib/epee/src/mlog.cpp:127` |
| Readiness is a `GETINFO status/bootstrap-phase` poll; no production code issues `SETEVENTS`. The supervisor's one `SETEVENTS`, the parsers for what it subscribes to, and the upload-round policy exist, unused (§4.2, `TSR-Q5`) | `rust/shekyl-tor-control-client/src/control/bootstrap.rs:10-11`; `rust/shekyl-tor-control-client/src/control/events.rs:42`, `:290`; `rust/shekyl-tor-control-client/src/control/upload_rounds.rs:50` |
| The event sink holds `EVENT_QUEUE_EVENTS` (256); an event past it is dropped and counted, and the read loop never waits (`TSR-F2`) | `rust/shekyl-tor-control-client/src/control/actor.rs:273` |
| Death has two signals: a watcher waits on the child beside the control connection's end, and either stops the actor (`TSR-F16`) | `rust/shekyl-tor-control-client/src/control/actor.rs:823`, `:1384`, `:1432`, `:1447` |
| Teardown is `DEL_ONION`, `SIGTERM`, 5 s, `SIGKILL`, reap, synchronous wipe | `rust/shekyl-tor-control-client/src/control/actor.rs:102`, `:889`, `:1042`; `rust/shekyl-tor-control-daemon/src/ephemeral.rs:395-415` |
| The managed tor inherits its owning control connection (`__OwningControllerFD`); it opens no control port and writes no cookie. The launch surface is a closed, tested option list | `rust/shekyl-tor-control-client/src/control/launch.rs:185`, `:393`, `:1126` |
| `SocksPort` is `auto ExtendedErrors`, so onion failures come back as `0xF0`–`0xF7` | `rust/shekyl-tor-control-client/src/control/actor.rs:614` |
| The binary witness is taken once, at start | `rust/shekyl-tor-control-daemon/src/ephemeral.rs:75-79` |
| The wallet's supervisor re-verifies the pin at every spawn, never gives up, and publishes the SOCKS route as data on a watch, read at use time | `rust/shekyl-tor-control-wallet/src/service.rs:6-45`, `:289-303` |
| The dialer draws a gray address, then checks whether it can dial at all; a `DialFailed` of any cause drops the outstanding gray draw | `rust/shekyl-dialer/src/owner/mod.rs:685-686`, then `rust/shekyl-dialer/src/owner/handshake.rs:53-71`; `rust/shekyl-peerlist/src/peerlist.rs:529-531` and `rust/shekyl-peerlist/src/partition.rs:326-331` |
| The Tor owner loop wakes every 0.5–1.5 s | `rust/shekyl-dialer/src/pace.rs:18-23` |
| Our onion reaches peers only as one uniform member of the disclosure sample; the sample is fixed for its window | `src/p2p/net_node.inl` lines 1896 to 1904 (at `d26148535e`); `rust/shekyl-peerlist/src/partition.rs:537-546` (F1, Rick 2026-10-09) |
| `get_info` Health is told to every caller; counts belong to Status | `rust/shekyl-rpc-types/src/info.rs:117-121` |

## 3. Findings

Severity-ordered. Each names who owns the fix.

**TSR-F1 (high; P2P lane). A down link erodes the gray list at the wake
rate.** `choose` draws before `attempt` checks for a tip, a network id or a
proxy. Every such attempt is `DialFailed(LocalClose)`, and the ruled list
transition drops the drawn address. Two live cases on `dev`: (i) every
connector, at every start, until the core publishes a tip; (ii) the Tor
connector after the managed Tor dies, because the proxy stays installed at a
dead port and the loop keeps drawing, about one gray onion per second for the
rest of the boot, including every address the address file restored. The
supervisor makes case (ii) routine, so it is closed first. **Proposed fix,
without touching the list rule:** the preconditions are part of the plan. No
draw happens unless the connector's link is usable and the tip and network id
are known; while the link is down the owner loop waits on the link's change,
not on a timer. A local failure that races the link's fall costs one draw per
incident. The drop stays: a non-implicating `DialFailed` is not returned to gray
(closed by the P2P lane, Rick, 2026-10-16, #1092; the dialer brief, "The
fill"). Implication decides the failed-address memory, not list membership,
and on clearnet nothing implicates, so the drop is what clears dead hosts.

**TSR-F2 (high; Tor lane). Subscribing to events makes the sink a memory
channel an outsider can fill.** `EventSink` wraps an unbounded `mpsc`. Once
`NOTICE`/`WARN` and status events flow, a burst of Tor warnings grows the
daemon's heap without bound, and anyone who can make Tor log can cause the
burst, including a peer misbehaving at our onion. The sink becomes bounded with
counted drops, and the count is itself reported, matching #1069 (every sink is
queued, and a log call never blocks).

**TSR-F3 (medium; brief correction). The event inputs are misfiled and
incomplete.** In the control specification's Status events, `CLOCK_SKEW`,
`DANGEROUS_VERSION`, `CLOCK_JUMPED`, `DIR_ALL_UNREACHABLE` and
`TOO_MANY_CONNECTIONS` are `STATUS_GENERAL`, not `STATUS_CLIENT`.
`CIRCUIT_ESTABLISHED` fires only when Tor "changed its mind", and
`CIRCUIT_NOT_ESTABLISHED` implements only `REASON=CLOCK_JUMPED`, so "no
circuit" cannot be read from `STATUS_CLIENT`. Missing from the brief and
needed: `NETWORK_LIVENESS UP|DOWN` and the `BOOTSTRAP` problem form (`WARNING=`,
`REASON=`, `COUNT=`, `RECOMMENDATION=`), which is where "outbound blocked"
appears. Consequence: *usable* rests on dial evidence (§4.5), and events name
causes.

**TSR-F4 (medium; brief correction). "DNS failure" is not a state of this
Tor.** An onion-only client resolves no names, and bootstrap dials directory
authorities and fallbacks by address; IG-Q6 already removed hostnames from peer
endpoints. The operator-facing cases are "outbound to Tor is blocked"
(`BOOTSTRAP` warn with a connection `REASON`, `NETWORK_LIVENESS DOWN`) and "no
directory is reachable" (`DIR_ALL_UNREACHABLE`).

**TSR-F5 (medium; brief correction). A wall-clock jump is the wrong suspend
detector.** It also fires on NTP steps and manual changes, and misses a suspend
on a correct clock. For the managed posture Tor says so itself: `CLOCK_JUMPED
TIME=` is emitted when Tor "spent enough time without CPU cycles that it has
closed all its circuits". The timing engine's clock does not advance across a
suspend on Linux (`rust/shekyl-timing-engine/src/lib.rs:98-104`); macOS and Windows are measured (`TSR-M8`). For the operator posture
(no control port), compare a suspend-inclusive clock with the monotonic one; a
growing difference is suspended time.

**TSR-F6 (medium; Tor lane). A respawn through a held witness re-runs a binary
verified hours earlier.** The wallet closed this gap (`service.rs:17-22`): the
daemon re-runs discovery and the pin gate at every spawn. A failed pin at
respawn cannot "refuse the start" (TB-2), because the daemon is running: it is
the named state `InstallDefect`, no spawn, retry at the cap.

**TSR-F7 (medium; brief correction). A fixed bootstrap deadline plus a fresh
directory can never converge on a slow link.** If bootstrap needs longer than
the deadline, each respawn discards the partial consensus and starts again.
Bootstrap is killed only when progress stalls (no new `BOOTSTRAP` progress
within a bound, with the network up), never on elapsed time. The kept
directory (`TSR-Q1`, ruled) removes the rest. PR-3's cold-first-contact run A (fresh data
directory per sample, pinned 15.0.24 bundle, the measurement host) had 5 of 100
managed Tors not bootstrapped within 120 s, with nothing in the log
(`docs/benchmarks/p2p_tor_gap_cold_20261014.md`; `docs/FOLLOWUPS.md`, the
row "A managed Tor that does not bootstrap leaves the node silent").

**TSR-F8 (low; config lane). `SHEKYL_TOR_BINARY` is an environment input**
(`rust/shekyl-tor-control-client/src/binary.rs:491`); IG-13 allows no
environment input. It becomes a config key or goes.

**TSR-F9 (design; amends the ruling's "hop-0 subscribes"). The relay does not
subscribe to the supervisor.** Hop 0 draws from sessions whose connector
declares `address_hidden_from_peer` (ruled 2026-10-01; stem candidates come
from the session registry). When Tor is down there are no such sessions and
hop 0 holds; when it returns, sessions return. A second input would be a second
source for one fact, and the two disagree in the window where the link is
usable but no session exists yet. The supervisor's job toward the relay is to
*explain* a hold (posture line, RPC), not to gate it. One consequence moves
from open review point to required: a dead own-edge is replaced by a fresh draw
when a hidden-address session exists again (review of `0fe22d39f`, "relay:
draw the own-edge from the hidden-address pool").

**TSR-F10 (design; amends the ruling's "resumes on the new SOCKS address").
The dialer never sees a SOCKS address.** The dialer is policy; it reads one
fact, whether this connector can dial now. The route is the connector's, read
at each dial, as the wallet already does (`service.rs:36-42`: read at use
time, never cached).

**TSR-F11 (medium; Tor lane). Today's only death notice is invisible at the
default log level** (§2). Every state change of §4.3 is an announcement in
IG-14's sense: it reaches the log and standard error whatever the level.

**TSR-F12 (high; daemon-configuration lane, a prerequisite). The daemon cannot
reap its own children while `tools::spawn` ignores `SIGCHLD`.**
`signal(SIGCHLD, SIG_IGN)` makes the kernel reap every child, the managed Tor
included: tokio's wait fails with `ECHILD` on Linux and never completes on
macOS and FreeBSD. Respawn needs the reap. DC-F12's fix ("the Rust runner reaps
its own children and never changes a signal disposition") lands first
(`docs/design/DAEMON_CONFIG_CUTOVER.md` line 800 (#1066)).

**TSR-F13 (medium; daemon-configuration and P2P lanes). The stop is slow, and
the dialer outlives Tor.** PR-3's rerun measured the managed Tor's teardown at
p50 0.1 s, p90 20.5 s, max 54.9 s over 99 stops; `REAP_TIMEOUT` (15 s) bounds
the graceful stop and reap, and nothing bounds `kill()` or the wipe. The dialer
is stopped after that teardown and redials through the dying proxy (up to 56
`LocalClose` dials in one stop) (`docs/FOLLOWUPS.md`, the row "A daemon stop is
slow, partly unbounded, and silent while it waits"). The
ruled teardown (§4.7) takes the wipe off the stop path; the dialer stops before
the Tor teardown. The brief's "stopped in step 9 in parallel with the core
stop" holds only after the dialer stop; #1066's step 9 is sequential today.

**TSR-F14 (low; Tor lane). The start sweep removes directories only.**
`data_dir.rs` matches the `ephemeral-tor-` prefix and removes with
`remove_dir_all`, which leaves a plain file. The kept log (§4.10) and anything
else the routine leaves beside the directory are named under that prefix, and
the sweep removes files as well as directories.

**TSR-F15 (medium; TB lane). macOS has no managed Tor yet, and §7 is what
gives it one.** Both macOS rows are `unavailable` with `"pending": "TB-11"` in
`config/tor_pins.json`; TB-11 makes a target pinned only with a launch test,
and the digests are already verified (`TOR_BUNDLE_DISTRIBUTION.md` §4). §7's
macOS cases are that launch test: the change whose job passes them adopts the
macOS pin and removes its `pending` marker. TB-11's Windows launch test is
this lane's Windows entry, the `windows-x86_64` entry of `tor-pin-verify`;
§7's Windows cases are the supervisor's acceptance tests, not the pin's gate.
Windows run of 2026-10-15 (the Windows development host): the pinned
`tor.exe` imports 21 libraries, all the operating system's (8 System32
libraries and 13 UCRT apisets), with no delay-loads; the pin's `imports`
list is that set, re-derived from the 15.0.25 `tor.exe`.

**TSR-F16 (medium; Tor lane). A leaked copy of Tor's socket end hides Tor's
death.** Measured on Windows (case C6b, 2026-10-15): with the handle leaked
into a concurrent child, killing Tor left our read on the owning socket blocked
for 30.3 s, until that child exited. EOF on the owning socket is therefore
never the sole death signal: the supervisor also waits on Tor's process (the
reap on Unix, the process handle on Windows). That is §4.2's "child exited"
input, which §2 records as missing today. Both inputs stay, and either one is
a process fault. Tor holds its own end inheritable, so a child Tor spawned (a
pluggable transport) could inherit it; that is moot while bridges are out of
scope (§5), and it reopens with them. Reproduced on Linux (2026-10-15, the
pinned 15.0.24 `linux-x86_64` bundle): Tor's end carries no close-on-exec flag
inside Tor (`fdinfo` flags `04002`); with a copy leaked into a concurrent child
that lived 5 s, the wait on Tor's process returned within 12 ms of the kill and
our read saw EOF only after 5.0 s; a concurrent spawn that was not handed the
socket held neither end, and EOF followed the kill within 7 ms.

**TSR-F17 (high; Tor lane; fixed in its own change).** Two defects in landed
launch code, found by the same Windows run: the default torrc is not
foreclosed, so a `torrc` in Tor's default location is read; and the cleared
environment (TB-7) kills `tor.exe`, which needs `SystemRoot`. Both are fixed by
the launcher fix, a separate change, #1083; this round depends on it.
§4.7's launch passes `--torrc-file` (`-f`'s long form) and `--defaults-torrc`, each naming an
empty file, and on Windows sets `SystemRoot` from the operating system, never
from our environment. **On Linux the default location is world-writable.** The
pinned Linux bundle's compiled-in defaults sit under `/var/tmp/dist/tor/`: with
no `-f`, Tor reads `/var/tmp/dist/tor/etc/tor/torrc` and `torrc-defaults`, and
`/var/tmp` is writable by every local user, so any of them can supply our
Tor's configuration. With `-f` and `--defaults-torrc` foreclosed, Tor still
tries to open `GeoIPFile` and `GeoIPv6File` at their compiled-in defaults,
`/var/tmp/dist/tor/share/tor/geoip` and `geoip6`, and would parse a file
planted there. The launch therefore also passes `GeoIPFile` and `GeoIPv6File`,
each naming the empty file; with them, Tor opens only that file (measured
2026-10-15). This joins the launcher fix's scope.

## 4. Design

### 4.1 The link

A connector-generic value in `shekyl-transport-layer`, published by whoever
owns the connector's route and read by everyone else:

```text
Link {
    incarnation: u64,          // bumps on every new route
    route: Option<Route>,      // Tor: the SOCKS address; None while there is none
    outbound: Facet,           // can this node open streams through it
    inbound: InboundFacet,     // can peers reach this node's address through it
}
Facet        = Unknown | Usable { since } | Down { cause, since }
InboundFacet = NotOffered | Publishing | Reachable { evidence_at } | Unreachable { cause, since }
```

Two facets, because they are two facts with two consumers. A Tor-only node
whose onion is unreachable can still originate (hop 0 needs outbound only);
collapsing them into one *usable* would hold transactions that could go.
`NotOffered` covers a posture with no onion (an operator Tor without
`tor-onion`).

One source per fact:

| Fact | Owner | Readers |
| --- | --- | --- |
| route | the supervisor (managed) or configuration (`tor-socks`, operator) | the connector, at each dial |
| outbound facet | the supervisor | the dialer's plan; the posture line; RPC |
| inbound facet | the supervisor | the posture line; RPC |
| own onion | the supervisor | `Dialer::set_own_addresses` (the peerlist's own member) |
| hidden-address sessions | the hub's board | the relay (hop 0) |

Clearnet's link is constant (`route = direct`; both facets follow the
transport layer). A proxied clearnet connector (`clearnet-socks`) has the same
shape as an operator Tor; that is noted for the clearnet lane, not designed
here.

### 4.2 Inputs

| Input | Source | Effect |
| --- | --- | --- |
| child exited | a wait on Tor's process: the reap on Unix, the process handle on Windows (`TSR-F16`) | process fault |
| control connection EOF, desync, or a reply past the reply bound | the control actor | process fault (a wedged Tor is a dead Tor) |
| `BOOTSTRAP PROGRESS=` | `STATUS_CLIENT` | progress; resets the stall bound |
| `BOOTSTRAP` with `WARNING`/`REASON` and `RECOMMENDATION=warn` | `STATUS_CLIENT` | named external cause (outbound blocked and kin). Tor sends `warn` from the tenth problem at a phase, so a few refused connections at startup raise nothing |
| `ENOUGH_DIR_INFO` / `NOT_ENOUGH_DIR_INFO` | `STATUS_CLIENT` | outbound facet cause |
| `NETWORK_LIVENESS UP/DOWN` | `NETWORK_LIVENESS` | external cause on or off |
| `CLOCK_SKEW SKEW=` | `STATUS_GENERAL` | named cause with the offset; the source is unauthenticated, so the message says Tor reports it, never "your clock is wrong" |
| `CLOCK_JUMPED TIME=` | `STATUS_GENERAL` | resume: re-evaluate now (Tor closed its circuits) |
| `DANGEROUS_VERSION` | `STATUS_GENERAL` | announcement; a release question, not a runtime fault |
| `DIR_ALL_UNREACHABLE` | `STATUS_GENERAL` | named external cause |
| `TOO_MANY_CONNECTIONS` | `STATUS_GENERAL` | named local cause (the open-file limit), with the count |
| `HS_DESC UPLOADED` / `FAILED REASON=` for our address | `HS_DESC` | `UPLOADED`: one upload round arms the probe (§4.5); `FAILED` across a round: Service-class evidence (§4.4) |
| `NOTICE` / `WARN` / `ERR` | log events | the `tor` log category (§4.10) |
| every Tor dial's outcome | the connector's dial path → the supervisor | by the SOCKS reply table below |
| a stream accepted at our forward listener | the Tor connector's inbound accept (`adopt_tor`, `rust/shekyl-ffi/src/zone_ffi.rs:392`) | display evidence only (posture line, RPC): a peer fetched the descriptor and completed introduction and rendezvous; it neither arms nor defers the probe |
| a probe nonce arrived | the dialer's nonce set (§4.5) | inbound evidence |

Each SOCKS reply answers two questions, not one: is it about the destination,
and is it about our link. One table drives both the address memory
(`implicates_address`) and the supervisor:

| Reply | About | Goes to |
| --- | --- | --- |
| `0x00` | — | link evidence (good) |
| `0x05`, `0xF0`, `0xF1`, `0xF2`, and `0x04` | the destination | the address memory, as today. **Residual** (`LV3_CONNECTION_OBJECT.md:1829`; `IMPLEMENTATION_INDEX.md:798`): an attacker on the directories responsible for a target's key can force reply `0x04`, and with `ExtendedErrors` on it forces `0xF0` (descriptor not found) instead; either buys only Tor's short backoff. It stays a residual under the dialer's failure memory (240 s, doubling to an hour, `rust/shekyl-dialer/src/memory.rs:34-38`): that attacker already makes the onion unreachable for everyone, and our memory only reflects it |
| `0x01`, `0x02`, `0x03`, `0x06`; our SOCKS port refusing or closing without a reply (`ProxyUnavailable`, `rust/shekyl-transport-layer/src/cause.rs:228-231`) | our link | the supervisor |
| `0xF3`, `0xF7` | neither, alone | the supervisor, as a rate: link-down is timeouts across **distinct** destinations with no success between them, never a count of replies |
| `0x07`, `0x08`, `0xF4`, `0xF5`, `0xF6` | this node (we never send what draws these) | the defect log; never peer or link evidence |

A rule a reviewer can break: a test feeds `0xF7` from one destination many
times and asserts the link stays up; the same count spread across distinct
destinations takes it down.

The supervisor sends one `SETEVENTS STATUS_GENERAL STATUS_CLIENT HS_DESC
NETWORK_LIVENESS NOTICE WARN ERR` as its first command, and nothing else sends
`SETEVENTS` on that connection. SP-T0 §3b withdrew a `STATUS_CLIENT`
subscription for the wallet because `SETEVENTS` is "a shared, replace-not-add
resource the consumer also uses"; on the daemon the supervisor is the only
reader, so it is the only writer, and the objection does not arise. The
retraction stands for the wallet. A sans-IO parser beside `stream.rs` reads
each event, pinned by known-answer tests and tolerant of unknown actions,
arguments and order, as the specification requires.

### 4.3 State

Per incarnation: `Absent { attempt, next_at } → Launching → Bootstrapping {
progress, last_progress_at } → Running → Stopping`. The brief's four names are
a projection of that phase and the two facets, which is what the posture line
shows:

| Shown | When |
| --- | --- |
| **Restarting** | phase is `Absent`, `Launching`, or `Stopping` for a respawn |
| **Bootstrapping** | phase is `Bootstrapping` |
| **Usable** | `Running`, outbound `Usable`, inbound `Reachable` or `NotOffered` |
| **Degraded** (cause) | `Running` and either facet is down, the facet and its cause named |

### 4.4 Remedies by cause

Ruled (`TSR-Q3`): the remedy is chosen by cause class. A respawn fixes only
faults in the Tor process, so only those respawn:

| Class | Causes | Remedy |
| --- | --- | --- |
| External | outbound blocked, `NETWORK_LIVENESS DOWN`, `DIR_ALL_UNREACHABLE`, clock skew | none but waiting; Tor retries itself; announce with the fix; **never respawn** |
| Service | descriptor upload failing past a bound; probe failing while outbound is usable | republish on the running Tor (`ADD_ONION` again); escalate to Process only if the control command itself fails |
| Process | child exit; control EOF or desync; reply past bound; bootstrap progress stalled with the network up; outbound dead past a bound with no external cause standing | respawn |
| Install | pin fails at spawn (`TSR-F6`) | no spawn; announce; retry at the cap |
| Local resource | data directory unwritable or out of space (checked before each spawn); `TOO_MANY_CONNECTIONS` | no spawn (or, for the open-file limit, no respawn); announce; retry at the cap |

Backoff applies to respawns and to Install and Local-resource retries; it never
gives up and reaches its cap with a loud announcement, repeated once per cap
interval and never more often (ruled).

### 4.5 The probe

The self-dial is a **dialer dial of our own onion** with a nonce minted as a
probe nonce. The inbound path already recognises our own nonce and drops the
session (the C++ calls into Rust; no C++ change). When the nonce taken is a
probe nonce, the dialer reports `ProbeArrived` to the supervisor. Arrival
proves descriptor, introduction, rendezvous, the forward listener and the Levin
accept, end to end; it cannot be forged by anyone who has not seen the nonce,
and only our own Tor carries it. The probe touches no list, no attempt count,
no failure memory and no target.

**What fires it (`TSR-Q5`, ruled 2026-10-15): one probe per descriptor
upload round.** Tor re-uploads our descriptor on its own schedule, every 60 to
120 minutes at random (`HS_SERVICE_NEXT_UPLOAD_TIME_MIN` and `_MAX`,
lines 34 and 36 of Tor's own `hs_service.h`, in its `feature/hs` directory, at tags `tor-0.4.9.13` and `tor-0.4.9.14`), and at once when it
picks new introduction points, when the proof-of-work effort changes, or when
the HSDir ring changes. Each upload reaches us as `HS_DESC UPLOADED`, one per
HSDir. The events of one round are coalesced into one trigger; after a
jittered delay the probe runs once. The delay keeps a hostile HSDir from
seeing "upload, then an immediate fetch of the same descriptor" as a
self-probe signature. There is no deadline of our own and no evidence-age
bookkeeping: inbound accepts are display evidence only, and `HS_DESC FAILED`
across a round is Service-class evidence (§4.4).

**Stated costs.** A failure Tor does not notice, and that causes no re-upload,
is caught at the next scheduled upload, at most two hours later. The cadence is
a Tor implementation constant, not specification: the re-pin procedure
(`RELEASE_CHECKLIST.md`, "Bundled Tor pin current") re-checks it on every
re-pin. The seven-day soak is the evidence on whether the two-hour window
matters.

Its timeout is not the dialer's 9.1 s Tor dial deadline:
26 of 100 cold dials on the measurement host exceeded it in PR-3's run A.
Residual, stated: our guard carries both ends of the probe's rendezvous, since
one Tor process draws one guard set
([`SP_T3_SKELETON_MEASUREMENT.md`](SP_T3_SKELETON_MEASUREMENT.md) SPIKE-F-12);
a malicious guard learns this client hosts an onion, which service-side
circuit shapes already tell it.

That a Tor client can reach an onion hosted by the same Tor is the
expectation; `TSR-M3` verifies it before anything depends on it.

### 4.6 The dialer

- `choose` reads the connector's outbound facet, the tip and the network id
  **before** it draws (`TSR-F1`). `dial`, the named draw, reads the same three
  before it draws. The owner loop draws through `choose`.
- While the facet is not `Usable`, the owner loop waits on the link, not on its
  wake timer.
- A Tor dial's outcome goes to the lists as today **and** to the supervisor as
  evidence. Attribution follows §4.2's reply table: the destination, our link
  (with `0xF3` and `0xF7` judged as a rate across distinct destinations), or
  this node's own defect, which is never evidence.
- After a respawn the white list is intact (peers' onions did not change), so
  recovery is white re-contact, not discovery.

### 4.7 Launch and teardown

Launch (`TSR-Q7`, ruled 2026-10-15): Tor starts with `__OwningControllerFD`
naming its end of a connected socket pair. Tor treats that socket as an owning
control connection that is already authenticated, so the launch has no
`ControlPort auto`, no port file, no cookie authentication, no `TAKEOWNERSHIP`
and no `RESETCONF`, and no window between spawn and ownership. Parent death
closes the socket, which covers what `__OwningControllerProcess` was for.
Measured on Windows (2026-10-15): the inherited socket answered `GETINFO
version` (`250-version=0.4.9.13`) with no `AUTHENTICATE` sent; Tor opened no
control port of its own (`net/listeners/control` empty); closing our end
exited Tor in about 20 ms (C4); and the parent's `abort()` exited Tor cleanly
through the same path (C5).

- **Unix:** a `socketpair`. Tor's end is marked inheritable in the child only,
  in `pre_exec` (clearing `FD_CLOEXEC`), so no concurrent spawn can inherit it.
  The parent's copy keeps close-on-exec, and is closed before the spawn returns.
- **Windows:** a connected loopback pair. The parent's copy of tor's end is
  inheritable only inside the spawn lock, and that copy is closed before the
  lock is released, including when the spawn fails. Closing the handle is what
  ends the window: a failed inherit-bit clear still drops the socket while the
  lock is held, so the bit cannot outlive the guard.
  Every other Rust spawn in a process that itself launches a managed tor takes
  the same lock. A process that does not launch tor does not. The socket is not
  in its address space.
  `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` would name the handles one `CreateProcess`
  may inherit. It would not stop a different `CreateProcess` in this process,
  still passing `bInheritHandles` and still omitting a list, from inheriting a
  handle that is inheritable at that moment. The lock is that closure.
  Stabilising the list in `std` does not retire it. The C++ `tools::spawn`
  residual (DC-F12) stays outside the lock until that lane is gone.

The launch also passes `--torrc-file`, `--defaults-torrc`, `GeoIPFile` and
`GeoIPv6File`, each naming an empty file, and on Windows sets `SystemRoot`
from the operating system (`TSR-F17`).

Measured on Linux (2026-10-15, x86_64, the pinned 15.0.24 bundle staged to its
four pinned files, cleared environment with the loader path only): the
inherited socket answered `GETINFO version` (`250-version=0.4.9.13`) with no
`AUTHENTICATE`; `net/listeners/control` was empty; `config-file` and
`config-defaults-file` named the empty file; over three runs, closing our end
exited Tor in 2–19 ms (C4) and a parent's `abort()` left Tor gone within
6–28 ms of the parent's reap (C5). The harness is
`scripts/tor/validate_owning_fd_launch.py` in the Foundation's development
repository: it verifies the staged files against `config/tor_pins.json`
first, and runs on Linux and macOS. macOS is measured with it once a host is
set up.
`AvoidDiskWrites 1` and these join the closed option list, whose test fails
first, which is its purpose. Discovery and the pin gate run at every spawn
(`TSR-F6`).

Teardown, as ruled: close the owning control connection (Tor exits on its
close and, in the specification's words, "does not wait a while for circuits
to close"), wait within `SHUTDOWN_GRACE`, kill (`TerminateProcess` on
Windows), reap. The routine is one; the directory's disposition follows from
why it ran. At a respawn the directory is kept (`TSR-Q1`), and after the run
of consecutive launch failures §1 names the next launch takes a fresh one. At
boot end it is renamed to a tombstone in the same parent (one metadata
operation, after the reap, so on Windows no Tor handle holds a file inside
it), handed to a blocking task that deletes it under the bound `TSR-M10`
sets, and swept at the next start. If the rename fails (a scanner holding a file
on Windows), the directory stays under its live name and the next start's
sweep removes it, with the failure logged. What a respawned Tor reads is the kept directory's `state`; when Tor first
writes it, and what a kill loses, is `TSR-M6`.

### 4.8 Identity across a respawn

The onion does not change across a respawn (`TSR-Q1`): the daemon republishes
it from the seed it holds for the boot. Nothing is republished to the peer
lists, and the brief's item 8 (identity churn on each respawn) is deleted.

### 4.9 Operator posture

No child and no control port. The route comes from configuration. Outbound
evidence comes from dial outcomes only. While outbound is down, the recovery
probe is a white re-contact at the backoff cadence (a failed white re-contact
leaves white unchanged, so the probe costs the lists nothing); with no white, a
seed. Inbound with `tor-onion` uses the same probe nonce through the operator's
Tor to the operator's onion. With `tor = off` there is no supervisor.

### 4.10 Log stream

`SETEVENTS` adds `NOTICE WARN ERR` beside the status and descriptor events;
they enter the daemon's log under `tor` through the bounded sink (`TSR-F2`).
The previous incarnation's file log is kept until the next start sweep (ruled):
it moves out of the `DataDirectory` to `ephemeral-tor-<id>.log` in the parent,
under the sweep's prefix (`TSR-F14`), so a crash loop keeps the last dead
incarnation's evidence and no Tor log survives into another boot's run. The
pinned Tor writes no onion address at `notice` or `info` (measured for the
wallet, `WALLET_SIDE_STORE.md:634`); the daemon's instance is re-measured once
(`TSR-M9`).

### 4.11 Runtime and timers

The daemon has one scheduler (Rick, 2026-10-13). Backoff, stall, probe and
evidence bounds are timing-engine deadlines on one owner. The control actor
runs on a runtime built where every runtime is built; `blocking.rs`'s own
one-worker runtime retires with its C++ caller. The policy core is written
sans-IO (events in, actions and the next deadline out), so it is testable on
`ManualClock` and the wallet could adopt it later. The wallet's supervisor is
not changed in this round. Where both need the same arithmetic (backoff, the
failure classes), that code lives in `shekyl-tor-control-client`, which both
already name; PWD-E9 forbids sharing an instance, not a library.

### 4.12 C++

Nothing is added to C++. The probe reuses the existing self-detection call. The
route moves from the FFI-installed `tor_proxy` to the published link inside
Rust. At the daemon-configuration cutover, `add_ephemeral_tor_zone`,
`check_ephemeral_tor_liveness`, `shekyl_daemon_tor_{start,publish,is_alive,shutdown}`
and `blocking.rs` have no caller; those deletions go to Rick before they are
cut (rule 15; §9).

## 5. Rule-82 states

| State | Source | Shown as | Fix named to the operator | Remedy |
| --- | --- | --- | --- | --- |
| Outbound blocked | `BOOTSTRAP` warn `REASON`, `NETWORK_LIVENESS DOWN` | Degraded (outbound) | this machine cannot reach the Tor network; check the firewall or network; Shekyl does not support bridges | wait |
| No directory reachable | `DIR_ALL_UNREACHABLE` | Degraded (outbound) | as above | wait |
| Clock skew | `CLOCK_SKEW SKEW=±s` | Degraded (outbound) | Tor reports this machine's clock is about *s* seconds off; check time sync | wait |
| Resumed from suspend | `CLOCK_JUMPED` | Bootstrapping, briefly | none | re-evaluate now |
| Onion unreachable | the probe, `HS_DESC FAILED` | Degraded (inbound) | none; recovering | republish |
| Tor exited or wedged | exit, EOF, reply bound | Restarting | none unless repeated; then the count and the last exit, and where the previous log is | respawn |
| Tor install defect | the pin gate at spawn | Restarting (held) | the file that failed and the reinstall remedy | retry at the cap |
| Data directory unusable | the pre-spawn check | Restarting (held) | the path's problem: not writable, or out of space | retry at the cap |
| Open-file limit reached | `TOO_MANY_CONNECTIONS` | Degraded | the limit and the count; raise it, in the platform's terms | wait; retry at the cap |
| Tor version flagged | `DANGEROUS_VERSION` | announcement | upgrade Shekyl when a release re-pins Tor (TB-10), never Tor itself | none |

Rule 81 applies to every message: the words name what the operator sees and
can do, not Tor's vocabulary. Bridges are out of scope; reopen when an operator
reports a network that blocks Tor and the typed launch surface
(`launch.rs:263`) has a reviewed bridge option.

## 6. Rejected alternatives

Every question of this round is ruled (§1).

### Ruled out (Rick, 2026-10-14 and 2026-10-15)

- **A new identity per respawn** (fresh directory and fresh onion): a guard
  re-roll on demand for whoever can cause a respawn, a livelock on a slow
  link (`TSR-F7`), and churn in every peer's lists.
- **Guards persisted across boots:** no reduction in expected exposure; a
  guard file on disk, and one hostile guard linking every boot's onion.
- **Respawn on a degradation bound:** a respawn fixes only process faults, and
  hands the cause of any other degradation a re-roll.
- **Tor state, since and count in Health:** links an RPC endpoint to the
  onion's lifetime.
- **A probe on a deadline of our own** (evidence age): bookkeeping that Tor's
  upload rounds make unnecessary.
- **`__OwningControllerProcess`, `TAKEOWNERSHIP` and `RESETCONF`:** a
  control port, a cookie and a window between spawn and ownership, all of
  which the inherited owning socket removes.

## 7. Acceptance

Linux, Windows, macOS; the Pi 4 is the Linux host for the soak. Each case
asserts the announced transitions, the recovery, the RPC fields, **and that the
gray list is unchanged by the outage**. On macOS these cases are TB-11's
launch test; on Windows TB-11's launch test is `tor-pin-verify`'s Windows
entry, and these cases are the supervisor's acceptance tests (`TSR-F15`). The
respawn case runs in the Windows CI job
beside the boot-and-stop smoke test (#1072), and in a macOS job once one
exists.

| Case | Expected | Apparatus |
| --- | --- | --- |
| kill the Tor child | respawn; the same onion republished; the dialer resumes; no draws while down | a kill by PID (`kill -9`, `taskkill /F`) |
| block outbound, then unblock | Degraded (outbound, blocked); **no respawn**; Usable on unblock | Linux: an unprivileged network namespace; Windows: a firewall rule (CI runners are administrators); macOS: a `pf` anchor under `sudo` |
| skew the clock | the clock message with the offset; no respawn | a VM or container with its own clock: Linux time namespaces do not offset the real-time clock, and TB-7's cleared environment refuses `LD_PRELOAD`-based fakes |
| fill the data directory's disk | the named state; no spawn while full; recovery when space returns | Linux: a small `tmpfs` in an unprivileged mount namespace; macOS: a small `hdiutil` image; Windows: a small VHD |
| descriptor upload fails | Degraded (inbound); republish; respawn only if the control command fails | the private Tor network with its HSDirs stopped, best effort (`TSR-Q6`); not an acceptance gate if it cannot be built |
| introduction flood with PoW | inbound may degrade; **no respawn**; guards unchanged | the private Tor network, best effort (`TSR-Q6`); not an acceptance gate if it cannot be built |
| crash-looping binary | the backoff cap; the loud announcement; never gives up | a test binary that exits at once, through the test-only unchecked witness |
| binary replaced on disk, then the child killed | `InstallDefect`; nothing unverified spawns | replace a pinned file between spawns |
| wedged Tor (stopped process) | the reply bound; respawn | `SIGSTOP`; a suspended process on Windows |
| slow link (rate-limited) | bootstrap completes past the old 300 s; no kill while progress advances | a rate limit on the namespace's link |
| suspend and resume | `CLOCK_JUMPED` handled; no respawn unless a process fault follows | a laptop or VM suspend |
| daemon stop under each trigger | the one stop path; the dialer stopped before Tor; teardown within its bound; the tombstone swept at the next start | each platform's stop signals and console events, the SCM stop on Windows, and `SIGKILL` of the daemon (the owner window) |
| Tor down at start with a restored address file | gray intact when Tor comes up | start with outbound blocked |

Then the seven-day soak per platform, the posture line and the RPC fields as
the record. PR-3's hundred-stop rig is not an acceptance basis.

## 8. Threat-model addenda (rule 26 A3)

| Objective | How | Route |
| --- | --- | --- |
| Re-roll our guard on demand | cause respawns from outside (introduction flood, descriptor refusal) so each draws fresh guards | §4.4; `TSR-Q1` (ruled): the directory, and its guards, are kept across a respawn; `TSR-M6` sizes the window before Tor's first `state` write |
| Exhaust the daemon's memory through Tor | make Tor log in bursts | `TSR-F2`: bounded sink, counted drops |
| Read the probe as a signature | a hostile HSDir sees an upload followed at once by a fetch of the same descriptor; the guard sees both ends of the self-dial | §4.5: one probe per upload round, after a jittered delay; the guard residual is stated |
| Link the RPC endpoint to the onion | read respawn timestamps and counts over RPC | `TSR-Q4` (ruled): only a boolean is unrestricted |
| Plant in the parent directory | a symlink named under the sweep's prefix | `std::fs::remove_dir_all` does not follow a symlink; the parent is daemon-owned and the `DataDirectory` 0700; a test plants a symlink to an outside directory and asserts the target survives |
| Outlive the daemon | the daemon dies, including under `panic = "abort"` | parent death closes the owning socket (C5, measured 2026-10-15); §7's `SIGKILL` case |
| Hide Tor's death | hold a copy of Tor's socket end, so our read never sees EOF | `TSR-F16`: the supervisor also waits on Tor's process; the Windows inheritance window admits no other spawn (§4.7) |
| Learn the onion from the log | Tor's log events in the daemon's log | `TSR-M9`; Tor's `SafeLogging` stays at its default |

## 9. What this deletes

| Deleted | Where | Replaced by |
| --- | --- | --- |
| The no-respawn disposition and its FFI echo | `rust/shekyl-tor-control-daemon/src/lib.rs:40-46`; `rust/shekyl-ffi/src/daemon_tor_ffi.rs:320-323` | §4.4 |
| `DEL_ONION` on stop (the daemon's path; the wallet keeps its own) | `rust/shekyl-tor-control-client/src/control/actor.rs:1042-1052` | §4.7 |
| `SIGTERM` in the managed shutdown | `rust/shekyl-tor-control-client/src/control/actor.rs:889-908` | §4.7 |
| The per-publish seed, minted and dropped inside `publish` so that Tor is the key's only holder | `rust/shekyl-tor-control-daemon/src/ephemeral.rs:328-332` | the boot's seed in secure memory, republished on each respawn (`TSR-Q1`) |
| The synchronous wipe in teardown and on drop | `rust/shekyl-tor-control-daemon/src/ephemeral.rs:402-422`; `data_dir.rs` `wipe`, `Drop` | the tombstone (§4.7) |
| `EventSink::unsubscribed()` on the daemon's path | `rust/shekyl-tor-control-daemon/src/ephemeral.rs:253` | §4.2 |
| The zone host's Tor route and the managed Tor's death edge | `zone_ffi::start_tor`, `zone_ffi::dial_through_tor`, `zone_ffi::watch_managed_tor` (`TSR-F1`) | the supervisor publishes the link (§4.1) |
| The control port, its port file, cookie authentication and `TAKEOWNERSHIP` on the daemon's managed launch (the wallet's attached posture keeps its authentication) | gone from the managed launch (`rust/shekyl-tor-control-client/src/control/launch.rs:203-204`); the attached handshake stays (`rust/shekyl-tor-control-client/src/control/actor.rs:1068-1076`) | the inherited owning socket (`TSR-Q7`, §4.7) |
| The C++ start, liveness poll and teardown, and their FFI exports | `src/p2p/net_node.inl` lines 756 to 810 and 1209 to 1232 (at `d26148535e`; deleted by the daemon-configuration cutover's commit (c)); `rust/shekyl-ffi/src/daemon_tor_ffi.rs:61`, `:142-341`; `blocking.rs` | the supervisor, started and stopped by the Rust `main()` (#1066); to Rick before they are cut |

## 10. Bounds to measure (FOLLOWUPS rows)

Each on the Pi 4, which sets the value (rule 76), and on one x86 host as a
diagnostic. No figure is set before its row lands. The pre-flight rows were
measured on 2026-10-19 on the floor device (Pi 4, Ubuntu 26.04.1 aarch64) with
tor 0.4.9.14 (16.0a14), launched as `TSR-Q7` rules (an inherited owning control
socket, the torrc and GeoIP defaults foreclosed, a cleared environment,
`AvoidDiskWrites 1`), and beside it on an x86 dev box with tor 0.4.9.14
(15.0.25) as the diagnostic. The raw rows, the harness revision and each
run's conditions are in `shekyl-dev`, `data/tsr-preflight/2026-10-19*/`.

| Row | Measures | Sets |
| --- | --- | --- |
| `TSR-M1` | bootstrap time, cold directory and kept directory. **Measured 2026-10-19.** Cold, n=100: p50 11.3 s, p90 17.0 s, p99 127.1 s, max 380.8 s; 1 run over 300 s. Kept, n=30: p50 3.54 s, max 3.81 s (a respawn into its kept directory, `TSR-Q1`). x86: cold max 42.7 s, kept max 2.36 s. **Where the cold tail comes from** (300 more cold runs with each phase's time, 03:38Z to 06:45Z): of the 31 over 60 s, 26 spent their time loading relay descriptors and 5 loading the consensus; circuits took a median 0.86 s, as in fast runs. A slow run sits at one directory percentage, often for about five minutes, and then completes. Tor raised a `BOOTSTRAP` problem event in 1 of the 31. The tail's size moves with the night: 3 % over 60 s in the record (01:23Z to 03:13Z), 9 % in this run outside its overlap with the load test | the stall bound. No bootstrap is given up (`TSR-F7`, §4.4), and a slow one is not a process fault (`TSR-Q3`). A stalled directory fetch usually raises no problem event, so problem events alone cannot carry §5's operator message for it |
| `TSR-M2` | respawn to outbound usable, and to inbound reachable | the backoff base and cap |
| `TSR-M3` | self-probe latency, and that it works at all. **Measured 2026-10-19**: 40 of 40 succeeded, the probe nonce arriving each time; p50 2.35 s, p90 7.39 s, max 12.29 s. x86: 40 of 40, max 46.15 s, with five probes in one cluster at 42.9 to 46.1 s | the probe's delay range and timeout. A timeout below about 46 s would have failed the x86 cluster's probes, each of which succeeded |
| `TSR-M4` | Tor's resident memory at 12 outbound plus inbound load, default and set `MaxMemInQueues`. **Measured 2026-10-19 at Tor's default**, under a synthetic load (no fleet daemon could supply one; Rick, 2026-10-19): 12 outbound and 12 inbound rendezvous streams, each carrying 512 bytes every 10 s, for an hour. Resident memory **91.0 MiB**, flat once the streams were up; idle baselines 85.7 and 92.3 MiB. x86: 82.5 MiB. A set `MaxMemInQueues` was not measured | `MaxMemInQueues` |
| `TSR-M5` | Tor's file descriptors at load; the limit the child inherits. **Measured 2026-10-19** under `TSR-M4`'s load: **36 to 38** open; soft limit 524288 as launched; idle 13 to 15 | the descriptor budget |
| `TSR-M6` | when Tor first writes `state` after bootstrap under `AvoidDiskWrites 1`, and whether a kill loses guard changes made since. **Measured 2026-10-19**: the first write came 603.8 s and 601.9 s after bootstrap, then about every 610 s. A clean exit saved all 20 guards; a kill wrote nothing at exit, leaving the last periodic write's 20. x86: 602.1 and 603.7 s. A Tor killed before its first write leaves a respawn to sample new guards: that window is the re-roll still open to an attacker who can crash Tor early | whether the kept directory needs more than `TSR-Q1` gives it |
| `TSR-M7` | descriptor upload time after `ADD_ONION` and after a republish. **Measured 2026-10-19**: the first `UPLOADED` 4.43 s after `ADD_ONION`, 3.53 s after a respawn into the kept directory republished the held key; 1 of 13 uploads in the republish round failed, the case `TSR-Q5`'s rounds absorb. x86: 3.11 and 4.58 s | the upload bound |
| `TSR-M8` | the monotonic clock across suspend on Windows and macOS | suspend handling |
| `TSR-M9` | no onion address in the daemon Tor's log events at `notice`. **Measured 2026-10-19**: 0 of 36 `NOTICE`/`WARN`/`ERR` events carried one, across a publish, 40 probes and a republish. x86: 0 of 33 | the log category |
| `TSR-M10` | the delete time of a used `DataDirectory` on the floor device's storage. **Measured 2026-10-19**: 100 used cold directories, p50 11 ms, max 13 ms each. x86: max 7 ms | the tombstone delete bound |
| `TSR-M11` | on Windows, whether a killed and reaped `tor.exe` has released its `DataDirectory` files (`lock`, `state`, `tor.log`) when the reap returns. **Measured 2026-10-16** (Windows 11 23H2, Defender real-time protection on; the pinned 15.0.24 `tor.exe`, launched as #1083 does): 0 failures in 400, by kill and by owner-close, each followed at once by the tombstone rename and by a recursive delete. Every file is released by the time `WaitForSingleObject` returns | a respawn into the kept directory (`TSR-Q1`) and the tombstone rename (§4.7) do not wait for the directory's files once the reap has returned |

**`TSR-M6`, what is established (2026-10-16; mechanisms from an x86 diagnostic
and the floor device's dry run; the floor's timings, 2026-10-19, are in the
table).** Under
`AvoidDiskWrites 1` Tor defers its periodic `state` write: none within 240 s of
bootstrap while it reported 20 entry guards; with `AvoidDiskWrites 0` it wrote
them within 34 s. Every clean exit saves `state` with every guard, under either
setting: `SIGTERM`, `SIGNAL SHUTDOWN`, and the end of the owning connection
(Tor's `lost_owning_controller` raises `SIGTERM`, and `tor_cleanup` saves
`state`; measured at 0.1 s to exit). A kill does not. So the teardown §4.7
rules keeps a live Tor's guards in its kept directory, and the re-roll this row
measures is a Tor that crashes before its deferred write: the respawn then
samples new guards. The same exit-time save explains the macOS run's leftover
temporary directories holding only `state`: kameo 0.20's
`ActorRef::wait_for_shutdown` returns when the mailbox closes, before the run
loop calls `on_stop` and reaps Tor, so a test's `TempDir` could drop while Tor
was still saving on its way out. The client's live tests now wait for the reap
before the drop.

The Windows and Linux stop-path figures (closing our end, and the parent's
`abort()`, each exiting Tor within about 20 ms; C4, C5) are evidence for the
stop path, not a bound.

**Pre-flight (rule 26).** `TSR-M1`, `TSR-M3` to `TSR-M7`, `TSR-M9` and
`TSR-M10` need only today's managed Tor and a SOCKS self-dial, and are measured
before increment 3 (§12), the first increment whose code uses a bound they set;
increment 2 uses none. They were taken on 2026-10-19, after the re-pin, on the Tor that ships
(0.4.9.14), the Pi 4 setting each value (the table above); `TSR-M11` is measured
(above). `TSR-M2` and `TSR-M8` need the supervisor
or the suspend apparatus, and are measured on the implementation branch before
its PR leaves draft.

## 11. Interfaces

- **P2P:** `TSR-F1` (plan preconditions, the owner loop parks on the
  link) lands before the supervisor; the probe nonce kind in the nonce set; the
  own-edge redraw (`TSR-F9`); the dialer stops before the Tor teardown
  (`TSR-F13`).
- **Daemon configuration (#1066):** starts the supervisor at step 6 and stops
  it at step 9, after the dialer; step 8 does not wait for Tor, since the
  connector starts parked on the link, which also removes the SCM start's
  dependence on bootstrap time; `tor = managed | operator | off` is the
  supervisor's input; `tor-socks` is the operator route; `TSR-F8`; DC-F12 is a
  prerequisite (`TSR-F12`).
- **RPC:** `TSR-Q4` (ruled): one Health boolean, this node can originate over
  an address-hiding connector now; state, cause, since and the respawn count
  are restricted Status fields, named by the RPC lane.
- **TB:** §7's macOS rows are TB-11's macOS launch test; the Windows launch
  test is `tor-pin-verify`'s Windows entry (`TSR-F15`).
- **Wallet:** none this round; the sans-IO core is there to adopt.

## 12. Increments (rule 26)

1. P2P lane: `TSR-F1`. The link replaces the zone host's `tor_proxy` slot
   here (Rick's TSR-F1 brief, 2026-10-16): the zone host publishes it, the
   managed Tor's death edge takes it down, and the connector reads its route
   from it. The daemon watches only the Tor it manages
   (`DaemonTorControl::death`), and the down names the incarnation installed
   when the watch began. An exit and a shutdown both take the link down;
   only an exit is reported.
2. Control client: the bounded sink; parsers for `STATUS_GENERAL`,
   `STATUS_CLIENT`, `NETWORK_LIVENESS`, `HS_DESC` and log events; the launch
   recipe and `AvoidDiskWrites` in the closed list; the process wait as the
   second death signal. **Implemented** (#1091).
3. The supervisor core (sans-IO) and its timing-engine driver; the pin gate per
   spawn; the respawn routine per the `TSR-Q1`/`TSR-Q2` rulings. It removes the
   daemon's step-8 Tor wait (`rust/shekyl-daemon/src/run.rs`) and its 300 s
   bootstrap deadline (`rust/shekyl-daemon/src/tor.rs`): step 8 does not wait
   for Tor, and no bootstrap is given up (Rick, 2026-10-19; one cold bootstrap
   in a hundred on the floor device took longer than 300 s, §10).
4. The probe nonce and the probe.
5. The supervisor becomes the Tor link's publisher, in place of the zone host.
6. Acceptance; then the C++ deletions, to Rick before they are cut.

## 13. Review denominator

Read for this round, at the pins above: the three Tor crates' public surfaces;
`actor.rs`'s launch, handshake, shutdown, event routing and readiness poll; the
wallet supervisor's loop and policy; `ephemeral.rs`, `data_dir.rs`,
`blocking.rs`; `daemon_tor_ffi.rs`; `net_node.inl`'s managed-Tor start,
liveness poll, teardown, self-connection check and announced address;
`mlog.cpp`'s default categories; the dialer's `choose`, `plan_wake`,
`exchange`, pace and memory, the peerlist's outcome transition and disclosure population,
the zone host's proxy slot and `cause.rs`'s attribution; #1066's §2.2 and
DC-F12; PWD-E7, PWD-E9, TB-1 to TB-13, SP-T0 §3b and §3c; `RPC_CHANNEL.md`
§6.1; `INPUT_GRAMMAR.md` IG-13, IG-14 and its Tor rows; the control
specification's `TAKEOWNERSHIP`, `__OwningControllerProcess`,
`__OwningControllerFD`, Status, `HS_DESC`, `NETWORK_LIVENESS` and `LOG`
sections. Every rooted `dev` anchor (`rust/…`, `src/…`) is under
`check_doc_claims.py`'s dead-citation ratchet, and every one was re-read at
ratification on `dev` after #1056's merge; the #1066 anchor and the
continuation forms (`:1306-1313`) were read by hand.
Examined and found nothing to change: the pin gate and TB-7's launch
environment; the `shekyl-socks` client, which keeps the reply byte the
evidence attribution needs. Not examined, and next round's scope: the Windows
and macOS process and filesystem behaviour this design assumes (rename after
reap, kill semantics, the monotonic clock across suspend), which only §7 and
`TSR-M8` can settle; and the wallet's Tor under the same standard, which is
outside this brief.
