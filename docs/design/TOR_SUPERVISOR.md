# The managed Tor supervisor — the link under the Tor connector

**Status: OPEN — Round 0, for ratification (2026-10-14); `TSR-Q1`…`TSR-Q7`
await Rick's rulings.** Builds nothing. The brief is the daemon-configuration
lane's, carrying Rick's rulings of 2026-10-14 (§1); nothing else here is ruled.
Identifier families (registered at birth, rule 94): `TSR-F1…TSR-FN` findings,
`TSR-Q1…TSR-QN` questions, `TSR-M1…TSR-MN` the measurements that set every
bound. Rule 26 is cited: the round changes a process lifecycle every connector
depends on, an FFI boundary, and the threat posture of the node's Tor identity.

**Read at:** `shekyl-core` `dev` `e4d100fb1` (the brief's `1b7803f69` is its
ancestor; no commit since touches the Tor crates or `src/p2p`), and PR-3
(#1056) at `17ec20681`, unmerged, which carries the dialer this design binds
to. Anchors on #1056 name the PR beside the path, as in `path` lines N-M
(#1056). Tor's control specification is the torspec book's *Commands* and
*Replies* chapters, cited by section name.

On ratification this round amends, and restates none of:
[`P2P_2_ENDPOINT_ROUND.md`](P2P_2_ENDPOINT_ROUND.md) PWD-E7's seam rows
"Restart" and "tor control unavailable" (`:605-606`);
[`TOR_BUNDLE_DISTRIBUTION.md`](TOR_BUNDLE_DISTRIBUTION.md) `TB-3`; and the
no-respawn disposition in `rust/shekyl-tor-control-daemon/src/lib.rs:40-46`
with its FFI echo (`rust/shekyl-ffi/src/daemon_tor_ffi.rs:320-323`).

---

## 0. What "integrated" means here

The managed Tor is not a service beside the P2P stack. It is the **link**
under one connector. The connector system already has every seam a supervisor
needs, so the supervisor adds no path around it:

| The supervisor needs to… | The seam that already exists (#1056) | What changes |
| --- | --- | --- |
| tell dials where to go | `ZoneDial::dial_tor` reads `tor_proxy` at each dial (`rust/shekyl-ffi/src/zone_ffi.rs` lines 172-180 (#1056)) | the `Option<SocketAddr>` becomes the supervisor's published route |
| stop the dialer drawing while Tor is down | `Dialer::choose` plans, then draws (`rust/shekyl-dialer/src/owner.rs` lines 642-790 (#1056)) | the plan reads the connector's link before it draws; the owner loop parks on the link |
| learn whether outbound works | every dial ends in a `CloseCause` that keeps the SOCKS reply (`rust/shekyl-transport-layer/src/cause.rs` lines 202-246 (#1056)) | each outcome is also evidence to the supervisor; no separate client probe |
| prove the onion is reachable end to end | the self-connection nonce: an inbound handshake carrying a nonce this node put in flight on this zone is recognised and dropped (`src/p2p/net_node.inl` lines 1571-1584 (#1056)) | a probe nonce kind; the probe is a dialer dial of our own onion |
| tell peers our address | `Dialer::set_own_addresses` (`rust/shekyl-dialer/src/owner.rs` line 300 (#1056)) → the partition's own member of the disclosure sample (`rust/shekyl-peerlist/src/partition.rs` lines 521-535 (#1056)) | called again when the onion changes |
| keep inbound working across a respawn | the forward listener is bound by the zone host on loopback, not by Tor (`shekyl_zone_listen_tor`) | nothing: a republished onion targets the same port |

The relay is deliberately absent from that table; see `TSR-F9`.

## 1. Rulings this round is built on (Rick, 2026-10-14)

| Ruling | Content |
| --- | --- |
| Supervisor | One Rust owner holds the managed Tor's state; its inputs are the child, Tor's status and descriptor events, and an end-to-end probe of our own onion; *usable* is defined by the probe; every other component reads this owner and none reads Tor state on its own |
| Start is iteration one | No separate bootstrap-failure path; capped backoff from the first launch; never gives up. A Tor-only node waits and announces (hop-0 fail-closed); a dual-posture node runs clearnet meanwhile |
| Respawn | On death, or on degradation past a bound: reap, fresh `DataDirectory`, fresh `DiscardPK` onion; the connector pauses and resumes on the new route; each death and recovery announced; a crash loop reaches the cap loudly. Backoff with resume for an operator's Tor |
| Teardown | Close the owning control connection, wait within `SHUTDOWN_GRACE` (5 s), kill and reap, **then** tombstone-rename the `DataDirectory`, delete off the runtime under a bound, sweep tombstones at start. `SIGTERM` and `DEL_ONION` dropped. One routine for stop and respawn |
| Launch | `__OwningControllerProcess=<daemon pid>` on the command line, `TAKEOWNERSHIP`, then `RESETCONF __OwningControllerProcess` |
| Disk | `AvoidDiskWrites 1` on every platform; no memory-backed `DataDirectory` |
| Requirements | The brief's items 3 to 7 (operator-fixable states, one log stream, suspend and resume, floor-device bounds, Windows first-class) are requirements of this round |
| Acceptance | §7's matrix on Linux, Windows and macOS, then a seven-day soak on each, a Pi 4 as the Linux host. Nothing is called "24/7" before that |

`TSR-F9`, `TSR-F10` and `TSR-Q1`, `TSR-Q3` propose amending parts of these
rulings; each says which and why.

## 2. What the code does today

| Fact | Anchor |
| --- | --- |
| The daemon's Tor starts once, blocks init up to 300 s, and is never respawned; the crate says so and why (the static C++ proxy) | `src/p2p/net_node.inl` line 757 (#1056); `rust/shekyl-tor-control-daemon/src/lib.rs:40-46` |
| Death is logged once and nothing else happens; the proxy stays installed at the dead port. The one log line is `MERROR` under `net.p2p`, which the default filter sets to `FATAL`, so at the default level it is not shown either (`TSR-F11`) | `src/p2p/net_node.inl:71`, `:2297-2315`; `contrib/epee/src/mlog.cpp:127` |
| Readiness is a `GETINFO status/bootstrap-phase` poll; no production code issues `SETEVENTS` | `rust/shekyl-tor-control-client/src/control/bootstrap.rs:10-11`; `rust/shekyl-tor-control-client/src/control/actor.rs:211-239` |
| The event sink, once used, is an **unbounded** channel | `rust/shekyl-tor-control-client/src/control/actor.rs:202` |
| Death is seen only as the control connection ending; no watcher on the child after spawn | `rust/shekyl-tor-control-client/src/control/actor.rs:1260-1266`, `:1306-1313` |
| Teardown is `DEL_ONION`, `SIGTERM`, 5 s, `SIGKILL`, reap, synchronous wipe | `rust/shekyl-tor-control-client/src/control/actor.rs:97`, `:611-632`, `:783-798`; `rust/shekyl-tor-control-daemon/src/ephemeral.rs:395-415` |
| The launch surface is a closed, tested option list | `rust/shekyl-tor-control-client/src/control/actor.rs:874-954`, `:1485-1497` |
| `SocksPort` is `auto ExtendedErrors`, so onion failures come back as `0xF0`–`0xF7` | `rust/shekyl-tor-control-client/src/control/actor.rs:900-901` |
| The binary witness is taken once, at start | `rust/shekyl-tor-control-daemon/src/ephemeral.rs:75-79` |
| The wallet's supervisor re-verifies the pin at every spawn, never gives up, and publishes the SOCKS route as data on a watch, read at use time | `rust/shekyl-tor-control-wallet/src/service.rs:6-45`, `:289-303` |
| The dialer draws a gray address, then checks whether it can dial at all; a `DialFailed` of any cause drops the outstanding gray draw | `rust/shekyl-dialer/src/owner.rs` lines 768-769, then 791-830 (#1056); `rust/shekyl-peerlist/src/peerlist.rs` lines 444-446 and `partition.rs` lines 326-331 (#1056) |
| The Tor owner loop wakes every 0.5–1.5 s | `rust/shekyl-dialer/src/pace.rs` lines 18-23 (#1056) |
| Our onion reaches peers only as one uniform member of the disclosure sample; the sample is fixed for its window | `src/p2p/net_node.inl` lines 1896-1904 (#1056); `rust/shekyl-peerlist/src/partition.rs` lines 537-546 (#1056) (F1, Rick 2026-10-09) |
| `get_info` Health is told to every caller; counts belong to Status | `rust/shekyl-rpc-types/src/info.rs:117-121` |

## 3. Findings

Severity-ordered. Each names who owns the fix.

**TSR-F1 (high; P2P lane). A down link erodes the gray list at the wake
rate.** `choose` draws before `attempt` checks for a tip, a network id or a
proxy. Every such attempt is `DialFailed(LocalClose)`, and the ruled list
transition drops the drawn address. Two live cases on #1056: (i) every
connector, at every start, until the core publishes a tip; (ii) the Tor
connector after the managed Tor dies, because the proxy stays installed at a
dead port and the loop keeps drawing, about one gray onion per second for the
rest of the boot, including every address the address file restored. The
supervisor makes case (ii) routine, so it is closed first. **Proposed fix,
without touching the list rule:** the preconditions are part of the plan. No
draw happens unless the connector's link is usable and the tip and network id
are known; while the link is down the owner loop waits on the link's change,
not on a timer. A local failure that races the link's fall costs one draw per
incident. Whether a non-implicating `DialFailed` should also return the draw to
gray (`settle_outstanding`) rather than drop it is the P2P lane's question;
this round does not need it answered.

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
suspend on Linux (`rust/shekyl-timing-engine/src/lib.rs` lines 98-104
(#1056)); macOS and Windows are measured (`TSR-M8`). For the operator posture
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
within a bound, with the network up), never on elapsed time. Directory reuse
(`TSR-Q1`) removes the rest. PR-3's cold-first-contact run A (fresh data
directory per sample, pinned 15.0.24 bundle, the measurement host) had 5 of 100
managed Tors not bootstrapped within 120 s, with nothing in the log
(`docs/benchmarks/p2p_tor_gap_cold_20261014.md` and `docs/FOLLOWUPS.md` line
1038 (#1056)).

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
`LocalClose` dials in one stop) (`docs/FOLLOWUPS.md` line 1035 (#1056)). The
ruled teardown (§4.7) takes the wipe off the stop path; the dialer stops before
the Tor teardown. The brief's "stopped in step 9 in parallel with the core
stop" holds only after the dialer stop; #1066's step 9 is sequential today.

**TSR-F14 (low; Tor lane). The start sweep removes directories only.**
`data_dir.rs` matches the `ephemeral-tor-` prefix and removes with
`remove_dir_all`, which leaves a plain file. The kept log (§4.10) and anything
else the routine leaves beside the directory are named under that prefix, and
the sweep removes files as well as directories.

**TSR-F15 (medium; TB lane). Windows and macOS have no managed Tor yet, and
§7 is what gives them one.** Both are `unavailable` with `"pending": "TB-11"`
in `config/tor_pins.json`; TB-11 makes a target pinned only with a launch test,
and the digests are already verified (`TOR_BUNDLE_DISTRIBUTION.md` §4). §7's
Windows and macOS cases are those launch tests: the change whose job passes
them adopts that platform's pin and removes its `pending` marker.

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
| child exited | the exit observer | process fault |
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
| `HS_DESC UPLOADED` / `FAILED REASON=` for our address | `HS_DESC` | inbound facet evidence |
| `NOTICE` / `WARN` / `ERR` | log events | the `tor` log category (§4.10) |
| every Tor dial's outcome | the connector → the supervisor | outbound evidence: success proves it; a local-proxy failure or a reply that does not name the destination (`0x01`, `0x03`, `0xF3`, `0xF7`) counts against the link, never against the address |
| an inbound Tor session established | the hub | inbound evidence |
| a probe nonce arrived | the dialer's nonce set (§4.5) | inbound evidence |

The supervisor sends one `SETEVENTS STATUS_GENERAL STATUS_CLIENT HS_DESC
NETWORK_LIVENESS NOTICE WARN ERR` after `TAKEOWNERSHIP`, and nothing else sends
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

The brief's "degraded past a bound restarts" turns every degradation into a
respawn. A respawn fixes only faults in the Tor process, and under a fresh
directory it hands whoever caused the degradation a new guard sample (`TSR-Q1`,
`TSR-Q3`). The remedy is chosen by cause class:

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

It runs only when inbound evidence is older than the probe interval: a node
with live inbound Tor sessions rarely probes; an idle one probes on a jittered
interval. The interval is derived, not chosen: bounded above by the window in
which a peer that fails to reach us forgets us (`FIRST_WINDOW_NANOS`, 240 s,
`rust/shekyl-dialer/src/memory.rs` line 34 (#1056)), and below by the measured
probe cost (`TSR-M3`). Its timeout is not the dialer's 9.1 s Tor dial deadline:
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
  **before** it draws (`TSR-F1`).
- While the facet is not `Usable`, the owner loop waits on the link, not on its
  wake timer.
- A Tor dial's outcome goes to the lists as today **and** to the supervisor as
  evidence. Attribution follows `implicates_address`: what names the
  destination is about the peer; everything else is about the link.
- After a respawn the white list is intact (peers' onions did not change), so
  recovery is white re-contact, not discovery.

### 4.7 Launch and teardown

Launch, per the ruled recipe: `__OwningControllerProcess=<pid>` on the command
line, `TAKEOWNERSHIP`, `RESETCONF __OwningControllerProcess` (the
specification's `TAKEOWNERSHIP` section). `AvoidDiskWrites 1`. Both join the
closed option list, whose test fails first, which is its purpose. Discovery and
the pin gate run at every spawn (`TSR-F6`). `TSR-Q7` poses the specification's
other route, `__OwningControllerFD`.

Teardown, as ruled: close the owning control connection (Tor exits on its
close and, in the specification's words, "does not wait a while for circuits
to close"), wait within `SHUTDOWN_GRACE`, kill (`TerminateProcess` on
Windows), reap. The routine is one; what happens to the directory afterwards
depends on why it ran (`TSR-Q1`, `TSR-Q2`): at boot end it is renamed to a
tombstone in the same parent (one metadata operation, after the reap, so on
Windows no Tor handle holds a file inside it), handed to a blocking task that
deletes it under the bound `TSR-M10` sets, and swept at the next start; at a
respawn it is kept or replaced. If the rename fails (a scanner holding a file
on Windows), the directory stays under its live name and the next start's
sweep removes it, with the failure logged. Whether Tor writes `state` on the
owner-close path decides whether kept guards survive it (`TSR-M6`).

### 4.8 Identity across a respawn

Under the ruled design a respawn mints a new onion. Then
`set_own_addresses(Tor, [new])`; onions retired this boot stay in the dialer's
own filter, so we never dial or admit our own corpse. The disclosure window is
not reset: wargamed, a peer that sees the same sample from our old and new
onion links the two incarnations, which is exactly what it would know if Tor
had never died. Within-boot linkage is the baseline, so there is nothing to
defend and no exception to add. Under `TSR-Q1` (c) the onion does not change
and this section reduces to nothing.

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
(`actor.rs:874-954`) has a reviewed bridge option.

## 6. Questions for Rick

**TSR-Q1. What is a respawn: a repair, or a new identity?**
*Problem.* The ruling gives each respawn a fresh `DataDirectory` and a fresh
onion. That costs three things. (1) **Guard re-roll on demand.** Each respawn
samples new entry guards. Anyone who can cause a respawn gets a new draw at
placing their relay as our guard, and the capture in ProxyMark (arXiv
2607.07062; `DAEMON_RELAY_PRIVACY.md` §99) was a watermark at a malicious
guard. Under the brief's bound-based respawn, causing one is remote: flood our
introduction points and the probe fails. (2) **Slow-link livelock**
(`TSR-F7`). (3) **Churn** (brief item 8): peers' white entries for us die,
inbound returns only as gossip spreads, and a respawn is visible network-wide.
*What fresh buys.* A corrupt directory cannot keep crashing Tor. Within-boot
unlinkability of incarnations, which is the no-respawn baseline and so defends
against no one. Tor-only custody of the onion key against an adversary who
reads daemon memory and, on the same host, Tor's memory too (host compromise
is not defended by process separation, 2026-10-10).
*Options.* (a) As ruled. (b) Keep the directory across respawns within a boot
(guards and consensus cache survive), fresh onion each time; after a measured
number of consecutive launch failures on a kept directory, the next launch uses
a fresh one. (c) (b), and the daemon holds the onion's seed for the boot in
secure memory (rules 35, 36) and republishes the same onion: a respawn is
invisible to peers except as an outage, and item 8 is deleted. (c) reverses the
ruled `DiscardPK` property that Tor is the key's only holder.
*Recommendation:* (c).

**TSR-Q2. Should guards persist across boots?** (brief item 9)
*Problem.* `rust/shekyl-tor-control-daemon/src/ephemeral.rs:80-83` wipes
guards so "a restart cannot reuse entry guards"; PWD-E9 (`:826-828`) gives the
reason, that guards "cannot join onions". Every boot then samples new guards.
*Adversaries.* (A1) A malicious guard with bandwidth share *f*: sees our
address and can watermark (ProxyMark). Per boot the exposure is *f*; over *B*
boots without persistence it is 1 − (1 − *f*)^*B*; with persistence it is *f*
once, until Tor's own guard rotation. Operators restart at every release, so
*B* grows at the release cadence. (A2) A malicious guard linking onion *N* to
onion *N+1*: it can do so only in the world where it is our guard, where it
already holds the larger prize, our address. (A3) A disk-seizing adversary
reads `state`: guard fingerprints, no service data (measured for the pinned
Tor, `WALLET_SIDE_STORE.md:634`); Tor use is already evident from the machine.
*Options.* (a) As today. (b) Persist `state` only, per network data directory,
mode 0700; caches stay per boot. (c) Persist the whole directory.
*Recommendation:* (b). This reopens PWD-E7's "nothing on disk joins boots" for
guard state only, so it is Rick's to rule. Under `AvoidDiskWrites 1` and a
killed Tor, the kept `state` may predate the current guards (`TSR-M6`).

**TSR-Q3. Remedy by cause instead of "degraded past a bound restarts"**
(§4.4). It changes two expected outcomes in the brief's acceptance table: a
firewall block never respawns, and a descriptor-upload failure republishes
first.

**TSR-Q4. Which Tor facts are Health?**
*Problem.* The brief puts state, since-when and the respawn count in Health,
which every RPC caller is told. On a node whose RPC is reachable (a public RPC
host, a remote wallet's daemon), a respawn timestamp lines up with an onion
disappearing from gossip, linking the RPC endpoint's clearnet address to the
onion; under `TSR-Q1` (a) it also links consecutive onions. `RPC_CHANNEL.md`
§6.1 admits a Health fact only if it says nothing lasting about the node.
*Proposal.* Health carries one boolean, as `has_peers` does: this node can
originate over an address-hiding connector now. State, cause, since and count
go to Status. The RPC lane names the fields.

**TSR-Q5. The probe as a dialer self-dial with a probe nonce, armed by
evidence age** (§4.5), in place of a fixed-period probe.

**TSR-Q6. How are the cases the public Tor network will not produce on demand
tested?**
*Problem.* A descriptor-upload failure and an introduction flood cannot be
caused on the live network, and an injected control-port event is a mock
(2026-09-18: test production pathways).
*Options.* (a) The project's own private Tor network in CI: the pinned binary
and its `tor-gencert`, a few authorities, relays and exits under
`TestingTorNetwork`, the real protocol (chutney was rejected for this role: it
is unmaintained and does not run on current Python). (b) Those cases only on
the Pi rig, by hand. (c) Both: the private network in CI for the state
transitions, the rig for the soak. The private network never stands in for a
latency or timing measurement (`ARCHIVAL_CHALLENGE_MECHANISM.md` `:2142-2145`).
*Recommendation:* (c).

**TSR-Q7. `__OwningControllerFD`.** The specification's other route starts Tor
with an already-open, authenticated, owning control connection on an inherited
socket: no spawn-to-ownership window, no control-port file and no cookie. It
needs socket inheritance under TB-7's cleared environment on Windows, which is
unverified. *Default:* the ruled `__OwningControllerProcess` recipe; reopen
with a measured Windows launch.

## 7. Acceptance

Linux, Windows, macOS; the Pi 4 is the Linux host for the soak. Each case
asserts the announced transitions, the recovery, the RPC fields, **and that the
gray list is unchanged by the outage**. On Windows and macOS these cases are
TB-11's launch tests (`TSR-F15`); the respawn case runs in the Windows CI job
beside the boot-and-stop smoke test (#1072), and in a macOS job once one
exists.

| Case | Expected | Apparatus |
| --- | --- | --- |
| kill the Tor child | respawn; inbound republished (the same onion under `TSR-Q1` (c)); the dialer resumes; no draws while down | a kill by PID (`kill -9`, `taskkill /F`) |
| block outbound, then unblock | Degraded (outbound, blocked); **no respawn**; Usable on unblock | Linux: an unprivileged network namespace; Windows: a firewall rule (CI runners are administrators); macOS: a `pf` anchor under `sudo` |
| skew the clock | the clock message with the offset; no respawn | a VM or container with its own clock: Linux time namespaces do not offset the real-time clock, and TB-7's cleared environment refuses `LD_PRELOAD`-based fakes |
| fill the data directory's disk | the named state; no spawn while full; recovery when space returns | Linux: a small `tmpfs` in an unprivileged mount namespace; macOS: a small `hdiutil` image; Windows: a small VHD |
| descriptor upload fails | Degraded (inbound); republish; respawn only if the control command fails | the private Tor network (`TSR-Q6`) with its HSDirs stopped |
| introduction flood with PoW | inbound may degrade; **no respawn**; guards unchanged | the private Tor network |
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
| Re-roll our guard on demand | cause respawns from outside (introduction flood, descriptor refusal) so each draws fresh guards | §4.4: external and service causes never respawn; `TSR-Q1`, `TSR-Q2` |
| Exhaust the daemon's memory through Tor | make Tor log in bursts | `TSR-F2`: bounded sink, counted drops |
| Read the probe as a signature | the guard sees both ends of a periodic self-dial | §4.5: armed by evidence age, jittered; the residual is stated |
| Link the RPC endpoint to the onion | read respawn timestamps and counts over RPC | `TSR-Q4` |
| Plant in the parent directory | a symlink named under the sweep's prefix | `std::fs::remove_dir_all` does not follow a symlink; the parent is daemon-owned and the `DataDirectory` 0700; a test plants a symlink to an outside directory and asserts the target survives |
| Outlive the daemon | the daemon dies between spawn and `TAKEOWNERSHIP`, or under `panic = "abort"` | `__OwningControllerProcess` covers the window; `TAKEOWNERSHIP` the rest; §7's `SIGKILL` case |
| Learn the onion from the log | Tor's log events in the daemon's log | `TSR-M9`; Tor's `SafeLogging` stays at its default |

## 9. What this deletes

| Deleted | Where | Replaced by |
| --- | --- | --- |
| The no-respawn disposition and its FFI echo | `rust/shekyl-tor-control-daemon/src/lib.rs:40-46`; `rust/shekyl-ffi/src/daemon_tor_ffi.rs:320-323` | §4.4 |
| `DEL_ONION` on stop (the daemon's path; the wallet keeps its own) | `rust/shekyl-tor-control-client/src/control/actor.rs:783-798` | §4.7 |
| `SIGTERM` in the managed shutdown | `rust/shekyl-tor-control-client/src/control/actor.rs:611-632` | §4.7 |
| The synchronous wipe in teardown and on drop | `rust/shekyl-tor-control-daemon/src/ephemeral.rs:395-415`; `data_dir.rs` `wipe`, `Drop` | the tombstone (§4.7) |
| `EventSink::unsubscribed()` on the daemon's path | `rust/shekyl-tor-control-daemon/src/ephemeral.rs:253` | §4.2 |
| The FFI-installed `tor_proxy` | `rust/shekyl-ffi/src/zone_ffi.rs` (#1056) | the link (§4.1) |
| The C++ start, liveness poll and teardown, and their FFI exports | `src/p2p/net_node.inl:892-946`, `:2292-2315`; `rust/shekyl-ffi/src/daemon_tor_ffi.rs:61`, `:142-341`; `blocking.rs` | the supervisor, started and stopped by the Rust `main()` (#1066); to Rick before they are cut |

## 10. Bounds to measure (FOLLOWUPS rows)

Each on the Pi 4, which sets the value (rule 76), and on one x86 host as a
diagnostic. No figure is set before its row lands.

| Row | Measures | Sets |
| --- | --- | --- |
| `TSR-M1` | bootstrap time, cold directory and kept directory | the stall bound |
| `TSR-M2` | respawn to outbound usable, and to inbound reachable | the backoff base and cap |
| `TSR-M3` | self-probe latency, and that it works at all | the probe interval floor and timeout |
| `TSR-M4` | Tor's resident memory at 12 outbound plus inbound load, default and set `MaxMemInQueues` | `MaxMemInQueues` |
| `TSR-M5` | Tor's file descriptors at load; the limit the child inherits | the descriptor budget |
| `TSR-M6` | whether `state` holds the guards after an owner-close exit, and after a kill, under `AvoidDiskWrites 1` | the `TSR-Q1`/`TSR-Q2` mechanism |
| `TSR-M7` | descriptor upload time after `ADD_ONION` and after a republish | the upload bound |
| `TSR-M8` | the monotonic clock across suspend on Windows and macOS | suspend handling |
| `TSR-M9` | no onion address in the daemon Tor's log events at `notice` | the log category |
| `TSR-M10` | the delete time of a used `DataDirectory` on the floor device's storage | the tombstone delete bound |

**Pre-flight (rule 26).** `TSR-M1`, `TSR-M3` to `TSR-M7`, `TSR-M9` and
`TSR-M10` need only today's managed Tor and a SOCKS self-dial, and are measured
before the first production commit. `TSR-M2` and `TSR-M8` need the supervisor
or the suspend apparatus, and are measured on the implementation branch before
its PR leaves draft.

## 11. Interfaces

- **P2P (#1056):** `TSR-F1` (plan preconditions, the owner loop parks on the
  link) lands before the supervisor; the probe nonce kind in the nonce set; the
  own-edge redraw (`TSR-F9`); the dialer stops before the Tor teardown
  (`TSR-F13`).
- **Daemon configuration (#1066):** starts the supervisor at step 6 and stops
  it at step 9, after the dialer; step 8 does not wait for Tor, since the
  connector starts parked on the link, which also removes the SCM start's
  dependence on bootstrap time; `tor = managed | operator | off` is the
  supervisor's input; `tor-socks` is the operator route; `TSR-F8`; DC-F12 is a
  prerequisite (`TSR-F12`).
- **RPC:** `TSR-Q4`.
- **TB:** §7's Windows and macOS rows are TB-11's launch tests (`TSR-F15`).
- **Wallet:** none this round; the sans-IO core is there to adopt.

## 12. Increments (rule 26)

1. P2P lane: `TSR-F1`.
2. Control client: the bounded sink; parsers for `STATUS_GENERAL`,
   `STATUS_CLIENT`, `NETWORK_LIVENESS`, `HS_DESC` and log events; the launch
   recipe and `AvoidDiskWrites` in the closed list.
3. The supervisor core (sans-IO) and its timing-engine driver; the pin gate per
   spawn; the respawn routine per the `TSR-Q1`/`TSR-Q2` rulings.
4. The probe nonce and the probe.
5. The link replaces `tor_proxy` in the zone host.
6. Acceptance; then the C++ deletions, to Rick before they are cut.

## 13. Review denominator

Read for this round, at the pins above: the three Tor crates' public surfaces;
`actor.rs`'s launch, handshake, shutdown, event routing and readiness poll; the
wallet supervisor's loop and policy; `ephemeral.rs`, `data_dir.rs`,
`blocking.rs`; `daemon_tor_ffi.rs`; `net_node.inl`'s managed-Tor start,
liveness poll, teardown, self-connection check and announced address;
`mlog.cpp`'s default categories; on #1056 the dialer's `choose`, `attempt`,
pace and memory, the peerlist's outcome transition and disclosure population,
the zone host's proxy slot and `cause.rs`'s attribution; #1066's §2.2 and
DC-F12; PWD-E7, PWD-E9, TB-1 to TB-13, SP-T0 §3b and §3c; `RPC_CHANNEL.md`
§6.1; `INPUT_GRAMMAR.md` IG-13, IG-14 and its Tor rows; the control
specification's `TAKEOWNERSHIP`, `__OwningControllerProcess`,
`__OwningControllerFD`, Status, `HS_DESC`, `NETWORK_LIVENESS` and `LOG`
sections. Every rooted `dev` anchor (`rust/…`, `src/…`) is under
`check_doc_claims.py`'s dead-citation ratchet; the #1056 and #1066 anchors and
the continuation forms (`:1306-1313`) were read by hand at their pins.
Examined and found nothing to change: the pin gate and TB-7's launch
environment; the `shekyl-socks` client, which keeps the reply byte the
evidence attribution needs. Not examined, and next round's scope: the Windows
and macOS process and filesystem behaviour this design assumes (rename after
reap, kill semantics, the monotonic clock across suspend), which only §7 and
`TSR-M8` can settle; and the wallet's Tor under the same standard, which is
outside this brief.
