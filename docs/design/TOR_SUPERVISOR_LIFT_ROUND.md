# TSR-W2 Round 0: the Tor supervisor's driver in a shared crate

**Status:** DRAFT, Round 0 (rule 126). It is waiting for Rick's rulings, and
nothing is built until he rules. It settles the eight items and the five
wargames that the `TSR-W2` brief (Rick, 2026-11-28) sets, under the rulings
listed in §0.2. The lift PR implements what is ruled here for the daemon as the
only host. `TSR-W3` then adds the persona host.

**Decision authority:** this document proposes; Rick rules. Each ruled row
lands in [`TOR_SUPERVISOR.md`](TOR_SUPERVISOR.md) (§4, §5, §11.1) in the lift
PR. The `TSR-W1…TSR-WN` row of
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) is the work item's
index row.

**Pinned sha:** `0dcd2327762ca369333bc961e928b86a2cfa999f` (`dev` tip,
2026-11-28). Every `path:N–M` below was read at this sha. Paths are relative to
`rust/`.

---

## 0. How to read this

### 0.1 Identifiers

Decisions use the existing `TSR-Q` family. Findings, from the wargames and the
rule 126 A3 pass, use the existing `TSR-F` family. Both families are already
registered, so this document adds no prefix.

| ID | Item |
| --- | --- |
| `TSR-Q16` | The host interface (brief item 1) |
| `TSR-Q17` | The persona's probe proof (item 2) |
| `TSR-Q18` | Managed and unmanaged by type (item 3) |
| `TSR-Q19` | The daemon-shaped parts of the core (item 4) |
| `TSR-Q20` | Isolation, as tests (item 5) |
| `TSR-Q21` | The differences between the two hosts (item 6) |
| `TSR-Q22` | Who hears "unreachable" (item 7) |
| `TSR-Q23` | The crates (item 8) |
| `TSR-F19`…`TSR-F27` | The wargame and A3 findings (§10) |

### 0.2 Binding rulings this round works under

From the brief (Rick, 2026-11-27 and 2026-11-28) and his answers in session
(2026-11-28):

1. The Tor agent owns this work, and the wallet lane reviews it.
2. The supervisor is one actor that owns Tor's state. There is no shared cell
   and no second actor. (§3.3 asks how this reads for the daemon's node layer.)
3. The supervisor is shared as code, never as an instance. There is one Tor per
   identity domain, no shared directory cache, no joined status or logs, and
   separate respawn timing (§11.1).
4. Each instance is an island. It answers "can this onion be reached?" from its
   own probe, its own directory fetches and its own dial results. Nothing comes
   from a peer, another instance or an outside service. In production, a second
   node of ours is only a test rig's answer key.
5. Managed and unmanaged are split by type.
6. The guard manager is shared, as one off-loop request, and a persistent
   onion's publish needs the guards' witness (`TSR-W1`).
7. Production code only. There are no test switches.
8. **The host trait may land in the lift with one implementer**, under a rule 21
   reversion clause. The condition is that this round shows the persona host's
   implementation, method by method, against code that exists today. A method
   only the daemon can fill means the trait is wrong. The reversion: if
   `TSR-W3` is dropped, or re-scoped so that no persona host implements the
   trait, one PR folds the trait back into the daemon's concrete host and
   changes nothing else.
9. **There is no principal Tor.** A wallet's own traffic goes through its
   daemon, and there is one persona per wallet process. The topology is the
   daemon and one or more persona processes on one host (§1).
10. **The wallet lane builds the operator alarm board's reader** (brief
    `WALLET_ALARM_READER`, 2026-11-28). The record carried by the onion row is
    the one item agreed between the two lanes in this round (§7).
11. **The per-instance root, required by type, is accepted** as part of the
    design (§5.2).

The rule numbers in this document are the renumbered ones (#1563): 125, 126,
142, 176 and 194 for what the brief cites as 25, 26, 42, 76 and 94.

---

## 1. The topology

On one host there is one `shekyld`, holding at most one Tor instance (the
daemon's managed Tor, or none under `off` or an operator's Tor), and zero or
more wallet processes. Each of those serves at most one persona, and each
persona holds one Tor instance:

- `shekyl-tor-control-wallet/src/onion_service.rs:108–124`: one `Option` on
  the supervisor's config, so a second persona is a second wallet process.
- `shekyl-engine-core/src/engine/stake_engine/serving/tor_config.rs:40–50`:
  the residual of two staking wallets on one machine, and the recommendation of
  one per machine.

Today the only production Tor launches are:

- the daemon's, through `shekyl-tor-control-daemon/src/ephemeral/spawn.rs:227`;
- the persona host's, through `shekyl-p-host/src/host.rs:422–481`, which calls
  `WalletTorControl::spawn` (`shekyl-tor-control-wallet/src/service.rs:487`).

So no process holds two instances. In-process isolation (§5.1) is a property
the crate keeps so that this stays a choice of topology, never a constraint of
the code. Cross-process isolation (§5.2–§5.4) is the one the topology actually
exercises.

The persona's serving chain, re-read at the pin, runs in this order:

1. `StakeFacade::start_serving_if_staker`
   (`shekyl-engine-core/src/engine/stake_facade.rs:178`);
2. the serving start
   (`shekyl-engine-core/src/engine/stake_engine/serving/start.rs:134`), which
   takes the onion identity at `start.rs:193` from
   `StakeEngineHandle::persona_onion_identity` (`handle.rs:276–284`, an
   `OnionIdentity` and never the seed);
3. `spawn_serving_task` (`serving/task.rs:304`);
4. `PersonaServingHost::start` (`shekyl-p-host/src/host.rs:422–481`);
5. `WalletTorControl::spawn` (`service.rs:487`).

The virtual port is `SERVING_VIRTUAL_PORT` (`start.rs:247`).

---

## 2. The audit: what the driver depends on today (A2)

The driver is `shekyl-daemon/src/tor/`: 5,569 lines in `mod.rs`,
`requests.rs`, `probe.rs`, `guards.rs`, `onion_key.rs`, `inbox/` and
`loop_tests.rs`. The table lists every outside dependency and its proposed
disposition:

- **H**: a host method (§3.1);
- **S**: a value at start;
- **N**: the daemon's node layer (§3.3), outside the shared driver;
- **M**: moves into the shared crate;
- **Out**: stays out of the crate.

| Dependency | Where the driver uses it | Disposition |
| --- | --- | --- |
| `Network::engine()` | `mod.rs:807–810`: registers the driver's timing owner (`network.rs:606`) | **S**: a `Handle<MonotonicClock>` handed in |
| `Network::probe_delay_draw()` | `probe.rs:122, 148, 165, 189`, `requests.rs:513, 558`, `mod.rs:662`. It is `SecureRelayRng.next_u64()` (`network.rs:729–737`) | **S**: each instance's own draw source (§5.3). The draw at `mod.rs:662` (a path want) is **N** |
| `Network::managed_route(pair)` | `probe.rs:64`: the probe's SOCKS route, read back against the link (`network.rs:746–753`, `tor.rs:109–118`) | **H** `probe_route` |
| `Network::mint_probe()` | `probe.rs:67`: a 1001 handshake frame and its nonce (`network.rs:695–700`, `shekyl-p2p-session/src/layer.rs:537–556`) | **H** `mint_probe` |
| `Network::publish_managed_running(socks)` | `mod.rs:1398` (`network.rs:704–722`) | **H** `route_up` |
| `Network::publish_tor_down(id, cause)` | `mod.rs:1408` (`network.rs:762–767`) | **H** `route_down` |
| `Network::publish_tor_inbound(id, facet)` | `probe.rs:171–181` (`network.rs:755–760`) | **H** `inbound` |
| `Network::note_own_onion(id, port)` | `requests.rs:783–790`, beside the onion-address log line. The brief's list omits it (`network.rs:769`) | **H** `inbound`, in the daemon's body (§3.1) |
| `Network::publish_onion_path(reading, at)` | `mod.rs:1207–1214`, the `Action::PathReading` arm (`network.rs:691–694`) | **N** |
| `SupervisorFeeds`: tally, verdict, sessions, path, probes, `reading_wait` | `inbox/mod.rs:128–154` makes them; `shekyl-p2p/src/tor.rs:47–67` declares them | Probes: **M**, behind a crate-owned arrival type (§3.4). Tally, verdict, sessions and path: **N** |
| The inbox's `Changed` cells: tally, verdict, sessions, forward | `inbox/mod.rs:97–107` | Forward: **M**. The other three: **N** |
| `Arrival::Probe(ProbeArrival)`, `Arrival::Path(PathFact)` | `inbox/mod.rs:60–93` | Probe: **M**, with the crate's own `ProbeArrival`. Path: **N** |
| `shekyl_daemon_config::sections::Tor` | `mod.rs:513–533`: picks `Supervises` | **Out**. The daemon reads its settings and starts either an instance or the node layer alone (§3.2) |
| `shekyl_daemon_rpc::tor_facts` (`TorFacts`, `TorFuture`, `TorHandle`, `FactsFault`) | The status and `hiding` asks | **Out**. The daemon's node layer answers them (§3.2, §3.3) |
| `shekyl_tor_control_daemon`: the control wrapper, spawn, data directories, the probe dial, `TorDeath`, `IsolationPair` | Throughout `requests.rs` and `probe.rs` | **M**: the whole crate folds into the shared one (§8) |
| `shekyl_tor_status` | `mod.rs:59`: the status words | **Out** of the driver: the hosts render (§7) |
| `shekyl_onion_key`, `shekyl_options`, `shekyl_os_account::key_file` | `onion_key.rs`: loads the operator's persistent key file | **Out**. The daemon loads the key and hands an `OnionIdentity` in (**S**) |
| `tracing`: 48 lines on `tor` and 12 on `global`, all with explicit targets | The whole driver | **H** `say` (§3.5). The brief counts 47 on `tor`; the 48th is #1571's `took_ms` line |

**Every dependency has a disposition.** One finding is more than a
disposition. `requests.rs:785–790` logs this node's onion address at `info`
on `global`. For the daemon that is the operator's own fact. For a persona it
is a P-correlated identifier, which `WSS-20` forbids in any log
(`shekyl-logging/tests/p_correlated_ids_absent_from_logs.rs:5–60`). It is the
reason `say` and the onion-address line are host-side (§3.5).

---

## 3. `TSR-Q16`: the host interface

### 3.1 The trait

The trait has six methods, and both hosts fill each of them. Nothing in it is
daemon-only, so the trait meets Rick's condition. What only the daemon has
(its relay verdict, sessions, dial tally and onion-path reading) is not in the
trait. Those are the node layer's (§3.3).

```rust
/// One instance's domain: where its route, verdict and words go.
pub trait InstanceHost: Send + 'static {
    /// The instance's Tor is running with SOCKS at `socks`.
    /// Returns the mark the host's later calls name.
    fn route_up(&mut self, socks: SocketAddr) -> RouteMark;
    /// The route `mark` fell, for `cause`.
    fn route_down(&mut self, mark: RouteMark, cause: RouteDown);
    /// The SOCKS route the probe dials, isolated by `pair`.
    /// `None` while there is none.
    fn probe_route(&self, pair: &IsolationPair) -> Option<Proxy>;
    /// A probe: the bytes to write, and the nonce, held until the probe ends.
    fn mint_probe(&mut self) -> Option<ProbeTicket>;
    /// The onion's reachability verdict, on route `mark`.
    fn inbound(&mut self, mark: RouteMark, onion: &ServiceId, verdict: Inbound);
    /// Something the instance says.
    fn say(&self, said: Said);
}
```

Each body, daemon beside persona:

| Method | Daemon (lift) | Persona (`TSR-W3`) | Persona rests on |
| --- | --- | --- | --- |
| `route_up` | `Network::publish_managed_running` (`network.rs:704–722`), as `mod.rs:1397–1410` does now | Records `socks`, and publishes `TorPosture::Ready { socks_addr, .. }` on the host's posture watch | Today's code: `TorPosture` (`shekyl-tor-control-wallet/src/service.rs:100–161`), which moves with the host (§8) |
| `route_down` | `Network::publish_tor_down` (`network.rs:762–767`) | Publishes `Restarting`/`Degraded` on the same watch | Today's code: the same `TorPosture` |
| `probe_route` | `Network::managed_route` (`network.rs:746–753`) | `Proxy::authenticated_shared(socks, pair)` over the recorded `socks` (`shekyl-socks`, as `tor.rs:109–118` builds it) | Today's code |
| `mint_probe` | `Network::mint_probe` (`network.rs:695–700`): the 1001 frame, with the nonce in `HandshakeNonceSet` (`shekyl-p2p-session/src/nonce.rs:136–146`) | Mints into the serving endpoint's probe table (§4) and returns the HTTP request bytes | **`TSR-W3`-new**: the table in `shekyl-p-serve` |
| `inbound` | `Network::publish_tor_inbound` (`network.rs:755–760`). On the route's first `Publishing`, it also runs `note_own_onion` and the onion-address line (`requests.rs:783–790`), moved here word for word | Writes the onion row on the wallet's alarm board (§7). `onion` is its own derived id; it is never written anywhere | **`TSR-W3`-new**: the alarm variant and its producer (§7). The board is today's |
| `say` | Renders each `Said` to today's target, level and text (§3.5) | Renders the allowed subset to the wallet's log under the `WSS-20` gate. The onion address is never a `Said` field | **`TSR-W3`-new**: the persona's rendering table |

The trait has three `TSR-W3`-new persona bodies (`mint_probe`, `inbound`,
`say`). Each rests on a type this round names (§4, §7, §3.5), and on nothing
that only the daemon has. `TSR-W3` implements the trait without editing any
signature the lift lands (rule 126 A1). The A1 reopening criterion stays as
rule 126 states it.

**The `inbound` timing.** Today `note_own_onion` and the address line run
when `ADD_ONION` is answered (`requests.rs:780–790`). The core then folds
`Input::OnionPublished` and asks for `PublishInbound(Publishing)` in the same
pass. Moving the two into the daemon's `inbound` body keeps their order
relative to every other host call: nothing reaches the host between them. The
lift's loop tests pin that order (§9.1).

### 3.2 Values at start

| Value | Daemon | Persona |
| --- | --- | --- |
| `root: InstanceRoot` (§5.2) | Its root under the data directory (§5.2 asks where) | `<wallet>.tor` (`shekyl-engine-file/src/paths.rs:192–196`) |
| `onion: OnionSource` | `PerBoot`, or `Persistent(key file)` (`mod.rs:700–707`) | `Persistent(derived)` (`handle.rs:276–284`) |
| Guards | Follows `onion`: persistent means managed (`mod.rs:771–790`) | Always persistent, so always managed. The `ServingPosture` rule (`service.rs:415–430`) is kept by construction |
| `pin: PinSource` | `Discover(binary)` (`mod.rs:710–717`) | `Discover(tor-file)` (`tor_config.rs:190–196`) |
| `ports: OnionPorts { virtual_port, max_streams }` | The configured port and `MAX_STREAMS = 8` (`mod.rs:81–82`) | `SERVING_VIRTUAL_PORT`, and the spec's `max_streams` (`onion_service.rs:128–139`) |
| PoW | On (`requests.rs` publish, `OnionPow`) | On by default (`onion_service.rs:137–150`) |
| `dirs: DataDirs` (§6) | `PerBoot` | `Durable` |
| `engine: Handle<MonotonicClock>` | `network.engine()` | The wallet process's one `EngineService` (§8) |
| `draws: Box<dyn RelayRng + Send>` (§5.3) | `SecureRelayRng` | `SecureRelayRng`, its own instance |
| `policy: Policy` | `Policy::provisional()` (`mod.rs:78–80`) | The same |

The forward listener stays a cell. The daemon's zone host binds after the
start and posts it (`inbox/mod.rs:163–167`). The persona posts its serving
endpoint's address once, at start (`host.rs:451–466`).

### 3.3 The node layer (`TSR-Q19`, and the second actor)

What the core folds today that only a node has:

- **The relay's verdict** (`core/mod.rs:658`, `origin_verdict`
  `core/mod.rs:1671–1685`). It feeds `health`, `own_tx` and an announcement's
  cadence.
- **Sessions** (`core/mod.rs:663–664, 1057–1060`). They feed `sync`.
- **The dial tally** (`core/mod.rs:659–661`, `dials.rs:123–139`). It is display
  only (`TSR-Q14`) and feeds the quiet line (`SayProgress`, `tor_quiet`). It
  drives no remedy and no respawn.
- **The onion-path facts and wants** (`core/mod.rs:683–704`,
  `onion_path.rs:127–166`). The reading is published to the Tor connector's
  judge (`mod.rs:1207–1214`). This runs under every setting, `off` and
  `operator` included: `path_fact` has no managed test, and the driver
  publishes the reading whatever the setting.
- **`own_tx` and `fixes`** (`posture.rs:592–616`). They read the verdict and
  the daemon's connector settings.

Each of these is **status or the connector's input; none is a remedy for the
instance's Tor**. The one coupling the other way is a path want. It asks for a
reachability check, which is the instance's probe (`onion_path.rs:151–166` →
`probe.rs:266–284`). Under a persona these facts do not exist. A persona has
no relay, no peer sessions, no dialer and no connector judge. Each one is
**absent by type** (§3.4), never a default.

The proposal is a **node layer** in `shekyl-daemon`. It is a small actor that
owns the verdict, sessions, tally, the onion-path state and the connector
settings. It answers `daemon_status` and Health's `hiding`.

- **Under a managed Tor** it holds the instance's handle. It reads the
  instance's status (phase, cause, inbound, bootstrap, clock, rounds, respawn
  count, and the latest probe verdict with its time). It sends the instance
  `CheckWanted { after, draw }` when the connector wants a reading.
- **Under `off` or an operator's Tor** it runs alone. That is item 3's
  unmanaged answerer (§3.2).

**This is a second actor in the managed daemon**, beside the instance's
driver. It owns no Tor state, sends Tor nothing, and holds no cell the
instance reads. Binding ruling 2 says "no second actor". I read that ruling as
being about Tor's state, as `TSR-Q9` and `TSR-W1` used it, but **that reading
is Rick's to confirm**. The alternative keeps these facts inside the shared
core behind an `Option<NodeSide>`. That is a runtime check, which ruling 5
refuses, and the persona's `None` is a dummy.

### 3.4 What crosses into the shared crate

- **A probe's arrival.** The crate owns `ProbeArrival { minted_at, arrived_at }`
  (two `Tick`s) and the poster that takes it. The daemon adapts
  `shekyl-p2p-session`'s `ProbeSink` (`owners.rs:207–220`) onto that poster in
  `shekyl-daemon`. The persona's serving endpoint calls the poster directly
  (§4). The shared crate never names `shekyl-p2p`.
- **`CheckWanted { after, draw }`**, as an input any host may send. Only the
  daemon's node layer sends it.
- **The status**, as the instance's own typed read. It has no relay, session or
  dial fields. The daemon composes it with the node layer's (§3.2). The
  persona's host reads it for the onion row (§7).

### 3.5 Who speaks (`say`)

The driver gets no logging dependency. Each of its 60 lines becomes a `Said`
variant carrying typed fields. Errors are carried as their types, not their
text. The daemon host renders each variant to today's target, level and words.
The lift proves this:

- a table test, one row per variant, compares the rendered line with today's
  literal;
- the daemon's existing `crate::logged` assertions pass unchanged.

The shared crate joins `WSS-20`'s `P_PATH_CRATES_WITHOUT_LOGGING`
(`shekyl-logging/tests/p_correlated_ids_absent_from_logs.rs:190–195`) in the
lift. Nothing in it can log, and that check can fail.

Four lines in today's driver need care:

1. **The onion-address line** becomes the daemon's `inbound` body (§3.1).
   `Said` has no variant carrying a `ServiceId`.
2. **Tor's own log lines** (`say_tor_log`, `mod.rs:554–561`) become
   `Said::TorLog(LogEvent)`. The daemon relays them as now. Under `TSR-W3`,
   the persona host does not relay them to the wallet's log. They stay in
   Tor's notice log inside the instance's root (`LOG_FILE_NAME`). `TSR-M9`
   showed no onion address at `notice` under the daemon's configuration, not
   the persona's.
3. **Errors whose `Display` can carry an onion id.**
   `AddOnionReplyError::ServiceIdMismatch { expected, .. }`
   (`shekyl-tor-control-client/src/control/onion.rs:488–495`) prints the
   expected id. The persona's rendering table names each error-bearing variant
   and renders its kind, never its `Display`. `TSR-W3`'s `WSS-20` row checks
   this.
4. **The probe's delay draw** is never said, as now (`probe.rs:195–198`).

---

## 4. `TSR-Q17`: the persona's probe proof

The ruled design: the instance mints a nonce, the serving path recognises it
before anything that serves, and the signer is kept from it by type.

### 4.1 The bytes

The probe's request is one fixed-length head:

```
GET /shard/18446744073709551615 HTTP/1.1\r\n
shekyl-pass-request: <146 lowercase hex>\r\n
\r\n
```

The 73-byte header (`stream[1] ‖ nonce[32] ‖ anchor_height_le[8] ‖ anchor_hash[32]`;
`shekyl-curve-tree/src/serving_route.rs:63–76, 107`) is filled as follows:

| Field | Value | Why |
| --- | --- | --- |
| `stream` | `0` | Never read. Recognition looks only at the nonce |
| `nonce` | 32 bytes from the instance's draw source, one per probe | The recognition key (§4.3) |
| `anchor_height` | `u64::MAX` | Never inside the pre-sign gate. `anchor_within_gate` admits `[p−720−L, p−720+L]` (`shekyl-p-serve/src/countersign.rs:191–206`), and its top is at most `p − 716`. A probe that recognition failed to catch gets the bare 400 before the store is consulted (`serve.rs:470–476`): nothing is served and nothing is signed |
| `anchor_hash` | 32 zero bytes | Carries nothing |
| shard id | `u64::MAX` | Carries no meaning. The gate refuses first, so the id is never consulted |

Only this process ever sees these bytes, because the probe runs end to end
inside the instance's own Tor to its own onion. Matching a challenger's request
byte for byte would buy nothing. What matters at the cell level is the length,
and the head fits in one cell either way.

### 4.2 Where recognition sits: after the cap

The brief's wargame line has the check before the connection cap. The code
argues for after it, and **this is the one point where this round departs
from the brief; Rick rules it**.

- **Today the cap is decided at accept, before any byte is read.**
  `try_acquire_owned` either takes one of `MAX_INFLIGHT = 64` permits or drops
  the stream (`serve.rs:180, 328, 349–353`). Recognising a probe before the cap
  means reading heads from connections the cap would have dropped. That needs
  a new stage with its own count, time and byte bounds, and an attacker can
  fill that stage. Filling it either drops the probe or, if the stage is
  uncapped, turns it into a free resource.
- **"Reachable" is a statement about challengers.** The row reads
  "challengers can reach this persona's onion". While the cap is full, a
  challenger is refused. A probe that went around the cap would report
  reachable in exactly the state where the challenger is not. Behind the cap,
  the probe's answer is the challenger's answer.
- **The daemon's probe is recognised the same way.** Its nonce is taken in the
  handshake, after the session's permit (`shekyl-p2p-session/src/session.rs:435–458`).

So recognition is the connection task's **first step after `read_head`**
(`serve.rs:512–514`; bounded at 8 KiB, `serve.rs:158`, and 30 s,
`serve.rs:183`). It comes **before `parse_request`, `resolve`, the gate, the
store, the counters and the signer.** A probe that meets a full cap is refused
like any caller, and `refused` counts it. The connection is one, and the
counter's meaning, the operator's capacity signal, is kept.

### 4.3 The check

- **Bounded parsing.** The head must be exactly the probe's fixed length, with
  the fixed request line and header name. If it is, the 146 hex characters at
  the fixed offset are decoded, with no scanning, and bytes `1..33` are the
  nonce. Anything else falls straight through to `parse_request` with the head
  untouched.
- **Constant-time lookup.** The probe table is a fixed array of slots. Every
  slot is compared over all 32 bytes with `subtle::ConstantTimeEq` (`subtle`
  is already a workspace dependency of `shekyl-crypto-pq` and
  `shekyl-rpc-channel`). The scan never exits early, so the time is the same
  whether or not any slot matches.
- **A miss falls through.** A head that is not the probe's shape, or whose
  nonce is in no slot, takes the normal path: the 400/404/503/200 classes of
  `serve.rs:460–505`.
- **The type.** Recognition returns `Recognised::Probe(ProbeArrival)` or
  `Recognised::Request(Head)`. `resolve` and the `PassSigner` take only a
  `Head`, and only the fall-through arm can build one. A probe cannot reach the
  signer by construction, not by a check.

### 4.4 Nonce lifetime: the `Flight` discipline

There is one nonce per probe. It is in the table before the request bytes are
written. It leaves the table on arrival (the take erases it) or when the
instance's `Flight` drops at the bound. The drop erases first, then aborts the
dial, on the driver's task (`shekyl-daemon/src/tor/probe.rs:31–48`). This is
the same order as `InFlightNonce` (`nonce.rs:192–212`). A replay finds an empty
slot and falls through. A nonce taken at or after the bound is not evidence:
the core judges the take against the bound
(`core/probe.rs:785–800`).

**Where the nonce exists in plaintext, and nowhere else:**

1. the probe table's slot;
2. the `Flight`'s ticket;
3. the dial task's request buffer;
4. the loopback SOCKS connection to the instance's own Tor;
5. that Tor's memory, client side and service side;
6. the onion's loopback forward to the serving listener;
7. the connection task's head buffer.

It is never logged, never in a status, and never on the wire outside Tor's
encryption.

### 4.5 What a probe never counts as

- **Served traffic.** No counter except `refused` moves (§4.2). `served`,
  `not_held`, `lookup_failures` and `sign_failures`
  (`serve_counters.rs`) are reached only through `resolve`.
- **A challenge answered.** The signer never sees a probe (§4.3).
- **Anything a third party could have sent.** A third party cannot know a live
  nonce, since one guess is 2⁻²⁵⁶ per live slot. A replay finds nothing. A head
  in the probe's shape with an unknown nonce is an ordinary request.

### 4.6 What a forced miss triggers

Two misses make the verdict: a refetch, then `Unreachable(ProbeTimedOut)` or
`(DescriptorNotFound)` (`core/probe.rs:741–757`). The verdict then does three
things:

- republishes under the republish hold (`TSR-M14`; `core/probe.rs:897–913`);
- announces the verdict, through the host's `inbound`, which writes the alarm
  row;
- **never respawns Tor by itself.**

A respawn follows only when Tor refuses the republish's `ADD_ONION`, which is
a process fault (`core/probe.rs:919–926`). An attacker who fills the cap at
each probe gets misses, republishes on the hold's backoff, and a true
"unreachable" row. They already know the onion, so the republishes tell them
nothing new (`TSR-F23`).

---

## 5. `TSR-Q20`: isolation, as tests

### 5.1 In-process: "share nothing" defined so that a test can fail

Two instances in one process **share nothing** when two things hold:

- **No crate-level `static`.** The shared crate declares no `static`, no
  `thread_local!` and no `OnceLock`/`LazyLock` outside `const`. This is a
  source gate in the crate's tests. It fails on the first one added.
- **Drive one, the other stays the same.** Instance A is driven through a full
  cycle: launch, publish, a probe arrival, a miss, a republish, a death, a
  respawn. Its host's call log equals the log of an A that ran alone on the
  same inputs, `ManualClock` and draws, while instance B runs its own different
  cycle in the same process. The same holds with A and B swapped. A shared
  queue, cell, counter, draw source or table would make the logs differ.

A test has no way to prove that two instances in one process are
indistinguishable to a reader, because a test can only compare logs. So that
claim is made per process: there is one instance per process (§1).

Process-wide state outside the crate, each with a disposition:

| State | Where | What it holds | Disposition |
| --- | --- | --- | --- |
| `PROCESS_ORIGIN` | `shekyl-timing-engine/src/lib.rs:134–136` | The first clock reading in the process. Read-only after that | **Allowed.** It holds no instance's state, and every instance in the process reads the same epoch |
| `IdSource`'s `NEXT` | `shekyl-timing-engine/src/lib.rs:380–383` | A counter of id *sources*, one per `EngineService` | **Allowed.** It counts engines, not instances. The wallet process starts one engine (§8). Owner ids are per source |
| `LEDGER` and `NEXT_ID` | `shekyl-thread-ledger/src/lib.rs:418–419` | The process's dedicated threads | **Allowed.** The rows are per process, and one instance per process makes them single-domain |
| kameo's `ACTOR_COUNTER` | `kameo-0.20.0/src/actor/id.rs:13` | A process-sequential `ActorId`, carried in kameo's own lines (`actor/spawn.rs:183, 424, 427`, target `kameo::actor::spawn`) | **Named.** It shows how many actors a process spawned, not which domain. `TSR-W3` shows that the wallet process's log filter excludes `kameo::*` at the levels it keeps, or that those lines carry no domain identifier (`TSR-F21`) |
| kameo's `ACTOR_REGISTRY` | `kameo-0.20.0/src/registry.rs:18` | Name-registered actors | **Unused.** No Tor crate registers an actor by name. The source gate refuses `.register(` in the shared crate |

### 5.2 Roots, across processes

`sweep_stale_data_dirs(parent, spare)` removes every entry under `parent`
whose name starts with `ephemeral-tor-` (`shekyl-tor-control-daemon/src/data_dir.rs:31–104`).
Two instances under one parent would delete each other's live directories.
There is also a contrived case today: a wallet file named `ephemeral-tor-…`
placed in the daemon's data directory would have its `.tor` directory, its
`.keys` and the wallet itself swept.

**The root.** `InstanceRoot::claim(dir) -> Result<InstanceRoot, RootRefused>`
is the only constructor.

- It creates `dir` at `0700`, or refuses a directory that exists with group or
  world write, as `establish_data_dir` does today (`tor_config.rs:238–260`).
- It takes an exclusive OS lock on `dir/instance.lock` with `fd-lock` (already
  a workspace dependency, `shekyl-engine-file/Cargo.toml:26`). The lock is
  held until the root drops.
- The sweep, the per-boot directories, the kept logs, the directory cache and
  the guard state all take `&InstanceRoot` and resolve inside it. **Nothing an
  instance writes or removes is outside its root.** There is no API that takes
  a bare parent path.

**Platform semantics**, as read in `shekyl-engine-file/src/lock.rs:28–40`:

- **POSIX:** `flock(2)`, which is advisory. A process of the same account can
  ignore it, and that is host compromise for this purpose.
- **Windows:** `LockFileEx` locks byte 0 of the file, and the lock is
  mandatory. `instance.lock` is a dedicated empty file that nothing reads, so
  mandatory locking only stops it being opened through another handle.

**The roots are disjoint by derivation**, and the lock covers the rest. The
persona's is `<wallet>.tor`, already exclusive per wallet because the keys
file's lock allows one handle per wallet (`lock.rs:1–20`). For the daemon,
**Rick rules where its root is** (asked in session):

- **(a) `<data-dir>/tor/`, a directory of its own.** The per-boot directories,
  kept logs, `tor-directory-cache` and `tor-guard-state-*` move into it. This
  is pre-genesis with no migration code (rule 60). On first start, a running
  node refetches the directory cache once, and a persistent onion re-draws its
  guards once. That is a visible change in a lift whose contract is "no
  behaviour change", so the lift PR body would name it.
- **(b) `<data-dir>` itself, as today.** It is already held by `shekyld.lock`
  for the process's life (`shekyl-daemon-config/src/lock.rs:1–25`, taken at
  `shekyl-daemon/src/run.rs:247`, before `tor::begin` at `run.rs:547`). The
  root would claim `instance.lock` inside it. The contrived wallet-in-data-dir
  case stays, but no instance can sweep it.

The recommendation is (a). An exclusive root is what the type promises, and
(b) keeps a root that holds other owners' files.

**The failure row** (rule 82):

- `RootRefused::Held` means another process holds this instance's root. For
  the daemon it cannot occur while `shekyld.lock` is held. For a persona it
  cannot occur while the keys file is locked. If it does occur, the start is
  refused with "Tor's directory `<root>` is in use by another process; stop
  that process or pick another directory". The daemon reaches its stop through
  the supervisor's end (#1557).
- `RootRefused::Unusable(io)` maps to the existing `DirectoryUnusable` row.

### 5.3 Jitter: each instance's own draws

Each instance owns the draw source its host hands it at start (§3.2). The
probe's delay, the path check's delay and the clock-jump probe draw only from
it. The two-instance test in §5.1 hands A and B distinct deterministic sources
and checks that each instance's delays follow its own. Independent draws make
the delays independent. They do **not** make two co-located instances
unlinkable (§10, `TSR-F20`).

### 5.4 Logs, across processes

The daemon logs to its own file or stream. A wallet process logs to its own.
Nothing in the shared crate opens a file or a stream (§3.5), so one process's
lines cannot reach another process's file through this code.

- **Under systemd,** the journal is one store, with a stream per unit. A
  reader of the journal is on the host. What that reader can link is bounded
  by the lines' contents. The daemon's stream names the daemon's onion (§2).
  A persona's stream never names its onion (§3.5). So the journal ties the
  host to the daemon's onion, as it does today, and never to the persona's
  onion.
- **Co-occurrence** across the two streams (both Tors lose the network at the
  same moment) is shared fate, not a joined stream (`TSR-F20`).

---

## 6. `TSR-Q21`: the differences between the two hosts

| Difference | Daemon | Persona | Disposition |
| --- | --- | --- | --- |
| **Data directory** | A new directory per boot. One kept for a respawn inside the boot (`TSR-Q1`). The directory cache as a sibling (`TSR-Q8`), guard state as a sibling (`TSR-Q15`, `TSR-Q2` as amended). Retired by tombstone (`data_dir.rs:1–25`) | One durable directory, reused across incarnations and sessions (`service.rs:394–400`, DQ-T0.7) | `DataDirs::PerBoot` or `DataDirs::Durable`, a value at start. Both live in the shared crate under the root (§5.2). The persona's cache is its own directory, never shared (§11.1) |
| **Bootstrap** | The core's bootstrap judgment and its progress window | A 300 s kill (`service.rs:279, 305, 770`) | The 300 s kill goes at `TSR-W3`. The persona takes the core's judgment |
| **The binary's source** | `Action::CheckPin` before the first launch and before every respawn (`core/mod.rs:759–762`, `shekyl-daemon/src/tor/mod.rs:489–503`) | A re-check on every spawn (`service.rs:17–23`) | One mechanism already: the core's `CheckPin`. `TSR-W3` deletes the wallet's re-check |
| **SOCKS** | `SocksPort auto`, discovered (`ephemeral/spawn.rs:227`, `parse_socks_listeners`) | The same (`service.rs:35–42`) | The same shape. The address goes to `route_up` |
| **Key and guards** | Per boot or persistent. Guards managed only when persistent | Always persistent (seed-derived), so guards always managed | The value at start (§3.2) |
| **Stream cap and PoW** | `MaxStreams = 8`, PoW on | The spec's value with close-circuit on, PoW on | The value at start |
| **Respawn timing** | The core's backoff, per instance | The wallet's own backoff (`service.rs:24–28`) | The core's backoff, per instance. `TSR-W3` deletes the wallet's |

---

## 7. `TSR-Q22`: who hears "unreachable"

The persona's verdict reaches the operator through the wallet's own surface.
That surface is the wallet lane's reader, as built on its branch
`feat/operator-alarm-reader` (not yet a PR, and not on `dev` at the pin).
The names below are that branch's: the one-board `Engine`, the reader's
methods, `DisarmedReason::Unreported`, `CheckGuard`, `report_not_serving`,
and Part M's `IG-Q115` and `IG-Q119`. This round cites them as proposals and moves with them if they
change in review.

- **Producer.** The instance's host `inbound` method (§3.1).
- **Board.** One `OperatorAlarms` per wallet, held on the `Engine` for the
  wallet's open span. The cadence driver and serving starts write to the same
  board.
- **Readers.** The wallet lane's reader: the wallet RPC methods
  `operator_alarm` and `operator_alarm_acknowledge`, and the CLI command
  `operator alarm` (`wallet_rpc.yaml` 0.28.0). Their names are `IG-Q115` in
  [`INPUT_GRAMMAR.md`](INPUT_GRAMMAR.md) Part M, where the wallet lane
  recommends `wallet alarm`.

**The record, agreed between the two lanes (2026-11-28):**

1. **The condition.** `AlarmCondition::OnionReachability` ("challengers can
   reach this persona's onion") is separate from `TransportLiveness`.
   - Every row starts disarmed as `DisarmedReason::Unreported` (wire
     `unreported`: no check is reporting). The onion row stays there until
     `TSR-W3` arms it.
   - After that, the board's other reasons apply. Their wire names are
     proposed in Part M, `IG-Q119`: `transport-unready`, `TransportStopped`
     and `host-down`.
2. **The detail.** It is `shekyl_tor_status::Onion` (state, age in awake
   seconds, cause; `shekyl-tor-status/src/lib.rs:678–686`). That is the same
   vocabulary as `daemon_status`, and the wallet RPC carries the same object.
3. **The words.** They come from a persona renderer in `shekyl-tor-status`,
   beside `onion_sentence`. It speaks of challengers and the bond, never "this
   node" or "peers". The CLI writes no Tor sentence of its own.
4. **The payload.** It is a `Copy` core of the known causes, carried in the
   alarm. `OperatorAlarm` stays `Copy` with no `String` (the crate's
   memory-amplifier closure). `OnionCause::Unknown { tag }`
   (`lib.rs:549–553`) stays an arm of the wire type that only decoding can
   produce.
5. **The causes.** All seven known causes apply to a persona as written:
   `probe-missed`, `uploads-refused`, `descriptor-missing`, `clock-behind`,
   `published-elsewhere`, `guards-refused` and `guards-unfilled`.
   - For a persona, `published-elsewhere` means a second process holds this
     wallet's seed and serves its onion. The persona's words say so.
   - A probe that could not be dialed is not a cause. It returns the core's
     probe to idle with no verdict (`core/probe.rs:776–783`), and the verdict
     stands as it was.
6. **The lifetime.** An `Episode`. It ends when the onion is reachable again,
   or on a disarm reason.
7. **No identifier, on any surface.** The record and its words carry no onion
   address, no service id, and no time on any clock but the age. The wallet
   lane holds every row on the board, and its RPC object, to that.

The wallet lane's review on #1578 raised three more points. The proposals
below answer them, and **Rick rules the first two**.

8. **`publishing`, and a verdict that has gone stale (`TSR-F25`).** An alarm
   is live only while the onion is unreachable, so `publishing` had no place
   on the row. A host that is alive but never probes would keep its last
   verdict armed. The board's `CheckGuard` sees a producer that ends, not one
   that has gone silent.
   - **The bound.** The proposal is one bound, `VERDICT_FRESH`, derived from
     the core's own constants, never a literal:
     - `DESCRIPTOR_LIFETIME`, 3 h (`core/mod.rs:231`). A healthy instance
       begins a round within it, or the core republishes to force one
       (`core/probe.rs:315–335`);
     - plus `ROUND_WAIT`;
     - plus `PROBE_AFTER_MAX`;
     - plus two probe bounds (`PROBE_WITHIN`), for the first attempt and the
       attempt after the refetch.

     In a healthy instance a verdict is never older than that.
   - **The row**, by state:
     - **Armed and clean:** only a `Reachable` verdict younger than
       `VERDICT_FRESH`.
     - **Live:** `Unreachable`, at any age. It is an episode until reachable.
     - **Disarmed**, with a reason Part M names (proposed "the first check is
       pending"): `NotOffered`, and `Publishing` younger than the bound.
     - **Past the bound** (`Publishing` or `Reachable` with no newer verdict):
       a **live alarm** that reachability is unknown.
   - **Unknown is an alarm, not a disarm.** For a bonded persona, reachability
     unknown for longer than the healthy maximum is a failure mode (rule 82),
     not a quiet "not checked". The live alarm needs one new cause beside the
     seven, proposed `unchecked`. That is an addition to `shekyl-tor-status`'s
     wire type, so a minor version bump. The alternative is the wallet lane's
     suggestion: a disarmed reason past the bound. It is honest, but it does
     not alarm. **Rick rules which.**
9. **A full serving cap.** Recognition sits behind the cap (§4.2), so a full
   cap shows on this row as unreachable (`probe-missed`) with no capacity
   reading beside it. `refused` is on no alarm today. `serve_health` raises on
   signing, lookups and accepts, not on the cap.
   - The proposal is that `TSR-W3` adds `refused` to `ServeHealth`, as a
     capacity reading.
   - The persona's words for `probe-missed` name both causes: the onion path,
     and a serving cap that is full. When the capacity reading is live, they
     point to it, so an operator under load is not sent to look at Tor.
   - Rick rules whether `refused` joins `ServeHealth` or gets a row of its own.
10. **Guard and teardown.** `TSR-W3`'s producer holds
    `OperatorAlarms::check_guard(&[AlarmCondition::OnionReachability])` for
    the instance's life. The serving task's not-serving report
    (`report_not_serving`, `serving/task.rs`) also takes the onion row, so a
    stopped host reads `host-down` on it, as on the board's other rows.

**A correction to what I told the wallet lane.** I said "the bound decides"
for a probe that was not dialed. It does not. A probe that was not dialed
gives no verdict either way. For a persona, the persistent causes of an
undialed probe are no SOCKS route, no onion yet, or a mint refused. Each of
those comes with a Tor that is not `Running`. Leaving `Running` resets the
verdict (`core/running.rs:38–44`), and the transport's disarm reasons cover
the row. One case is left: a hostile host whose `mint_probe` always returns
`None` while Tor runs. No type forbids it (`TSR-F25`). Item 8's bound turns
its stale verdict into a value on the board, instead of something a reader
has to work out from the age.

**The split between the PRs.** The wallet lane's PR adds the condition and its
disarmed row, with no variant and no payload. `TSR-W3` adds three things
together, so that no symbol lands before it is used:

- the alarm variant carrying the `Copy` core;
- the persona renderer;
- the producer.

---

## 8. `TSR-Q23`: the crates

**A new crate, `shekyl-tor-supervisor`** (rule 126: a new crate is its own
design, review, gates and PR; this round is the design). The lift fills it
with three things:

- the driver, moved from `shekyl-daemon/src/tor/` with its tests;
- the `InstanceHost` trait and `InstanceRoot`;
- the whole of `shekyl-tor-control-daemon`:
  - the control wrapper and spawn (`ephemeral/`);
  - the per-boot directories (`data_dir.rs`);
  - the probe's dial (`probe.rs`).

The lift folds `shekyl-tor-control-daemon` into the new crate and deletes it
(rule 15).

**Its dependencies** (rules 125 and 17). Each is already in the workspace, so
nothing new needs vetting:

| Dependency | What for |
| --- | --- |
| `shekyl-tor-control-client` | The core, control, binary and guard manager |
| `shekyl-timing-engine` | Clocks and owners |
| `shekyl-socks` | The probe's `Proxy` |
| `shekyl-onion-key` | Onion keys |
| `fd-lock` | The root's lock |
| `subtle` | Only if the probe table lives here. §4 puts it in `shekyl-p-serve`, so it is not |
| `tokio` | Runtime, with the features `-daemon` uses now |
| `kameo` | Actors |
| `zeroize` | Wiping secrets |
| `getrandom` | Random bytes |

It names no `tracing` (§3.5), no `shekyl-p2p`, no `shekyl-daemon-*` and no
`shekyl-engine-*`.

**`shekyl-tor` (the connector)** uses `DaemonTorControl`'s publish
(`shekyl-tor/src/publish.rs:24`). It follows the type into the new crate.
`shekyl-wss-q1b-bench` names `-daemon` in a comment only.

**After `TSR-W3`:**

- **`shekyl-tor-control-wallet` is deleted.** Its supervisor (backoff, 300 s
  kill, re-pin) is replaced by the shared driver.
- **`OnionServiceSpec`, `TorPosture`, `ServiceFailure` and `ServiceWarning`**
  move to the persona host's own module in `shekyl-p-host`. They are the
  persona host's posture watch, which `route_up` and `route_down` publish.
- **`shekyl-operator-alarm`'s mapping**
  (`shekyl-operator-alarm/src/tor_posture.rs:39–51`) follows `TorPosture`.
- **`shekyl-crypto-pq`** names `-wallet` only in a `Cargo.lock` comment
  (`shekyl-crypto-pq/Cargo.toml:256`). The comment is corrected there.
- **`shekyl-tor-control-client`'s module doc** ("the launch path for a second
  Tor instance", `service.rs:73–78`) is corrected. Its consumers are the
  daemon and the wallet's persona, not a principal.

**What the wallet process supplies for the timing engine.** One
`EngineService::start(MonotonicClock::new())`
(`shekyl-timing-engine/src/service/mod.rs:395–423`) per wallet process, held by
the engine for the wallet's open span. The persona host takes a `Handle` from
it. This is `TSR-W3`-new in the wallet process, built from today's types.

---

## 9. The lift PR(s)

### 9.1 What lands, and the proof of no change

The lift has two validation surfaces, so **this round asks whether it is two
PRs** (rule 119). The recommendation is two:

- **L1: the node layer and the unmanaged split**, inside today's crates.
  - The relay, session, dial and path state leave the core for the daemon's
    node layer (§3.3).
  - `off` and `operator` run the node layer alone. `Drive::boot_for`,
    `SupervisorEnd::NoTorToRun` and `TorAsk` are deleted
    (`shekyl-daemon/src/tor/mod.rs:230–260, 875–881, 1111–1114, 1368`).
  - The proof is an **action trace**, not only `Status`. For `off`, `operator`
    and `managed`, a generated input stream (verdicts, sessions, tallies, path
    facts and wants, probe arrivals, deadlines) is fed to today's core and to
    L1's composition. The emitted host-visible effects must be equal, in
    order: `PathReading`, announcements, `SayProgress` and inbound publishes.
    So must `Status` and `hiding` after every input.
  - Under `off` and `operator`, the path reading still reaches the connector
    (§3.3).
- **L2: the move.** The driver moves into `shekyl-tor-supervisor` behind
  `InstanceHost`, together with `InstanceRoot`, `Said` and the fold of
  `-daemon`.
  - The proof is the moved tests passing unchanged: `loop_tests.rs`,
    `inbox/tests.rs`, and the unit tests of `guards.rs`, `probe.rs` and
    `requests.rs`.
  - The `Said` table test, the source gates (§5.1) and the two-instance test
    (§5.1) are new tests.

If Rick rules a single PR, L1 and L2 land as ordered commit ranges in it,
each range carrying its own proof.

### 9.2 Acceptance, as the brief sets it

- **The floor-device re-run, as on 2026-11-16.** A control node and a slow
  node, each with a second node of ours dialing its onion as the answer key.
  The mark is agreement between each node's own answer and the dialer's.
- **The pinned-Tor live tests pass on the Pi.**
- **Documents:**
  - `TOR_SUPERVISOR.md` §11.1: the principal is out, the topology of §1, the
    driver's crate, and the host;
  - the driver sections (§4, §5);
  - the index row;
  - `FOLLOWUPS`: the `TSR-W2` part removed;
  - a `changelog.d` fragment.

  `shekyl-tor-control-daemon/src/lib.rs:38–41` ("no vanguard `SETCONF` …
  vanguards stay the wallet's") went stale at `TSR-W1`. That text moves with
  the fold and is corrected there.

---

## 10. Wargames and the A3 pass

Attacker objectives:

- **O1:** link the persona's onion to the daemon's onion, or to the host;
- **O2:** a false "reachable", masking the unreachability that leads to a
  slash;
- **O3:** a false "unreachable", or making the persona's republishes visible;
- **O4:** use recognition as an oracle;
- **O5:** learn the persona from its logs or RPC (the `WSS-18` adversary);
- **O6:** leak state between instances.

| Wargame | Finding | Route |
| --- | --- | --- |
| **W1: the daemon and a persona process on one host** (it replaces the brief's principal case, Rick 2026-11-28). Roots, logs, timing | **`TSR-F19` roots.** The sweep crossing processes is closed by `InstanceRoot` (§5.2). **`TSR-F20` timing.** The shared triggers are listed below; one is enough to link | Roots: absorbed (§5.2). Logs: absorbed (§3.5, §5.4). Timing: see `TSR-F20` |
| **W2: a reader of the wallet's log or RPC links onions** (O5) | **`TSR-F21`.** The persona's onion never appears in a `Said`, a status, the alarm record or the RPC. Three surfaces need checking at `TSR-W3`: Tor's relayed lines, error `Display`s and kameo's id lines (§3.5, §5.1) | Absorbed: the `Said` design and the `WSS-20` gate. Forward action: `TSR-W3`'s `WSS-20` row and log-filter check |
| **W3: two personas on one schedule** | **`TSR-F22`.** Two wallet processes have two roots, two engines and two draw sources, so their probe delays are independent. They are still not separable from the shared triggers of `TSR-F20`. One persona per machine stays the recommendation (`tor_config.rs:40–50`) | Absorbed as a discipline note, already stated in code. No mechanism closes shared fate |
| **W4: a forged or replayed probe** (O2, O4) | **`TSR-F23`.** A forgery needs a live 256-bit nonce: 2⁻²⁵⁶ per guess per live slot. A replay finds an empty slot (§4.4). The comparison is constant time over fixed slots (§4.3). A miss falls through to the normal path, so an observer sees no probe-shaped oracle. Flooding the cap forces misses: the row reads a true "unreachable", and republishes follow on the hold (§4.6). There is no capacity reading beside it until `refused` is on an alarm (§7 item 9) | Absorbed. Capacity: forward action to `TSR-W3` (§7 item 9) |
| **W5: a hostile host** (O6). Publish before a pin, skip a probe, share an instance | **`TSR-F24` publish before a pin.** Forbidden by type. A persistent onion's publish takes `VanguardsActive` (`TSR-W1`), and a persona is always persistent. **`TSR-F25` skip a probe.** **Not** forbidden by type. A host whose `mint_probe` returns `None` while Tor runs keeps a stale verdict, which only its age shows. **`TSR-F26` share an instance.** Forbidden: the instance takes its host by value, is not `Clone`, and owns its root, whose OS lock refuses a second claim (§5.2) | F24 and F26: absorbed. F25: forward action to `TSR-W3`, through §7 item 8's `VERDICT_FRESH`. Past that bound the row is a live alarm with a new cause (`unchecked`, a wire addition) or a disarm, as Rick rules |

**`TSR-F20`: the shared triggers**, for a daemon and a persona on one host.
The probe draws are uniform over 15–60 s
(`core/mod.rs:140–175`: `probe_after_min = 15 s`, `PROBE_AFTER_MAX = 60 s`).

| Trigger | What both instances do | Against the draws |
| --- | --- | --- |
| Host boot | Both Tors bootstrap and publish within the same window. The daemon's onion is new; the persona's is republished | The draws place each probe within 15–60 s of its own round. They hide where in that window it falls, not that both followed the boot |
| Loss and return of the host's link | Both lose the network together. On recovery both re-upload, on Tor's own schedule, and probe after their rounds | As above |
| Resume from suspend | Both see a clock jump. Each draws its own jump probe (`probe.rs:186–191`) | As above. The shared moment is the jump |
| A wall-clock step | Both may judge the clock and hold republishes (`TSR-M14`) | As above |
| One process's restart | Only that instance acts | None. This one is separable |

Route: **absorbed as a stated residual** (shared fate). It is written into
§11.1 at the lift. The only answer is separate hosts or links, which the
operator chooses.

A per-instance random delay before the first publish after a shared trigger
would blur the window further. It would cost minutes of reachability on every
boot and resume. Against the epoch-scale challenge cadence that may be cheap,
but it is a new mechanism and a behaviour change, so it is **not proposed for
the lift**. It is offered to Rick as a `TSR-W3` question (`TSR-F27`).

---

## 11. Open questions (to Rick, in session)

None of these are in a PR body.

1. Whether the node layer, a second actor that owns no Tor state, satisfies
   ruling 2 (§3.3).
2. The persona's probe recognition after the cap, which departs from the
   brief's line (§4.2).
3. The daemon's root: (a) `<data-dir>/tor/`, or (b) the data directory (§5.2).
4. The lift as two PRs, L1 and L2, or one (§9.1).
5. For `TSR-W3`, three questions:
   - **`publishing` and a stale verdict past `VERDICT_FRESH`** (§7 item 8,
     `TSR-F25`): a live alarm with a new `unchecked` cause (a wire addition),
     or a disarm;
   - **`refused`** (§7 item 9): whether it joins `ServeHealth` or gets a row
     of its own;
   - **a delay after a shared trigger** (`TSR-F27`).
