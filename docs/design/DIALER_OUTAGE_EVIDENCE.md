# One judge of failed dials; each connector declares how its failures are judged

**Status: RULED (Round 0 closed 2026-10-31; `OE-D10` ruled 2026-11-01; its launch stamp, §6.1, ruled 2026-11-05). AMENDED 2026-11-15 (Rick): the judge is decoupled from every connector; one path reading taken after the failure decides, from the dialing connector, and the Tor connector's readings are the Tor Manager's (§3.3, [`TOR_SUPERVISOR.md`](TOR_SUPERVISOR.md) §4.5a); the quiet line reads the manager's own reading (§6).** Every decision is ruled (§0) and nothing in the mapping is open. The code is #1235 (§8), all seven steps built there as of 2026-11-02, not yet on dev. The brief is [`DIALER_OUTAGE_EVIDENCE_BRIEF.md`](DIALER_OUTAGE_EVIDENCE_BRIEF.md). This record states the design as ruled; the rounds that reached it are in git (revision 1 `4a570f834`, revision 2 `2f85829ef`, revision 3 `12737f3fbe`).

**Read at:** `dev` `f608d01604`; every anchor in §1 holds there.
**Reviews:** the Tor lane reviewed Tor's mapping (§3.2) against tor 0.4.9.14 and derived `OE-D10` (§6); Rick's reviewer covered clearnet's mapping (§3.1).
**Live runs** wait for the Pi, after the Tor soak's claim ends (about 2026-11-07 06:17Z).

The intent (Rick, 2026-10-31): each connector declares how its connections are tested and judged, as data, the way it already declares its escalation and backoff ladders. One judge in the dialer carries that out. The judge does not derive against a universal; it judges each connector by the stated characteristics of that network.

## 0. The decisions

| ID | Decision | Reason |
| --- | --- | --- |
| `OE-D1` | Three kinds of evidence: Destination, Local, Uncertain (§2.1) | One judge: a fourth kind, or a per-connector meaning, would give the judge a branch per connector |
| `OE-D2` | The judge takes its own type, `DialFailure { evidence, retry, reached }`; the D12 `CloseCause` travels beside it for the log, out of the judge's reach (§2.2) | Three independent facts get three typed fields, and misbehaviour can be built only where the connector authenticates the destination |
| `OE-D3` | Clearnet's mapping (§3.1); Local only for failures independent of the destination | A destination-dependent failure as Local is never counted: a node with no IPv6 route would excuse every IPv6 address forever |
| `OE-D4` | Tor's mapping (§3.2); nothing a gossiped address can cause is Local | Local is retried every 10–15 s and never climbs, so a planted onion able to produce one would be redialed forever |
| `OE-D5` | One path reading taken after the failure decides, asked of the dialing connector, which supplies its own source and its own wait (§3.3). *Amended 2026-11-15: the bracket's before side is dropped, and the evidence list moves to each connector* | The connector, not the judge, knows whether its path works; the judge names no connector |
| `OE-D6` | Hold the rung: an excused failure neither climbs nor descends; only an address with no counted failure takes `outage_retry`, and the next working reading clears those (§3.4) | No failure without a working reading ever counts, and excusal never undoes the ladder |
| `OE-D7` | Values per connector, each an `Assumption` with its own basis in `DAEMON_RELAY_PRIVACY.md` §97 (§3.5) | Equal numbers on two connectors are two derivations, each re-derived when its own basis moves |
| `OE-D8` | One function in the dialer, `judge`, returns a verdict; `Peerlist::apply` keeps only seat mechanics; a deferred verdict holds no target place and no in-flight slot (§4.1) | One point of judgment, and a pending verdict never idles a slot |
| `OE-D9` | The K/S quiet guard, its thresholds, the `Ladder` parameter and the close-cause marks are deleted (§5) | Rule 15: the judge replaces each |
| `OE-D10` | The quiet line stands only when the Tor Manager's reading is impaired, peers are known, and a Tor dial has failed since (§6). *Amended 2026-11-15* | The operator is told what the manager reads, the one owner of whether the onion path works |
| — | Retry follows each row's meaning: `Final` only for a definitive answer (another network's prefix, a message that does not verify, proven misbehaviour); Tor keeps its reply finality (§3) | A retry decided by what the failure says, not by where it was observed; Tor does Tor (`TSR-Q14`) |
| — | A banned address is never eligible to be drawn; bans and lifts arrive at the peer list as events (§3.1, §8) | A ban is this node's verdict, not a failure to judge |

## 1. Pre-flight: what the code holds at the pin

**The brief's anchors hold:** `Dialer::ladder` at `shekyl-dialer/src/owner/quiet.rs` line 67 at `821beb1215` (*records-was:* #1235 deleted the guard); `fail_test` at `shekyl-peerlist/src/partition.rs:454`; the marks at `shekyl-transport-layer/src/cause.rs` lines 143, 146, 149 and 156 at `7559d9f81a`; `proxy_reply_marks` at `shekyl-tor/src/replies.rs` line 89 at `821beb1215` (*records-was:* #1235 deleted both); `Peerlist::apply`'s misbehaviour test at `shekyl-peerlist/src/peerlist.rs:594`. The Pi run is shekyl-dev `8049fe7`, `data/tsr-acceptance/2026-10-31-pi-floor/`, and reads as §1 of the brief says.

**What the design rests on, found at the pin:**
- **Every finished attempt reaches the lists through one function**, `Dialer::record` (`owner/mod.rs:716-729`). It folds the attempt into the quiet counters, asks `ladder` once, and calls `Peerlist::apply`. Retries within a test are decided before it, in `settle_or_retry` (`owner/mod.rs:742-790`), from `RETRY` and `WINDOW_TIMEOUT`. The judge goes where `ladder` is.
- **"A stream opened" is already observable.** `reach::attempt_stream` (`reach.rs:48-63`) reads it from the close kind's phase (`CloseCause::opened_a_stream`, `cause.rs` lines 313–316 at `7559d9f81a`; *records-was:* #1235 reads `Reached` instead): any failure past `BeforeChannel`, and every success.
- **"A session received bytes" is observable but unread.** The transport stamps each session's last received byte (`node_gate().activity(conn)`, `shekyl-capped-stream/src/gate.rs:255`), keyed by the socket id the dialer already keeps (`channel.held().open.id()`, `owner/handshake.rs:142`). The C++ stall check reads it; the dialer does not. The stamp's clock is `monotonic_ms()` (`shekyl-transport-layer/src/clock.rs:21`), whose origin is not the engine clock's, so the judge compares stamps with `monotonic_ms()` read at the same instant, never with an engine `Tick`.
- **A session merely held proves nothing.** In the Pi's blackhole every idle session stayed open 2 min 10 s into the block before closing as `LocalClose`.
- **A white address has no cooling state.** `Ladder::FirstStep` on white changes nothing and leaves it drawable at once (`partition.rs:481-483`).
- **The failure count resets only on promotion** (`partition.rs:359-390`), and recovery never shortens a cooldown (`owner/recovery.rs:149`, `re_admit`: an address already seated keeps its cooldown).
- **Clearnet's stamping has catch-alls** (`shekyl-clearnet/src/drive.rs:292-309`, `handshake.rs:141-275`): a refused connect is `DialFailed`, every other connect error is `LocalClose`; `TransportHandshakeFailed` holds a peer's bad message 2, a mid-handshake EOF or reset, and our own engine, crypto or join failure.
- **`CloseCause::proxy_refused` masks marks** to `RETRY | NAMES_DESTINATION | WINDOW_TIMEOUT` (`cause.rs` lines 216–222 at `7559d9f81a`), and the C header mirrored the marks (`SHEKYL_CLOSE_MARK_*`, checked by a test; *records-was:* #1235 deleted the marks and the header's projection of them).
- **Healthy sessions talk every minute.** Each established connection gets a timed sync with a 60 s mean (`TIMED_SYNC_MIN` 45 s plus a uniform 30 s jitter, `rust/shekyl-p2p-session/src/timing.rs:32-38`, PWD-B2; the C++ it replaced ran `peer_sync_idle_maker` on `P2P_DEFAULT_HANDSHAKE_INTERVAL`, line 686 of `src/p2p/net_node.inl` at `e8838b0095`), from both ends: about two received messages a minute per session.

## 2. The vocabulary (`OE-D1`, `OE-D2`)

### 2.1 Three kinds, and what the judge does with each

| Evidence | What it says | What the judge does |
| --- | --- | --- |
| **Destination** | The far end answered, or is shown absent | Counts: the ladder steps and a white address is demoted. A Destination failure that also proves misbehaviour drops the address, on a connector that authenticates the destination |
| **Local** | This node's side failed, independent of the destination: the operator's proxy unavailable, this node's own request, engine or close | **Excused.** Never counts: no ladder step, no white demotion, the failure count untouched. An address with no counted failure cools for the connector's `outage_retry` (§3.5); an address with counted failures cools at its current rung (§3.4) |
| **Uncertain** | The link or the destination: a timeout, an unreachable reply from the path, a failure that depends on the destination's address family or route | Counts only on a working reading of the connector's path taken after it (§3.3). Otherwise excused, as Local |

The vocabulary belongs to the dialer. A connector that needs a meaning outside it is a design round, not a new local rule.

### 2.2 The judge's own type

```rust
struct DialFailure { evidence: Evidence, retry: Retry, reached: Reached }
enum Evidence { Destination(Proof), Local, Uncertain }
struct Proof(ProofKind);              // opaque: read through kind()
enum ProofKind { Absent, Misbehaviour }
enum Retry { Final, Again, AgainInsideWindow }
enum Reached { NoStream, StreamOpened }

struct DialEnd { failure: DialFailure, cause: CloseCause }
enum StreamEnd { PeerClosed, IoError, SendQueueFull }
```

- **Misbehaviour** is built only by `DialFailure::refused_by_peer(connector, reached)`, which reads the connector's `destination_authenticated` declaration and is always `Final`. On a connector that does not authenticate the destination it cannot return it, so clearnet can never prove misbehaviour by type.
- **`DialEnd` carries the D12 `CloseCause` beside the failure, for the log.** The judge's signature takes a `DialFailure` and the connector's declaration; it cannot see the cause.
- **Who builds it:**
  - **the connector:** every failure before the channel, and every end of its own stream after it. Shared code that observes a stream's end hands the `StreamEnd` to the connector to stamp (`stamp_stream_end`); no connector-independent code assigns a meaning;
  - **the Levin layer:** a rejected handshake, a wrong network or a refused peer list through `refused_by_peer`; a Levin handshake timeout is `Uncertain`;
  - **the dialer and the hub:** `Local` for their own failures (the socket table exhausted, `OpenError::Exhausted`; a session refused; their own close, `DialEnd::local_close()`).
- **Inbound refusals** never build a `DialFailure`, so the accept-only kinds (`InboundNotAccepted`, `AcceptRateExceeded`) need nothing.
- **No persisted state changes.** The address file keeps addresses, not seats, so rule 42 is not touched.

## 3. What each connector declares

As data, in a `FailureJudging` declaration on each connector's `DialProfile` row in `shekyl-transport-layer/src/profile.rs`, one `const fn` row per connector (rule 71: data, never control flow):
1. **The mapping:** carried by the connector's own stamping into `DialFailure` (§2.2, §3.1, §3.2); the declaration holds nothing extra, so there is one source.
2. **Its source of path readings** and the longest the judge waits for one (§3.3).
3. **Its `destination_authenticated` flag:** whether the destination is authenticated, which is the only thing that lets misbehaviour be built (§2.2).
4. **Its values:** the reading wait and `outage_retry` (§3.5), beside the ladder, retries, waits and window the profile already holds.

**Retry follows each row's meaning.** `Final` only for a definitive answer: another network's prefix, a message that does not verify, proven misbehaviour. A timeout or an uncertain answer within the window is `AgainInsideWindow`; the rest is `Again`. Tor keeps its own reply finality: Tor does Tor (`TSR-Q14`, ruled 2026-10-25), and the full-window rule (Rick, 2026-10-26) makes a reply Tor does not retry `Final`.

### 3.1 Clearnet's mapping (`OE-D3` — RULED; built in #1235)

| What happened (where) | At the pin | Evidence |
| --- | --- | --- |
| Connect refused, direct (`drive.rs:292-309`) | `DialFailed`, `RETRY` | Destination |
| Connect reset, direct | `LocalClose` (catch-all) | Destination |
| Connect timed out by the kernel; host unreachable (ICMP from a router on the path) | `LocalClose` | Uncertain |
| Network unreachable, address not available, permission denied | `LocalClose` | Uncertain: each depends on the destination's address family or route |
| Any other connect error | `LocalClose` | Uncertain |
| Any connect error through the operator's SOCKS proxy (this node's proxy) | `LocalClose` | Local |
| The dial deadline, 1.415 s (`drive.rs:333-343`) | `TransportTimeout`, `RETRY \| WINDOW_TIMEOUT` | Uncertain |
| A socket-table or engine failure | `LocalClose` | Local |
| SOCKS reply through the operator's proxy: `0x05` | final, no marks | Destination |
| SOCKS reply `0x07` (command not supported); SOCKS I/O, malformed or authentication failure | final / `ProxyUnavailable` | Local |
| SOCKS reply `0x02` (refused by the proxy's rules), `0x08` (address type not supported) | final, no marks | Uncertain: both depend on the destination; `0x08` is the IPv6 case arriving through a proxy |
| Any other SOCKS reply | final, no marks | Uncertain |
| Handshake: the peer's message 2 does not verify; the prefix is another network's (`PrefixMismatch`) | `TransportHandshakeFailed` / `PrefixMismatch` | Destination |
| Handshake: EOF or reset from the peer mid-handshake | `TransportHandshakeFailed` (catch-all) | Destination |
| Handshake: our engine, crypto job or join failed | `TransportHandshakeFailed` | Local |
| Handshake deadline | `TransportTimeout` | Uncertain |
| After the channel: the Levin handshake times out; an I/O error | `LevinHandshakeTimeout` / `IoError` | Uncertain |
| After the channel: the peer closes; a record does not open; the Levin handshake or peer list is refused | `PeerClosed` / `RecordRejected` / `LevinHandshakeRejected` | Destination (clearnet never proves misbehaviour) |

A reset or a bad record can be forged by an on-path party. On clearnet that party already decides which peers this node reaches; counting what it forges records what it already enforces (the permanent clearnet residual: clearnet can encrypt and recognize, never authenticate).

**On Windows a direct dial's socket caps its SYN retransmissions at one** (`SIO_TCP_INITIAL_RTO`, `shekyl-win-sec`'s `cap_syn_retransmissions`). By default Windows retries a refused connect, a SYN 0.5 s after each reset, and reports the refusal after about 2.0 s, past the 1.415 s direct deadline, so a refusing peer ended on the deadline row (Uncertain) instead of the refusal row (Destination). A dial to the operator's proxy runs against the proxied deadline, the Tor dial's 120 s, which the default retries fit inside, so a refused proxy port was always judged Local and its socket keeps the system's retries. The cap governs both kinds of retry, one to one. At one, a refusal is reported in about 0.5 s, and a lost SYN is still resent once at +1.0 s, as Linux does, before the connect gives up at +3 s, after the deadline. Measured on Windows 11, loopback and a remote host's reset alike (shekyl-dev, `data/windows-refused-connect/`, 2026-11-03).

**The principle:** Local is only for failures independent of the destination. A failure that depends on the destination's address family or route is Uncertain: corroboration counts it when another path works (IPv4, here) and excuses it in a total outage.

**A banned address is not in the mapping.** It is never eligible to be drawn: the ban list posts each ban and lift as an event to the peer list, which bars every seat an active entry covers. Clearnet checks the ban at admission before the connect, and a refusal there is the dial contract's "refused here" result, which moves no ladder.

### 3.2 Tor's mapping (`OE-D4` — RULED; reviewed by the Tor lane against tor 0.4.9.14; built in #1235)

| What happened (where) | At the pin | Evidence |
| --- | --- | --- |
| The SOCKS port refuses or errors; authentication; malformed reply (`shekyl-tor/src/drive.rs:255-294`) | `ProxyUnavailable` / `LocalClose` | Local |
| Reply `0x05` (the service's own answer: refused, reset, or DONE for a port it does not offer); `0xF1` (descriptor unusable); `0xF4`, `0xF5` (client authorization, demanded by the onion's own descriptor, `hs_client.c:1636-1650`); `0xF6` (Tor could not parse the onion name, `connection_edge.c:2192-2198`; validated before the dial, so in practice it never arrives) | final, `NAMES_DESTINATION` for `0x05`, `0xF1` | Destination |
| Reply `0x01` (general failure: Tor sends it for many endings, `reasons.c:109-155`; a circuit destroyed after the stream joins it comes back as a plain `0x01`, `connection_edge.c:400-411`) | final, `NAMES_DESTINATION` | Uncertain. As Destination, a hostile guard destroying each rendezvous circuit, or this node's own guard link dropping at an outage's start, would be counted without corroboration |
| Reply `0x02` (this node's own Tor policy, `connection_edge.c:1685` onward; a service sends DONE for an unoffered port, `:4096-4103`) | final, no marks | Uncertain. Under the managed Tor it never arrives; under an operator's own Tor with a port policy (`RejectPlaintextPorts`, a supported posture) it depends on the gossiped port, and Uncertain counts it once the link is shown working, so the address climbs |
| Reply `0x03` (network unreachable: only when Tor decides every directory server is unreachable and fails the waiting streams, `DIR_ALL_UNREACHABLE`, `mainloop.c:1095-1107`); `0x07`, `0x08` (Tor rejected the shape of this node's own SOCKS request, `proto_socks.c:615`, `:653`; the connector only ever sends a v3 onion hostname) | `0x03` `RETRY \| WINDOW_TIMEOUT`; the rest final, no marks | Local |
| Reply `0x04` (with extended errors on, only the service's own connect failing), `0x06`, `0xF0`, `0xF2`, `0xF3`, `0xF7` | `RETRY \| WINDOW_TIMEOUT`, some `NAMES_DESTINATION` | Uncertain |
| Any other reply | final, no marks | Uncertain |
| The dial deadline, 120 s | `TransportTimeout`, `RETRY \| WINDOW_TIMEOUT` | Uncertain |
| A local engine, socket-table or check failure | `LocalClose` | Local |
| After the stream opened: the Levin handshake times out; the peer closes; an I/O error | `RETRY` | Uncertain. A circuit that collapses with this node's link looks the same as an onion that hangs up |
| After the stream opened: the Levin handshake or peer list is refused | `NAMES_DESTINATION \| PROVES_MISBEHAVIOUR` | Destination, and it drops |

**The rule for Tor (the Tor lane, 2026-10-31):** nothing a gossiped address can cause may be Local. Local is retried every 10–15 s and never climbs, so a planted onion that could produce a Local reply would be redialed forever.

### 3.3 The path reading (`OE-D5` — RULED; amended 2026-11-15)

**One reading taken after the failure decides.** For an Uncertain failure
the judge asks the dialing connector for a reading of its path taken after
the failure (`PathSource::reading_after`, `rust/shekyl-transport-layer/src/path.rs`):
- **Working:** the failure counts against the address.
- **Impaired, or no reading within the connector's declared wait:** the
  failure is excused.
- While it waits, the address is not drawn again, and the verdict holds no
  in-flight slot (§4.1).

The judge knows nothing about bytes, stream opens, probes or checks, and
names no connector (`rust/shekyl-dialer/src/judge.rs`); a new connector
supplies its own source, with no judge change. `shekyl-dialer` depends on no
Tor crate, held by `scripts/ci/check_dialer_no_tor.sh`. A short outage the
judge misses is not a defect: the dialer keeps peer slots filled, and an
outage matters only when it stops the node finding peers.

**Each connector's source** (`rust/shekyl-p2p/src/path.rs`):
- **Tor: the Tor Manager** ([`TOR_SUPERVISOR.md`](TOR_SUPERVISOR.md) §4.5a).
  Working, from a check in which the probe came back and the directory
  check passed, an outbound onion dial that completed, or a new inbound Tor
  session. Impaired, from Tor's own statements that it cannot reach its
  network or that no directory answers, or a failed check (the two-miss
  verdict). Never from a failed peer dial, a byte on a held session, or a
  session merely held. A failure with no reading after it is posted to the
  manager once; the manager answers from a later fact or runs its check, at
  most one per 15 minutes. Declared wait: the spacing plus one check, 19
  minutes. Under an operator's Tor there is no check, and readings come only
  from completed dials and new inbound sessions.
- **Clearnet: its own outbound sessions.** A byte received on an outbound
  clearnet session after the failure is a working reading. The byte's stamp
  is `monotonic_ms`, which is not the process clock: on Windows `Instant`
  counts through S3 sleep and the process clock does not. The source marks
  `monotonic_ms` at the first ask and counts a byte strictly after that
  mark, never by subtracting the two clocks. Inbound sessions do not count:
  a censor can block this node's outbound connects while established inbound
  flows continue, and inbound peers choose this node, not the reverse.
  Declared wait: 15 s (§3.5). An on-path party who passes only its own
  session still counts: it must be a peer this node chose, and must keep
  that session talking after each failure (§7).

### 3.4 The excusal and the clearing rule (`OE-D6` — RULED: hold the rung; clearing is the judge's)

**The rule:**
- An excused failure neither climbs nor descends the ladder.
- An address already on the ladder (it has counted failures) cools at its current rung.
- Only an address with no counted failure, which includes every live white address, takes the connector's short `outage_retry`.
- **Clearing is the judge's behaviour:** the first working reading on a connector lifts the excused cooldowns of addresses with no counted failure. Nothing on the ladder is touched.

No failure without a working reading ever counts, so invariants 1, 2 and 7 hold exactly. What is left is the first failure of each new dead address while sessions are scarce, which can be excused and retried more than once before it counts: a stated residual, bounded by `outage_retry`.

**The model** (shekyl-dev `data/dialer-outage/2026-10-31-oe-d6-fill-model/`, `fill_model.py`; every input is stated there, none measured):
- **Clearnet as the profile has it:** bound 1, target 12, deadline 1.415 s, wake 0.5 s + U(1 s), the ladder 120 s doubling to 1 h with U(50 %) jitter. The gray list starts full and white starts empty, as after a restart.
- **Addresses:** live addresses succeed and dead ones time out.
- **Sessions:** each outbound session receives about two messages a minute (§3.5) and lasts an exponential 30 minutes.
- **A blackhole:** stops all bytes and closes idle sessions 130 s in, as on the Pi.
- **Runs:** 200 seeds a cell for fill and decay, 100 for outages, two hours each. "At the pin" is the K/S guard the design deletes.

**Fill from zero sessions** (medians; seconds to the target, p90 in brackets):

| Gray list, planted dead | At the pin (the K/S guard) | Hold the rung |
| --- | --- | --- |
| 1,000, 50 % | 42 (60) | 41 (57) |
| 1,000, 90 % | 277 (399) | 259 (373) |
| 5,000, 50 % | 42 (61) | 41 (56) |
| 5,000, 90 % | 269 (382) | 241 (348) |

At these sizes decay does not matter: each dead address is dialed about once during the fill. Hold the rung fills no slower than the guard, and counts 83–95 % of the dead addresses it dials; the rest are excused and redialed.

**Where decay matters: few live addresses, so few sessions, held for hours** (dials in the second hour):

| Live addresses (sessions held) | At the pin | Hold the rung |
| --- | --- | --- |
| 5 of 50 (5) | 55 | 63 (mean 5.9 failures) |
| 2 of 100 (2) | 102 | 256 (mean 4.9 failures) |
| 0 of 100 (none: an outage, as far as the node can tell) | 1,490 | 1,757 |

- **Decay does happen:** dead addresses climb toward the ladder's cap (a mean of 6 failures) in every regime, because once sessions exist they corroborate most failures.
- **What it costs is dials:** with two sessions many failures miss the bracket (§3.5's table), and each excusal of an address with no counted failure costs a redial after `outage_retry`.
- **With no live address at all,** the dialer dials at the bound's ceiling, as the guard did.

**Outages** (two blackholes in a row, 20 live addresses, 10 % of live dials failing at random; white addresses demoted across both outages, median, p90 in brackets):

| Blackhole length | At the pin | Hold the rung |
| --- | --- | --- |
| 60 s | 1 (2) | 0 (0) |
| 120 s | 2 (4) | 1 (2) |
| 180 s | 12 (20) | 2 (4) |
| 600 s | 12 (20) | 2 (4) |

Hold the rung's 1–2 are ordinary random failures in the δ right after each blackhole ends, which the measure's window includes; it counts no failure made during an outage. Recovery after each blackhole is 1–12 s (the Pi's 2 min 44 s at the pin came from a six-address white list all cooling at the first rung).

### 3.5 Values (`OE-D7` — RULED: per connector)

Each value is the connector's own, an `Assumption` with its basis in `DAEMON_RELAY_PRIVACY.md` §97. Not modelled; the Pi measures (brief §7).

| Value | Tor | Clearnet |
| --- | --- | --- |
| The reading wait | 19 minutes: the on-demand check spacing (15 min) plus one check (240 s), `READING_WAIT` ([`TOR_SUPERVISOR.md`](TOR_SUPERVISOR.md) §4.5a) | 15 s, `CLEARNET_READING_WAIT_NANOS` |
| `outage_retry` | 10 s + U(5 s) | 10 s + U(5 s) |
| **Basis of `outage_retry`** | Stays under the slot turnover, `window / bound` (105 s / 5 = 21 s): an excused address is drawable again before a slot comes free, so the outage cooldown never holds a slot idle | Caps redials of an unproven address: with bound 1 and a 1.415 s deadline, at most one redial of such an address per 10–15 s |
| **Basis of the wait** | A failure just after a check began waits out the spacing, then one check; with no reading by then the manager could not answer | The 60 s mean timed-sync interval (`TIMED_SYNC_MIN` plus half `TIMED_SYNC_JITTER`, `shekyl-p2p-session` `timing.rs`), on outbound sessions only (inbound is excluded from clearnet's source) |
| Ladder, retries, waits, window, target, in-flight bound | unchanged | unchanged |

Equal numbers on the two rows are two derivations landing on one value, not one value shared: each row's basis is its own, and each re-derives when its basis moves (the check's spacing and bounds for Tor's wait; the timed-sync interval for clearnet's; Tor's window or bound for Tor's `outage_retry`; clearnet's deadline or bound for clearnet's).

**Why clearnet's wait is 15 s.** An outbound session receives about two messages a minute (§1). **Arrival model (an assumption, not a measurement):** bytes arrive on each outbound session as an independent Poisson process at that rate, so with `n` outbound sessions the chance that the 15 s after a failure shows nothing is `p = exp(−n · 15 s / 30 s)`.

| Outbound sessions | 1 | 2 | 3 | 6 | 12 (target) |
| --- | --- | --- | --- | --- | --- |
| A healthy link's Uncertain failure excused anyway | 61 % | 37 % | 22 % | 5.0 % | 0.25 % |

At target nothing changes, except that the verdict on an Uncertain failure waits for its reading. During fill, or at boot with no session, an Uncertain failure on a dead address is often excused; each excusal of an address with no counted failure costs a redial after `outage_retry`, so the cost is redials, not a lost address. A Destination failure always counts.

**Registered before the Pi run (Rick, 2026-11-15).** With half of a 100-address gray list dead, a settled node that loses one Tor slot refills it in a median of 4.2 s; the registered band is 0.6 s to 55.6 s, the model's 5th to 95th percentile, and a floor-device refill outside it is a finding. At most one check runs during a refill: the completed dial is itself a working fact. The model and every input it states are shekyl-dev `data/dialer-outage/2026-11-15-onion-path-refill/`.

**Recovery (invariant 3).**
- **At the pin:** the first rung is 120–180 s. The Pi recovered 2 min 44 s after the unblock, against 6 s in the refuse block.
- **Clearnet:** `outage_retry` bounds the cooldown that starts at an excused verdict, not the time from the unblock. A failure just before the unblock holds its seat outstanding for its waiting verdict, up to the wait (15 s, §4.1), and only then cools for up to 15 s; and the redial needs that address to be the one drawn, or another eligible candidate to exist. So the first redial of a given excused address is at most about δ + 15 s (≈ 30 s) after the unblock, plus one dial, and its success clears every excused cooldown of an address with no counted failure; addresses with counted failures keep their rung (§3.4). This is the design's bound; the Pi measures it (brief §7).
- **Tor:** the first redial after an unblock waits for a slot, and in-flight attempts are left to run (`TSR-Q14`: Tor retries inside its own window), so the bound above does not hold there. The time from unblock to the first stream open is a Pi measurement (brief §7).

## 4. The judge (`OE-D8` — RULED)

### 4.1 One function, and the peer list keeps seat mechanics

- **The judge.** `judge(failure) -> Judgement` and `settle(reading, waited_out)` in `shekyl-dialer` (`judge.rs`) take the place of `Dialer::ladder` in `record`. They read the failure's evidence and, for an Uncertain one, the dialing connector's path reading after it (§3.3), nothing else.
- **The verdict.** `Verdict` is `Counted`, `Excused` or `Drop`. `Peerlist::apply` takes a verdict and performs it: `fail_test` for `Counted`, a new `excuse` for `Excused`, `drop_tested` for `Drop`. It makes no decision of its own. That replaces the `Ladder` parameter, so the 58 `Ladder::Climb` call sites change mechanically.
- **Seat changes in the peer list:**
  - A gray seat's cooling phase records whether it was excused.
  - A white seat gains an optional excused-until instant, because white has no cooling state. Without one, an excused white address would be redrawn at once, in a tight loop on clearnet.
- **The deferred verdict** holds **no target place and no in-flight slot; only the seat stays outstanding.**
  - The attempt's in-flight slot frees when the attempt completes.
  - The pending verdict is not a kept session or a pending `Keep`, so the fill's count toward the target never includes it. The dialer draws and dials while verdicts wait.
  - The address is not drawn again meanwhile. A gray address's seat stays `Outstanding` until the verdict. A white address has no outstanding state (a re-contact is not a draw), so the dialer's eligibility excludes every address whose verdict waits; the onset test fails without it (#1235).
  - The connector's owner loop arms its wake for the earliest pending deadline, and a reading rings its bell. Tor's five slots are never held idle for the wait.
  - The reading must be taken after the failure's own instant, the attempt's end on the process clock; the wait in the completion queue is not part of it. With none by the wait the failure is excused, so a verdict performed late can err only toward excusing.
  - A Destination failure needs no wait and is applied at once.
- **Each connector's tally** (`LinkTally`: its census, and the latest launch among its failed dials) is published per connector under connector-neutral names; the daemon wires the Tor connector's copy to the Tor Manager, for the quiet line (§6).

### 4.2 What the judge guarantees, for every connector

Each is tested against every connector's declaration, over a simulated timeline, not promised per connector:
1. **An outage never empties white:** a failure no working reading backs never demotes white.
2. **An outage never climbs the ladder.**
3. **Recovery doesn't wait on outage cooldowns:** the first working reading clears the excused cooldowns of addresses with no counted failure (§3.5's arithmetic).
4. **Proven misbehaviour still drops,** on a destination-authenticated connector.
5. **The probe alone is no reading:** a check needs its directory check to pass as well, and the probe's own arrival is never a new inbound session.
6. **The judge names no connector:** it reads only the dialing connector's reading. The Tor connector's is the Tor Manager's, which reads Tor's own statements and its check and infers nothing from this node's traffic (`TSR-Q14`, restated 2026-11-15); the quiet line reads the manager's own reading (§6).
7. **An impaired path demotes nothing:** tests whose reading after them is impaired, or that get none within the wait, are all excused.

## 5. Deletions (`OE-D9` — RULED, rule 15)

From the census at the pin, each in the #1235 commit that removes it (§8). Historical ledger rows stay; they are a record. Each deleted test names the rule it tested and where that rule is now covered.
- **The ban query path** (with the ban transport half): `BanQuery`, `BanSnapshot`, `Skip::Banned`, `pre_dial_check`, the `demote_banned` scan, the per-wake snapshot, and the `&mut NoBans` argument at its call sites (about 190); in `shekyl-transport-layer/src/ban.rs`, the lazy expiry in `is_banned`, `hosts()` and `subnets()`, and `is_banned`'s `now`. The ban list's timer is the only expiry.
- **The ladder parameter** (commit 4): `Ladder` in `shekyl-peerlist` (`lib.rs:153-170`), replaced by the verdict (§4.1), with the `FirstStep` halves of `door.rs:627` and `lifecycle.rs:261`.
- **The guard** (commit 5, `shekyl-dialer`):
  - `src/owner/quiet.rs`, all of it;
  - `Shared::unopened` and `Shared::last_opened` (`owner/mod.rs:139-144`, `:278-279`), and both `note_attempt` calls (`:723`, `:781`);
  - `reach::QuietEvidence` and `quiet_evidence` (`reach.rs:37-45`, `:70-80`);
  - tests: nine in `shekyl-dialer/tests/attempts/quiet.rs`, two in `white.rs`, and `a_local_close_counts_for_the_quiet_guard_and_not_the_tally` (`reach.rs`), rewritten as the judge's tests.
  - **Stays:** `Shared::inbound` and `attempt_stream`, which the Tor tally reads.
- **The marks** (commit 6): `Marks` and the marks byte in the Rust `CloseCause`; `proxy_refused`'s marks argument; `proving_misbehaviour_on`, `retry_worthy`, `window_timeout`, `proves_misbehaviour`, `names_the_destination` and `opened_a_stream`; Tor's `proxy_reply_marks`, replaced by Tor's stamping. The generated `close_cause.h` is regenerated from `c_header()`, with no hand edit to any C or C++ file. The supervisor's Tor dial tally moves from `opened_a_stream` to `Reached::StreamOpened`, still excluding the probe, with a test.
- **The held condition** (commit 5b): the held condition in `Dials::evaluate`; the posture line reads the judge's instant instead (§6).
- **The thresholds, whole** (commit 7): in `shekyl-transport-layer/src/profile.rs`, clearnet's K (11) and Tor's K (13), `QuietThreshold`, `derive`, `quiet()`, the build-time span check and `the_quiet_span_is_derived_from_the_row`, and `the_profile_table_moves_todays_values` loses its K pin; the daemon's `policy()` reading of S (`shekyl-daemon/src/tor/mod.rs:60-71`) and `the_posture_lines_quiet_stretch_is_the_dialers` (`:1077`). After commit 5b nothing reads S, so this deletes it outright. **Nothing of the guard survives #1235.**
- **Docs that state the guard, K or S** (commit 7): `DAEMON_RELAY_PRIVACY.md` §97 (the gray-cooldown row's quiet threshold, and the in-flight row's quiet stretch); `P2P_3_SLICE_3_DIALER_BRIEF.md` (the quiet-stretch paragraph and its wargame); `P2P_3_SLICE_1_PEERLIST_BRIEF.md` (four lines); `NOISE_FLIP_REHEARSAL_BRIEF.md`'s K and S follow-up (C4); `docs/benchmarks/p2p_tor_inflight_bound_20261025.md`; the Unreleased CHANGELOG lines.
- **The measurement ledger:** editing `profile.rs` needs new acknowledgements on the clearnet and Tor span path sets. No constant's needle points at `profile.rs`.
- **No CI gate** names the guard, K, S or `quiet_after`.

## 6. The quiet line (`OE-D10` — RULED; amended 2026-11-15: the manager's reading)

The quiet line is one neutral posture sentence of the Tor supervisor (`shekyl-tor-control-client/src/supervisor/core/dials.rs`). It is display only, never a cause (`TSR-Q14`).

- **When it stands:** only when the Tor Manager's own onion-path reading is impaired ([`TOR_SUPERVISOR.md`](TOR_SUPERVISOR.md) §4.5a), peers are known (the census holds a non-empty run), and a Tor dial launched at or after the later of that reading and the run's start has failed (§6.1). A reading from before this Tor reached Running, or before a wake, does not stand it. It is said once when it begins, and only while no cause is named: Tor's own statements name their cause instead (Rick, 2026-11-15).
- **The line:** "Peers are known, but Tor has not been able to reach them for X.", X the time since the impaired reading, taken at the ask. No fix is offered. No line stands while no peer is known: there is nothing to dial, so no dial fails.
- **Its inputs:** the manager's reading, which it holds itself; and, from the dialer, the Tor connector's copy of its per-connector tally (`LinkTally`): the census (`LinkCensus`: pending until the first Tor wake, empty when no address is held, or the seat count and the time the run began; every wake that plans publishes it, a retry's included) and `failed_attempt_began`. The dialer's last sign of life is deleted (rule 15): the dialer no longer works out whether the path works.
- **The status field** is `tor_quiet`: `null`, or `{"unreached": {"age": s}}`. The keys `empty` and `failing` are gone; `impaired` already names Tor's own degraded state, so the line takes `unreached` ([`INPUT_GRAMMAR.md`](INPUT_GRAMMAR.md) IG-Q99, amended).

### 6.1 The launch stamp, `attempt_began`: one field both rules read (Rick, 2026-11-05)

A Tor dial launched before the quiet stretch began can fail inside it: a respawn's new Running, or a wake, starts the stretch while dials sent to the old Tor are still running out their window. Dating that failure by when it was counted (`last_unopened_at`, above) lets it stand the line on a link that has not been tested since the stretch began.
- **The rule:** only failures are filtered, never successes. A failure counts toward the line only if its attempt began at or after the stretch started. A stream that opens counts whenever it arrives, however old its dial.
- **No incarnation.** Leaving the link's incarnation out of the rule is rule 21: the launch time already separates a dial sent to the old Tor from one sent to the new, and adding the incarnation would provision for a case the launch time covers.
- **The field:** `attempt_began`, the instant the dialer launched the attempt (today the `started` stamp in `timed`, `shekyl-dialer/src/owner/flight.rs`). It is named once, here, for both rules:
  - the supervisor's line asks whether a failed dial began at or after the impaired reading;
  - the judge dates a failure at its attempt's end, and asks the connector for a reading after it (§3.3).
- **The tally carries** the latest `attempt_began` among failed Tor dials. The line stands only if that is at or after the stretch's start. It replaces `last_unopened_at`, which is deleted (rule 15).
- **One clock, enforced by type.** The dialer's stamp and the supervisor's stretch start both come from the process timing engine. They are a type only that engine's clock can mint, so the compiler checks that two instants are comparable, not a convention. The type lives in `shekyl-timing-engine`, and every `MonotonicClock` in the process reads one origin (a process-wide `OnceLock` of the platform reading), so a stamp from any production clock compares with one from any other, however each owner came by its clock. The type is minted only by those clocks, and the shared origin makes any two of them one timeline (`a_stamp_from_a_later_clock_is_never_earlier_than_one_taken_before_it`). The process clock leaves a suspend out where that clock does (`P2P_TIMING_ENGINE.md` §8), and a wake restarts the stretch either way.
- **Tests,** each naming the edit that makes it fail:
  - a failure launched before a respawn's Running raises nothing;
  - a failure launched before a wake raises nothing;
  - a failure launched after the stretch began still counts;
  - an old dial's success still counts.
- **Where it is built:** the Tor lane's PR after #1272 (`feat/tor-doorbell-wait`), with `TorLinkTally::held` deleted and the supervisor's wait restructured.
  - **The type** is `shekyl_timing_engine::Stamp`, minted only by `Clock::stamp`. `Clock` is sealed to the engine's two clocks, so no number converts into one. The type ends at the supervisor's core, which is sans-IO and reads every instant as nanoseconds from the one clock its driver is given: the daemon converts the tally's stamps there, in one function (`dial_tally`).
  - **The stamp** is taken once, where the dialer times the attempt (`AttemptTimes::began`, `shekyl-dialer/src/owner/flight.rs` `timed`), and every failed Tor attempt carries it to the tally, a retried one included. A local failure before any I/O began and ended at once.
  - **The tally** carries `failed_attempt_began` (the latest launch among failed dials), a stamp. `last_unopened_at` is deleted, and so, on 2026-11-15, is `last_sign_of_life` (§6).
  - **The supervisor's line** reads it (`Dials::evaluate`); the four tests above are `shekyl-tor-control-client/src/supervisor/core/tests/quiet.rs`.
  - **The judge's reading** ("did a stream open after an attempt began") is the dialer lane's; it has no rule text or test list here yet. The field is in place for it.

## 7. Wargame (§5 of the brief)

- **A total blackhole of the access link, both connectors.** No reading is working: on clearnet no byte arrives; on Tor, Tor says it cannot reach its network, or the manager's check fails, or no answer comes within the wait. White stays and nothing climbs. An excused address with no counted failure becomes eligible again after 10–15 s; one with counted failures holds its rung. Eligible only means drawable when a slot is free: the in-flight bound, and on Tor the attempts still running (left to run, `TSR-Q14`), decide when it is dialed. At the unblock the first working reading clears the excused cooldowns of addresses with no counted failure.
- **The same blackhole, with five Tor tests in flight at its onset.** Each gets an impaired reading, or none within the wait, so all five are excused.
- **Clearnet, an on-path party who passes only its own session.** Its session is outbound and talks, so it is a working reading, and honest addresses that time out are judged and demoted.
  - That party already decides which peers this node reaches. Demoting them records what it enforces: the permanent clearnet residual.
  - Excluding inbound makes it be a peer this node drew. Requiring bytes makes it keep that session talking around each failure, which is cheap for it. The design does not claim more than that.
- **Tor, an attacker who keeps one session open, or dials in.** A held session's bytes are no reading on Tor. A peer that dials in makes a new inbound Tor session, a working fact, at the cost of a full onion connection and handshake for each; that counts this node's failed dials during an outage of the onion path a peer can still dial through. It is narrower than before 2026-11-15, when any byte on any held Tor session counted ([`TOR_SUPERVISOR.md`](TOR_SUPERVISOR.md) §4.5a).
- **Many dead onion addresses gossiped to a settled node.** Each failure posts one want to the Tor Manager. The check runs at most once per 15 minutes however many dials fail. Judged when it ends, its working verdict is after every failure already waiting and answers each of them, so a dead onion is counted on its first verdict and climbs the ladder. A fact dated between two failures answers only the earlier, and the later one keeps its want. Between checks, a completed dial or a new inbound session answers the failures before it.
- **Clearnet fill from zero sessions, 50 % and 90 % planted dead (§3.4's numbers).** The fill takes as long as the guard's or less: 41 s and 241–259 s against 42 s and 269–277 s (medians). Decay does not matter at these sizes, since each dead address is dialed about once. Where it does matter (two live addresses, so two sessions, for hours), holding the rung keeps excusal from undoing the ladder: 256 dials an hour, against 102 under the guard.
- **A dead-onion flood while the node is isolated.** Every failure is excused, so dead addresses cool for 10–15 s and never climb. The draw stays uniform over drawable seats, so honest addresses keep their turn. The first working reading clears the excusals. From then on dead onions fail with a working reading after them and climb.
- **A slow link (the 40 kbit case).** Streams open late but do open, and outbound sessions receive slowly but do receive: on Tor a completed dial is a working fact, and on clearnet a received byte is, so a slow link is never taken for an outage. A live onion that misses the 105 s window on a slow link, while another stream opens, is counted.
- **A healthy clearnet link.** At target (12 outbound sessions) an Uncertain failure is excused in about 0.25 % of cases under §3.5's arrival model, and judged otherwise, within the 15 s wait. During fill the excusal rate follows §3.5's table; an excused dead address costs a redial per excusal. Destination failures, the refusals, count at once.

## 8. The code (#1235)

One PR off `dev`, by the dialer lane, [#1235](https://github.com/Shekyl-Foundation/shekyl-core/pull/1235), pushed a commit at a time:
1. **The judge's type and each connector's judging row** (`shekyl-transport-layer`): `DialFailure` and its enums (§2.2), `FailureJudging` on each `DialProfile` row with its values and bases (§3.5).
2. **The connectors stamp `DialFailure`.**
   - **2a, the declarations:** `DialEnd` and `StreamEnd`; clearnet's `Observed` and `stamp_stream_end` (§3.1); Tor's `stamp_reply`, `Observed` and `stamp_stream_end` (§3.2). Pure tables, every row pinned.
   - **Bans as events.** The peer-list half: a covered seat is barred on both lists, a lift re-checks against the remaining entries, and the door refuses a covered address. The transport half: one timing owner per ban list holds the earliest expiry, ordered by deadline and re-keyed when a ban is extended, a permanent ban never in it; events go to a FIFO that rings the dialer's bell, and every `Dialer::shared` drains it under the dialer lock, so each reader of the lists sees every ban before it reads; the table rings its subscribers after its own lock drops (`6257afdbcf`, `63bfdbc714`); the seed and the subscription are taken in one lock section. Then the ban query path is deleted (§5). Tests: a lookup after the deadline does not remove the entry; an extension re-arms; a permanent ban is never lifted; a lift during the seed is not lost.
   - **2b, the plumbing:** the `Dial` contract returns a `DialEnd` before the channel and gains `stamp_stream_end(connector, end)` for after it, `ZoneDial` dispatching to each connector's table; the drives call `Observed::end()`; the hub, the dialer's four failure paths, and the fake dialers, each taking a connector's own table. Clearnet's ban check at admission before the connect returns "refused here", tested to send no SYN. **A production-path test:** the real `Dialer` over the real `ZoneDial` and the real clearnet connector on localhost (a refusing port, a handshake the peer breaks, a listener that never answers), and Tor's drive against a scripted SOCKS server. The probe's arrival is checked against the activity stamp (§3.3).
3. **The Levin layer and the dialer** build theirs: refusal, wrong network or refused peer list through `refused_by_peer`; a Levin timeout `Uncertain`; the dialer's own failures `Local`.
4. **The peer list takes a verdict:** `Verdict { Counted, Excused, Drop }` replaces `Ladder`; excused seats on gray and white; hold the rung. Test: an excused failure on an address with counted failures cools at its current rung, not shorter.
5. **The judge:** bracketed corroboration, the deferred verdict, clearing; the quiet guard deleted; the judge's last sign of life on Tor published on `TorLinkTally` (§6). Tests: the brief's §6 tests 1–8 and the onset test (invariant 7), each red first with the edit that breaks it named; with the bound's worth of verdicts pending (five on Tor) the dialer still starts new dials up to the bound and the fill's target count excludes them; the first sign of life clears only the excusals of addresses with no counted failure.
   - **5b, the posture line** (the Tor supervisor's half of `OE-D10`; the Tor lane reviews it on #1235): `Dials::evaluate` drops the held condition and reads the judge's instant; `Policy::quiet_after` becomes `SocksTimeout + δ` from the Tor connector's own two declarations; the new sentence; its six tests; `TOR_SUPERVISOR.md` §4.2 (§6).
6. **The marks deleted**, `close_cause.h` regenerated, and the supervisor's Tor dial tally moved to `Reached::StreamOpened` (§5).
7. **The thresholds, the §97 rows, the docs:** the guard deleted whole: both connectors' K and S, their arithmetic and checks, the daemon's reading of S, and the docs that state them (§5). Nothing of the guard survives #1235.

**The live runs** follow on the Pi after the Tor soak's claim ends (the brief's §7).

## 9. Rejected alternatives

- **The marks encoding** (`OE-D2` as first ruled: an `Evidence` enum encoded as bits on the close cause's marks): it folds three independent facts (evidence, retry, how far the attempt got) into one byte read by name-checking helpers, and forced accept-only kinds to carry an evidence value nothing reads.
- **Every excused failure takes `outage_retry`:** excusal undoes the ladder; with two sessions it dials 346 times an hour against hold the rung's 256 (§3.4's model).
- **"One excusal per address per sign of life":** an address excused in one outage has its failures in the next counted after any sign of life between them, so white is emptied (13 demoted at 600 s, against 12 for the guard).
- **A per-connector clearing rule:** each connector's input to clearing is already its own path reading (§3.3). The reopening condition, a connector showing signs of life while its dials still cannot succeed, was met on Tor, where a held session talks through an onion-directory outage; the ruling of 2026-11-15 answered it by moving the reading to the Tor Manager, not by a clearing rule of the connector's own.
- **Option (a) for the quiet span** (the supervisor's own copy of S's arithmetic): its formula silently swapped K for the target and reached 364.5 s only because both round to three, and it would redo the dialer's arithmetic beside the dialer.
- **`0x02` as Local while no destination-port policy is configured:** the condition sits where nothing can check it, and an operator's own Tor with `RejectPlaintextPorts` lets a gossiped port produce `0x02`, so the address would be redialed every 10–15 s forever.
- **Tor's own statement per dial** (the STREAM event's `REASON` / `REMOTE_REASON`, matched to SOCKS dials): in steady state Tor's corroboration is almost always present, so Uncertain already counts; the gain is limited to fill and isolation, at the cost of a new path matching control-port events to SOCKS dials. *Reopen when* the Pi runs show that excused Tor failures carry a material dial cost during fill.
- **A ban row in clearnet's mapping** (a refusal by this node's ban counted as Destination): a ban is this node's standing verdict, not a failure to judge; a banned address is never eligible to be drawn (§3.1).
