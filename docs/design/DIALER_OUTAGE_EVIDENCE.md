# One judge of failed dials; each connector declares how its failures are judged

**Status: RULED (Round 0 closed 2026-10-31, revision 3)** — Rick ruled the second return the same day (§0.2): `OE-D6` hold the rung; clearing is the judge's behaviour, not a declaration; the judge takes its own type, `DialFailure`, which supersedes `OE-D2`; the values are per connector, each an `Assumption` with its basis in §97. **Still open:** `OE-D4` and `OE-D10`, with the Tor lane (§3.2, §6); and two rows of clearnet's mapping that are Rick's (§3.1): this node's ban or address check as Destination, and SOCKS `0x02` / `0x08` as Uncertain. The code is #1235 (§8), which stamps each open row with its proposed bucket and says so. *Records-was (revision 2): OPEN, `OE-D6` open, no code until it was ruled.* The brief is [`DIALER_OUTAGE_EVIDENCE_BRIEF.md`](DIALER_OUTAGE_EVIDENCE_BRIEF.md), revision 2, ruled 2026-10-31, with §4.2 item 3 and §7 amended by this ruling.

**Read at:** `dev` `f608d01604` (revision 3; every anchor in §1 re-read there and holds; since the brief's pin `e543f0d329`, `cause.rs` gained `CloseKind::AcceptRateExceeded`, an accept-only kind, and clearnet's `drive.rs` gained the accept linger, accept-side only). *Records-was: `dev` `e543f0d329`, the brief's own pin.*
**Reviews:** the Tor lane reviews the Tor declarations (§3.2, `OE-D4`) and rules the supervisor's new quiet-span source (`OE-D10`). Rick's reviewer covered clearnet's mapping independently (2026-10-31).
**Live runs** wait for the Pi, after the Tor soak's claim ends (about 2026-11-07 06:17Z).

The intent (Rick, 2026-10-31): each connector declares how its connections are tested and judged, as data, the way it already declares its escalation and backoff ladders. One judge in the dialer carries that out. The judge does not derive against a universal; it judges each connector by the stated characteristics of that network.

## 0. The decisions

| ID | Decision | Proposed | The alternative, and what breaks under it |
| --- | --- | --- | --- |
| `OE-D1` | The vocabulary | Three kinds: Destination, Local, Uncertain (§2) | A fourth kind, or a per-connector local meaning. Breaks "one judge": the judge would grow a branch per connector |
| `OE-D2` | Where a failure's kind is carried — **SUPERSEDED 2026-10-31 by the judge's own type, `DialFailure` (§2.2)** | *Records-was:* in the close cause's marks: `NAMES_DESTINATION` plus two new bits; every cause carries exactly one; a kind whose meaning depends on its trigger has no default and is built only with its kind named (§2.2) | A parallel channel beside the cause. Breaks the 2026-10-24 rule that each layer owns its rejections in its cause |
| `OE-D3` | Clearnet's mapping | §3.1. Splits today's catch-alls (every connect error but a refusal is `LocalClose`; `TransportHandshakeFailed` holds the peer's bad answer and our own engine failure alike) | Keep the catch-alls. Breaks the mapping: a remote router's "host unreachable" would be Local, never counted; a peer's bad message 2 would be indistinguishable from ours |
| `OE-D4` | Tor's mapping | §3.2 (the Tor lane reviews) | Map unknown replies to Local. Breaks invariant 4's spirit: an onion that answers with an unlisted code never climbs |
| `OE-D5` | Corroboration | **Bracketed**: the link is shown working within δ before **and** within δ after the failure (§3.3). Tor: a stream opened, or bytes on any Tor session; clearnet: bytes on an outbound session. A session merely held never corroborates | "During the attempt", as the brief proposes. Breaks invariant 1 at an outage's onset: traffic from before the outage corroborates tests that the outage made fail (§3.3, the 5-in-flight case) |
| `OE-D6` | The excusal and the clearing rule — **RULED 2026-10-31: hold the rung; clearing is the judge's** | **Revised (§3.4), ruled as proposed:** an excused failure neither climbs nor descends the ladder: an address already on it cools at its current rung; only an address with no counted failure takes the short `outage_retry`, and the first sign of life clears those | "One excusal per address per sign of life" (Rick's to evaluate). Breaks invariant 1 on a second outage: white is demoted as today (§3.4) |
| `OE-D7` | Values — **RULED 2026-10-31: per connector, each an `Assumption` with its own basis in §97** | Tor: δ 15 s, `outage_retry` 10 s + U(5 s), under the slot turnover; clearnet: δ 15 s, `outage_retry` 10 s + U(5 s), capping redials of an unproven address; the ladder, retries, waits and windows unchanged (§3.5) | A first-rung cooldown for excused failures (today's `FirstStep`). Breaks invariant 3: recovery waits 120–180 s, the Pi's 2 min 44 s |
| `OE-D8` | Where the judgment is | One function in `shekyl-dialer`, `judge`, returning a verdict; `Peerlist::apply` takes the verdict and keeps only seat mechanics (§4.1) | Keep `fail_test` deciding by marks in the peer list. Breaks "one point of judgment": the decision would sit half in each crate |
| `OE-D9` | Deletions | The quiet guard, its thresholds and the `Ladder` parameter (§5) | Keep the guard beside the judge. Breaks rule 15, and the 2026-10-31 ruling |
| `OE-D10` | The supervisor's quiet span | The Tor lane rules (§6). Two sources offered | Leave it reading Tor's S. Impossible: S is deleted |

### 0.1 Rick's rulings on the first return (2026-10-31)

- **Approved:** `OE-D1` (the vocabulary), `OE-D5` (bracketed corroboration), `OE-D9` (the deletions).
- **`OE-D2`, amended:** the evidence kind is an enum at the Rust API; the two bits are only its encoding (§2.2). The readers of `NAMES_DESTINATION` are checked below.
- **`OE-D3`, amended:** network unreachable, address not available, host unreachable and permission denied are Uncertain, not Local. **Local is only for failures independent of the destination.** The reason: a node with no IPv6 route would otherwise excuse every IPv6 address forever, and planted IPv6 entries would stall a v4-only node's one-at-a-time clearnet fill. Corroboration counts them when IPv4 works and excuses them in a total outage (§3.1).
- **`OE-D6`, open:** add clearnet fill from zero sessions at 50 % and 90 % planted dead addresses to the wargame, today against the proposal; evaluate "one excusal per address per sign of life"; bring back the numbers and a recommendation (§3.4).
- **`OE-D7`, amended:** each value's derivation per connector is stated in §97, with δ's dependency on the 60 s timed-sync interval (§3.5).
- **`OE-D8`, amended:** a deferred verdict holds no target place and no in-flight slot; only the seat stays outstanding. Made explicit and tested (§4.1, §8).
- **`OE-D4` and `OE-D10`:** the Tor lane's.

### 0.2 Rick's rulings on the second return (2026-10-31)

- **`OE-D6`: hold the rung.** An excused failure neither climbs nor descends. An address with counted failures cools at its current rung. Only an address with no counted failure takes `outage_retry`, and only those are cleared by the next sign of life.
- **Clearing is the judge's behaviour, not a declaration.** The brief's §4.2 item 3 is amended. Under rule 21:
  - *Rejected:* a per-connector clearing rule. Each connector's input is its corroboration declaration.
  - *Reopen when:* a connector shows signs of life while its dials still cannot succeed, so the first event must not clear.
- **The judge takes its own type, which supersedes `OE-D2`** (§2.2): `DialFailure { evidence, retry, reached }`. The D12 `CloseCause` travels beside it for the log; the judge's signature cannot see it. Who builds it, and what goes away, are in §2.2; the deletions are approved (§5).
- **Values, per connector** (§3.5): each an `Assumption` with its basis in §97. Not modelled; the Pi measures.
- **Corrections:** §3.3's short-outage residual holds on both connectors; §3.5's recovery bound is shown for clearnet only, and Tor's is a Pi measurement.
- **Pi runs added** to the brief's §7.
- **To the Tor lane:** `OE-D4` is now Tor's stamping into `DialFailure` (§3.2); `OE-D10`'s option (a) is wrong as written (§6).

## 1. Pre-flight: what the code holds at the pin

**The brief's anchors hold:** `Dialer::ladder` at `shekyl-dialer/src/owner/quiet.rs:67`; `fail_test` at `shekyl-peerlist/src/partition.rs:454`; the marks at `shekyl-transport-layer/src/cause.rs:143`, `:146`, `:149`, `:156`; `proxy_reply_marks` at `shekyl-tor/src/replies.rs:89`; `Peerlist::apply`'s misbehaviour test at `shekyl-peerlist/src/peerlist.rs:594`. The Pi run is shekyl-dev `8049fe7`, `data/tsr-acceptance/2026-10-31-pi-floor/`, and reads as §1 of the brief says.

**What the design rests on, found at the pin:**
- **Every finished attempt reaches the lists through one function**, `Dialer::record` (`owner/mod.rs:716-729`). It folds the attempt into the quiet counters, asks `ladder` once, and calls `Peerlist::apply`. Retries within a test are decided before it, in `settle_or_retry` (`owner/mod.rs:742-790`), from `RETRY` and `WINDOW_TIMEOUT`. The judge goes where `ladder` is.
- **"A stream opened" is already observable.** `reach::attempt_stream` (`reach.rs:48-63`) reads it from the close kind's phase (`CloseCause::opened_a_stream`, `cause.rs:313-316`): any failure past `BeforeChannel`, and every success.
- **"A session received bytes" is observable but unread.** The transport stamps each session's last received byte (`node_gate().activity(conn)`, `shekyl-capped-stream/src/gate.rs:255`), keyed by the socket id the dialer already keeps (`channel.held().open.id()`, `owner/handshake.rs:142`). The C++ stall check reads it; the dialer does not. The stamp's clock is `monotonic_ms()` (`shekyl-transport-layer/src/clock.rs:21`), whose origin is not the engine clock's, so the judge compares stamps with `monotonic_ms()` read at the same instant, never with an engine `Tick`.
- **A session merely held proves nothing.** In the Pi's blackhole every idle session stayed open 2 min 10 s into the block before closing as `LocalClose`.
- **A white address has no cooling state.** `Ladder::FirstStep` on white changes nothing and leaves it drawable at once (`partition.rs:481-483`).
- **The failure count resets only on promotion** (`partition.rs:359-390`), and recovery never shortens a cooldown (`owner/recovery.rs:149`, `re_admit`: an address already seated keeps its cooldown).
- **Clearnet's stamping has catch-alls** (`shekyl-clearnet/src/drive.rs:292-309`, `handshake.rs:141-275`): a refused connect is `DialFailed`, every other connect error is `LocalClose`; `TransportHandshakeFailed` holds a peer's bad message 2, a mid-handshake EOF or reset, and our own engine, crypto or join failure.
- **`CloseCause::proxy_refused` masks marks** to `RETRY | NAMES_DESTINATION | WINDOW_TIMEOUT` (`cause.rs:216-222`), and the C header mirrors the marks (`SHEKYL_CLOSE_MARK_*`, checked by a test). New bits widen both.
- **Healthy sessions talk every minute.** Each established connection gets a timed sync every `P2P_DEFAULT_HANDSHAKE_INTERVAL`, 60 s (`src/cryptonote_config.h:193`, `peer_sync_idle_maker`, `src/p2p/net_node.inl:686`), from both ends: about two received messages a minute per session.

## 2. The vocabulary (`OE-D1`, `OE-D2`)

### 2.1 Three kinds, and what the judge does with each

| Evidence | What it says | What the judge does |
| --- | --- | --- |
| **Destination** | The far end answered, or is shown absent | Counts: the ladder steps and a white address is demoted, as today. A Destination failure that also proves misbehaviour drops the address, as today, on a connector that authenticates the destination |
| **Local** | This node's side failed, independent of the destination: the operator's proxy unavailable, this node's own request, engine or close (no route and address unavailable depend on the destination and are Uncertain, `OE-D3` as ruled) | **Excused.** Never counts: no ladder step, no white demotion, the failure count untouched. An address with no counted failure cools for the connector's `outage_retry` (§3.5); an address with counted failures cools at its current rung (hold the rung, `OE-D6` as ruled). *Records-was (revision 2): "no route, address unavailable" listed as Local, and every excused address took `outage_retry`* |
| **Uncertain** | The link or the destination: a timeout, an unreachable reply from the path | Counts only when the connector's corroboration holds (§3.3). Otherwise excused, as Local |

The vocabulary belongs to the dialer. A connector that needs a meaning outside it is a design round, not a new local rule.

### 2.2 The judge's own type (ruled 2026-10-31; supersedes `OE-D2`)

```rust
struct DialFailure { evidence: Evidence, retry: Retry, reached: Reached }
enum Evidence { Destination(Proof), Local, Uncertain }
enum Proof { Absent, Misbehaviour }
enum Retry { Final, Again, AgainInsideWindow }
enum Reached { NoStream, StreamOpened }
```

- **`Proof::Misbehaviour`** is built only by a constructor that reads the connector's `destination_authenticated` declaration, and is always `Final`. On a connector that does not authenticate the destination the constructor cannot return it, so clearnet can never prove misbehaviour by type.
- **The D12 `CloseCause` travels beside it, for the log.** The judge's signature takes a `DialFailure` and the connector's declaration; it cannot see the cause.
- **Who builds it:**
  - **the connector:** every failure before the channel, and every end of its own stream after it;
  - **the Levin layer:** a rejected handshake, a wrong network or a refused peer list is `Destination`, its proof by the connector's declaration; a Levin handshake timeout is `Uncertain`;
  - **the dialer itself:** `Local` (its own failures: the socket table exhausted, its own close).
  - Where shared code observes a stream's end today, it hands that end to the connector to stamp. No connector-independent code assigns a meaning.
- **What goes away:**
  - An inbound refusal never builds a `DialFailure`, so the accept-only kinds (`InboundNotAccepted`, `AcceptRateExceeded`) need nothing.
  - `OpenError::Exhausted` on a dial is the dialer's own failure: `Local`.
  - The marks (§5): the type carries what they encoded, and nothing else reads them.
- **No persisted state changes.** The address file keeps addresses, not seats, so rule 42 is not touched.

*Records-was (`OE-D2`, revision 2, superseded):* an `Evidence` enum at the Rust API encoded as marks on the close cause — `NAMES_DESTINATION` plus two new bits, `LOCAL` and `UNCERTAIN`, exactly one per cause, trigger-dependent kinds built only through a constructor naming the evidence, `proxy_refused`'s mask and the C header widened. Superseded because the marks fold three independent facts (evidence, retry, how far the attempt got) into one byte read by name-checking helpers, and an accept-only kind had to carry an evidence value nothing reads.

## 3. What each connector declares

As data, in a `FailureJudging` declaration beside each connector's `DialProfile` in `shekyl-transport-layer/src/profile.rs`, one `const fn` row per connector (rule 71: data, never control flow):
1. **The mapping:** carried by the connector's own stamping into `DialFailure` (§2.2, §3.1, §3.2); the declaration holds nothing extra, so there is one source.
2. **Its corroboration:** from the closed list in §3.3.
3. ~~**Its clearing rule**~~ — *REJECTED 2026-10-31 (rule 21):* clearing is the judge's behaviour (§3.4). Each connector's input is its corroboration declaration. *Reopen when* a connector shows signs of life while its dials still cannot succeed, so the first event must not clear.
   - **Its `destination_authenticated` flag:** whether the destination is authenticated, which is the only thing that lets `Proof::Misbehaviour` be built (§2.2).
4. **Its values:** δ and `outage_retry` (§3.5), beside the ladder, retries, waits and window the profile already holds.

### 3.1 Clearnet's mapping (`OE-D3`; the transport lane reviews)

| What happened (where) | Today | Proposed |
| --- | --- | --- |
| Connect refused, direct (`drive.rs:292-309`) | `DialFailed`, `RETRY` | Destination |
| Connect reset, direct | `LocalClose` (catch-all) | Destination |
| Connect timed out by the kernel; host unreachable (ICMP from a router on the path) | `LocalClose` | Uncertain |
| Network unreachable, address not available, permission denied | `LocalClose` | Uncertain (ruled: each depends on the destination's address family or route) |
| Any other connect error | `LocalClose` | Uncertain |
| Any connect error through the operator's SOCKS proxy (this node's proxy) | `LocalClose` | Local |
| The dial deadline, 1.415 s (`drive.rs:333-343`) | `TransportTimeout`, `RETRY \| WINDOW_TIMEOUT` | Uncertain |
| A socket-table or engine failure | `LocalClose` | Local |
| This node's ban on the address (`AdmissionRefused`); a check that refuses the address | `AdmissionRefused` / `LocalClose` | **Destination, for Rick:** both depend on the destination, so under the ruling neither is Local. Each is this node's standing verdict on that address, which no outage produces, so counting it at once is safe and keeps the address from being redrawn |
| SOCKS reply through the operator's proxy: `0x05` | final, no marks | Destination |
| SOCKS reply `0x07` (command not supported); SOCKS I/O, malformed or authentication failure | final / `ProxyUnavailable` | Local |
| SOCKS reply `0x02` (refused by the proxy's rules), `0x08` (address type not supported) | final, no marks | **Uncertain, for Rick:** both depend on the destination; `0x08` is the IPv6 case of the ruling arriving through a proxy |
| Any other SOCKS reply | final, no marks | Uncertain |
| Handshake: the peer's message 2 does not verify; the prefix is another network's (`PrefixMismatch`) | `TransportHandshakeFailed` / `PrefixMismatch` | Destination |
| Handshake: EOF or reset from the peer mid-handshake | `TransportHandshakeFailed` (catch-all) | Destination |
| Handshake: our engine, crypto job or join failed | `TransportHandshakeFailed` | Local |
| Handshake deadline | `TransportTimeout` | Uncertain |
| After the channel: the Levin handshake times out; an I/O error | `LevinHandshakeTimeout` / `IoError` | Uncertain |
| After the channel: the peer closes; a record does not open; the Levin handshake or peer list is refused | `PeerClosed` / `RecordRejected` / `LevinHandshakeRejected` | Destination (clearnet never proves misbehaviour) |

A reset or a bad record can be forged by an on-path party. On clearnet that party already decides which peers this node reaches; counting what it forges records what it already enforces (the permanent clearnet residual: clearnet can encrypt and recognize, never authenticate).

**The principle, ruled:** Local is only for failures independent of the destination. A failure that depends on the destination's address family or route is Uncertain: corroboration counts it when another path works (IPv4, here) and excuses it in a total outage.

### 3.2 Tor's mapping (`OE-D4`; the Tor lane reviews — now Tor's stamping into `DialFailure`, including `0x03` and the destination-dependent replies)

| What happened (where) | Today | Proposed |
| --- | --- | --- |
| The SOCKS port refuses or errors; authentication; malformed reply (`shekyl-tor/src/drive.rs:255-294`) | `ProxyUnavailable` / `LocalClose` | Local |
| Reply `0x01` (a live service's port refuses, after a working rendezvous), `0x05` (refused), `0xF1` (descriptor unusable) | final, `NAMES_DESTINATION` | Destination |
| Reply `0x02`; `0x07`, `0x08`, `0xF4`, `0xF5`, `0xF6` (this node's own request, `socks_reply_is_our_request`) | final, no marks | Local |
| Reply `0x04`, `0x06`, `0xF0`, `0xF2`, `0xF3`, `0xF7` | `RETRY \| WINDOW_TIMEOUT`, some `NAMES_DESTINATION` | Uncertain |
| Reply `0x03` (network unreachable) | `RETRY \| WINDOW_TIMEOUT` | **Uncertain, for the Tor lane to ground:** which stream-end reason produces it on a rendezvous stream. Local would mean never counted; Uncertain is the safe bucket until that is read in Tor's source |
| Any other reply | final, no marks | Uncertain |
| **For the Tor lane, under `OE-D3`'s principle:** `0x08` (address type), `0xF6` (onion address rejected) and `0xF4`, `0xF5` (client authorization for that onion) depend on the destination, as does `0x02` | listed as Local above | Not Local under the principle; Uncertain or Destination is the Tor lane's call |
| The dial deadline, 120 s | `TransportTimeout`, `RETRY \| WINDOW_TIMEOUT` | Uncertain |
| A local engine, socket-table or check failure | `LocalClose` | Local |
| After the stream opened: the Levin handshake times out; the peer closes; an I/O error | `RETRY` | Uncertain. A circuit that collapses with this node's link looks the same as an onion that hangs up |
| After the stream opened: the Levin handshake or peer list is refused | `NAMES_DESTINATION \| PROVES_MISBEHAVIOUR` | Destination, and it still drops |

### 3.3 Corroboration (`OE-D5`)

**The finding: "during the attempt" leaks at an outage's onset.** Suppose the node is filling, with five Tor dials in flight (the bound) and six white entries (testnet), and the link goes silent. Each of those tests began before the onset, and streams opened during their windows before it: another attempt's open, or bytes on a held session. So every one of them fails "corroborated" by traffic from before the outage, and is counted. Five of six white entries are demoted at the onset, which is the failure the guard had.

**So corroboration is bracketed.** At the instant `t_f` a test's final attempt fails with Uncertain evidence, the verdict waits δ. The failure counts only if the link was shown working both:
- within δ **before** `t_f`, by an event other than the failing attempt itself; **and**
- within δ **after** `t_f`.

What each side closes:
- **The onset** of an outage leaves nothing after `t_f`, so the failure is excused.
- **The end** of an outage leaves nothing before `t_f`, so the failures made during it are excused.
- **What stays (a stated residual, corrected 2026-10-31):** the bracket counts failures made inside any outage shorter than about 2δ, on **both** connectors — the link is shown working within δ before and within δ after `t_f`, so an outage that fits between those two signs of life is invisible to it. With δ 15 s that is outages under about 30 s. On Tor an attempt whose window spans a longer outage is also counted if the outage ends more than δ before its deadline, up to the in-flight bound (5) per outage. The Pi's 10, 20 and 30 s blackholes and the pulsed-loss run (brief §7) measure it. *Records-was: "On clearnet the window (1.415 s) is shorter than δ, so the case cannot arise" — wrong: a clearnet dial made inside a short outage is bracketed by signs of life on both sides.*

**What shows the link worked (the closed list):**
- **`StreamOpened`:** an attempt on this connector reached an open stream (`opened_a_stream`, or a session).
- **`SessionReceived { outbound_only }`:** a held session on this connector received a byte (the activity stamp, §1).
- **Never:** a session merely held (the Pi's idle sessions sat open 2 min 10 s into the blackhole), the probe of the node's own onion (it never reaches the dialer, `TOR_SUPERVISOR.md` §4.5), or anything from Tor's own network judgment (`TSR-Q14`).

**The declarations:**
- **Tor:** `StreamOpened` or `SessionReceived` on any session, inbound included. Every Tor byte crosses the one guard link, and an observer on it cannot tell streams apart, so it passes all of them or none.
- **Clearnet:** `SessionReceived` on **outbound sessions only**.
  - **Inbound excluded:** a censor can block this node's outbound connects while established inbound flows continue, and inbound peers choose this node, not the reverse. An inbound session would then corroborate failures the censor caused.
  - **Idle excluded** by construction: a byte must arrive.
  - The clearnet on-path party who passes only its own session still corroborates. Inbound exclusion makes it be a peer this node chose (it must win a draw), and the byte rule makes it keep that session talking around each failure. That is a small cost, honestly stated: §7.

### 3.4 The excusal and the clearing rule (`OE-D6` — RULED 2026-10-31: hold the rung; clearing is the judge's)

**Rick's concern:** with few sessions most failures are excused and every success clears them, so dead addresses may never decay.

**The model** (shekyl-dev `data/dialer-outage/2026-10-31-oe-d6-fill-model/`, `fill_model.py`; every input is stated there, none measured):
- **Clearnet as the profile has it:** bound 1, target 12, deadline 1.415 s, wake 0.5 s + U(1 s), the ladder 120 s doubling to 1 h with U(50 %) jitter. The gray list starts full and white starts empty, as after a restart.
- **Addresses:** live addresses succeed and dead ones time out.
- **Sessions:** each outbound session receives about two messages a minute (§3.5) and lasts an exponential 30 minutes.
- **A blackhole:** stops all bytes and closes idle sessions 130 s in, as on the Pi.
- **Runs:** 200 seeds a cell for fill and decay, 100 for outages, two hours each.

**Fill from zero sessions** (medians; seconds to the target, p90 in brackets):

| Gray list, planted dead | Today (with the K/S guard) | The first return's proposal | One excusal per address per sign of life | **Hold the rung (recommended)** |
| --- | --- | --- | --- | --- |
| 1,000, 50 % | 42 (60) | 41 (57) | 41 (57) | 41 (57) |
| 1,000, 90 % | 277 (399) | 259 (373) | 259 (388) | 259 (373) |
| 5,000, 50 % | 42 (61) | 41 (56) | 41 (56) | 41 (56) |
| 5,000, 90 % | 269 (382) | 241 (348) | 241 (347) | 241 (348) |

At these sizes decay does not matter: each dead address is dialed about once during the fill. The proposal fills no slower than today. It counts 83–95 % of the dead addresses it dials, today 100 %; the rest are excused and redialed once.

**Where decay matters: few live addresses, so few sessions, held for hours** (dials in the second hour; every rule's dead addresses reach the ladder's cap, a mean of 6 failures, except where noted):

| Live addresses (sessions held) | Today | Proposal | One excusal per sign of life | Hold the rung |
| --- | --- | --- | --- | --- |
| 10 of 100 (about 10) | 110 | 112 | 111 | — |
| 5 of 50 (5) | 55 | 65 | 59 | 63 (mean 5.9 failures) |
| 2 of 100 (2) | 102 | **346** | 102 | 256 (mean 4.9 failures) |
| 0 of 100 (none: an outage, as far as the node can tell) | 1,490 | 1,757 | 1,757 | 1,757 |

- **Decay does happen:** dead addresses climb to the cap in every regime, because once sessions exist they corroborate most failures.
- **What the proposal costs is dials.** With two sessions, about 37 % of failures miss the bracket, and an excused failure reset even a capped address to a 10–15 s cooldown. That gives 346 dials an hour against today's 102.
- **With no live address at all,** every rule dials at the bound's ceiling, today's guard included.

**Outages** (two blackholes in a row, 20 live addresses, 10 % of live dials failing at random; white addresses demoted across both outages, median, p90 in brackets):

| Blackhole length | Today | Proposal | One excusal per sign of life | Hold the rung |
| --- | --- | --- | --- | --- |
| 60 s | 1 (2) | 0 (0) | — | 0 (0) |
| 120 s | 2 (4) | 1 (2) | — | 1 (2) |
| 180 s | 12 (20) | 2 (4) | — | 2 (4) |
| 600 s | 12 (20) | 1 (4) | 13 (15) | 2 (4) |

The proposal's and hold-the-rung's 1–2 are ordinary random failures in the δ right after each blackhole ends, which the measure's window includes; neither counts a failure made during an outage. Recovery after each blackhole is 1–12 s for both (today's 2 min 44 s on the Pi came from a six-address white list all cooling at the first rung).

**"One excusal per address per sign of life" breaks invariant 1.** An address excused in the first outage, followed by any sign of life, has its failures in the second outage counted. White is emptied as today (13 against today's 12 at 600 s). Two tighter forms were tried:
- **Counting from the address's last uncorroborated failure** still counts once per address per outage, enough to demote every white address (12).
- **One excusal, then a 120 s bracket** matches today's dial rate with two sessions (102) and survives long outages. But any bracket counts failures inside a blip shorter than twice its width, so it demotes white in 60–120 s blackholes as today does (1–2).

**The recommendation: an excused failure neither climbs nor descends the ladder.**
- An address already on the ladder (it has counted failures) cools at its current rung.
- Only an address with no counted failure, which includes every live white address, takes the short `outage_retry`, and only those are cleared by the next sign of life.
- No uncorroborated failure ever counts, so invariants 1, 2 and 7 hold exactly.
- Excusal no longer undoes the ladder. That takes the two-session waste from 346 to 256 dials an hour.
- What is left is the first failure of each new dead address while sessions are scarce, which can be excused and retried more than once before it counts: a stated residual, bounded by `outage_retry`.

**The ruling (Rick, 2026-10-31): hold the rung.** An excused failure neither climbs nor descends. An address with counted failures cools at its current rung. Only an address with no counted failure takes `outage_retry`, and only those are cleared by the next sign of life.

**The clearing rule is the judge's, not a declaration:** the first sign of life on a connector lifts the excused cooldowns of addresses with no counted failure. Nothing on the ladder is touched. A per-connector clearing rule is rejected (rule 21; §3, item 3).

### 3.5 Values (`OE-D7` — RULED 2026-10-31: per connector)

Each value is the connector's own, an `Assumption` with its basis in `DAEMON_RELAY_PRIVACY.md` §97 (the code PR adds the rows). Not modelled; the Pi measures (brief §7).

| Value | Tor | Clearnet |
| --- | --- | --- |
| δ (the bracket) | 15 s | 15 s |
| `outage_retry` | 10 s + U(5 s) | 10 s + U(5 s) |
| **Basis of `outage_retry`** | Stays under the slot turnover, `window / bound` (105 s / 5 = 21 s): an excused address is drawable again before a slot comes free, so the outage cooldown never holds a slot idle | Caps redials of an unproven address: with bound 1 and a 1.415 s deadline, at most one redial of such an address per 10–15 s |
| **Basis of δ** | Depends on the 60 s timed-sync interval (`P2P_DEFAULT_HANDSHAKE_INTERVAL`) and on stream opens through the one guard link: with `n` sessions, `exp(−n · δ / 30 s)` is the chance a healthy link shows nothing in δ | Depends on the 60 s timed-sync interval and on outbound sessions only (inbound is excluded from clearnet's corroboration, §3.3) |
| Ladder, retries, waits, window, target, in-flight bound | unchanged | unchanged |

Equal numbers on the two rows are two derivations landing on one value, not one value shared: each row's basis is its own, and each re-derives when its basis moves (the timed-sync interval for both δ; Tor's window or bound for Tor's `outage_retry`; clearnet's deadline or bound for clearnet's).

**Why δ is 15 s.** A session receives about two messages a minute (§1). **Arrival model (an assumption, not a measurement):** bytes arrive on each corroborating session as an independent Poisson process at that rate, so with `n` sessions the chance that one δ-interval shows nothing is `p = exp(−n · δ / 30 s)`. The bracket needs a sign of life in the δ before **and** the δ after the failure, two disjoint intervals, so a healthy link's Uncertain failure is excused when either is empty: `1 − (1 − p)²`.

| Sessions that corroborate | 1 | 2 | 3 | 6 | 12 (target) |
| --- | --- | --- | --- | --- | --- |
| A healthy link's Uncertain failure excused anyway (two-sided) | 85 % | 60 % | 40 % | 9.7 % | 0.50 % |

*Records-was (to 2026-10-31, corrected on #1229's review): the one-sided figures 61 %, 37 %, 22 %, 5 % and 0.25 %, which count only one of the two intervals.*

At target nothing changes, except that the verdict on an Uncertain failure waits δ. During fill, or at boot with no session, an Uncertain failure on a dead address is often excused; each excusal of an address with no counted failure costs a redial after `outage_retry`, and §3.4 allows an address to be excused more than once before a failure counts (its stated residual), so the cost is redials, not a lost address. A Destination failure always counts.

**Recovery (invariant 3; corrected 2026-10-31).**
- **Today:** the first rung is 120–180 s. The Pi recovered 2 min 44 s after the unblock, against 6 s in the refuse block.
- **Clearnet:** `outage_retry` bounds the cooldown that starts at an excused verdict, not the time from the unblock. A failure just before the unblock holds its seat outstanding for its deferred verdict, up to δ (15 s, §4.1), and only then cools for up to 15 s; and the redial needs that address to be the one drawn, or another eligible candidate to exist. So the first redial of a given excused address is at most about δ + 15 s (≈ 30 s) after the unblock, plus one dial, and its success clears every excused cooldown of an address with no counted failure; addresses with counted failures keep their rung (§3.4). This is the design's bound; the Pi measures it (brief §7). *Records-was (revision 3, same day): "at most 15 s away … recovery is at most 15 s plus one dial", which omitted the deferred verdict.*
- **Tor:** the first redial after an unblock waits for a slot, and in-flight attempts are left to run (TSR-Q14: Tor retries inside its own window), so the bound above does not hold there. The time from unblock to the first stream open is a Pi measurement (brief §7). *Records-was: "recovery is then at most 15 s plus one dial (Tor's median cold dial is 6.4 s)" stated for both connectors.*

*Records-was (revision 2): δ 15 s and `outage_retry` 10 s + U(5 s) "on both", from one derivation.*

## 4. The judge (`OE-D8`)

### 4.1 One function, and the peer list keeps seat mechanics

- **The judge.** `judge(outcome, declaration, observations) -> Verdict` in `shekyl-dialer` takes the place of `Dialer::ladder` in `record`. It reads the outcome's evidence kind, the connector's declaration, and the dialer's own observations (stream opens; the activity stamps of held sessions).
- **The verdict.** `Verdict` is `Counted`, `Excused` or `Drop`. `Peerlist::apply` takes a verdict and performs it: `fail_test` for `Counted`, a new `excuse` for `Excused`, `drop_tested` for `Drop`. It makes no decision of its own. That replaces the `Ladder` parameter, so the 58 `Ladder::Climb` call sites change mechanically.
- **Seat changes in the peer list:**
  - A gray seat's cooling phase records whether it was excused.
  - A white seat gains an optional excused-until instant, because white has no cooling state today. Without one, an excused white address would be redrawn at once, in a tight loop on clearnet.
- **The deferred verdict (`OE-D8`, as ruled):** a deferred verdict holds **no target place and no in-flight slot; only the seat stays outstanding.**
  - The attempt's in-flight slot frees when the attempt completes.
  - The pending verdict is not a kept session or a pending `Keep`, so the fill's count toward the target never includes it. The dialer draws and dials while verdicts wait.
  - The address's seat stays `Outstanding` until the verdict, so it is not drawn again meanwhile.
  - One timing-engine owner per connector carries the earliest pending deadline, the shape of the accept linger in #1226. Tor's five slots are never held idle for δ.
  - At the deadline the judge reads the after-side evidence and applies the verdict.
  - A Destination failure needs no wait and is applied at once.

### 4.2 What the judge guarantees, for every connector

Each is tested against every connector's declaration, over a simulated timeline, not promised per connector:
1. **An outage never empties white:** an uncorroborated failure never demotes white.
2. **An outage never climbs the ladder.**
3. **Recovery doesn't wait on outage cooldowns:** the first corroborating event clears excused cooldowns (§3.5's arithmetic).
4. **Proven misbehaviour still drops,** on a destination-authenticated connector, as today.
5. **The probe never counts as link evidence.**
6. **Nothing is inferred about Tor's network:** the judge reads only the dialer's own observations (`TSR-Q14`); the supervisor's posture line is unchanged.
7. **An outage's onset demotes nothing** (added by §3.3): five tests in flight when the link goes silent are all excused.

## 5. Deletions (`OE-D9`, rule 15)

From the census at the pin. Historical ledger rows stay; they are a record.
- **The guard** (`shekyl-dialer`):
  - `src/owner/quiet.rs`, all of it;
  - `Shared::unopened` and `Shared::last_opened` (`owner/mod.rs:139-144`, `:278-279`), and both `note_attempt` calls (`:723`, `:781`);
  - `reach::QuietEvidence` and `quiet_evidence` (`reach.rs:37-45`, `:70-80`).
  - **Stays:** `Shared::inbound` and `attempt_stream`, which the Tor tally reads.
- **The thresholds** (`shekyl-transport-layer/src/profile.rs`):
  - `QuietThreshold` and `derive` (`:90-141`), `quiet()` (`:173-183`);
  - `quiet_attempts` and the two constants, K 11 and K 13 (`:257-266`, `:289`, `:309`);
  - the build-time span check (`:314-326`).
- **The ladder parameter** (`shekyl-peerlist`): `Ladder` (`lib.rs:153-170`), replaced by the verdict (§4.1).
- **The marks** (approved 2026-10-31, superseding `OE-D2`): `Marks` and the marks byte in the Rust `CloseCause`; `proxy_refused`'s marks argument; `proving_misbehaviour_on`, `retry_worthy`, `window_timeout`, `proves_misbehaviour`, `names_the_destination` and `opened_a_stream`; Tor's `proxy_reply_marks`, replaced by Tor's stamping into `DialFailure`. The generated `close_cause.h` is regenerated from `c_header()`, with no hand edit to any C or C++ file. Each deleted test names the rule it tested and where that rule is now covered.
- **Tests that pin K, S or the guard**, rewritten as the judge's tests:
  - nine in `shekyl-dialer/tests/attempts/quiet.rs`, two in `white.rs`;
  - `the_profile_table_moves_todays_values` and `the_quiet_span_is_derived_from_the_row` (`profile.rs`);
  - `a_local_close_counts_for_the_quiet_guard_and_not_the_tally` (`reach.rs`);
  - the `FirstStep` halves of `door.rs:627` and `lifecycle.rs:261`;
  - `the_posture_lines_quiet_stretch_is_the_dialers` (`shekyl-daemon/src/tor/mod.rs:1077`), which moves with `OE-D10`.
- **Docs that state the guard, K or S:**
  - `DAEMON_RELAY_PRIVACY.md` §97 (the gray-cooldown row's quiet threshold, and the in-flight row's quiet stretch);
  - `P2P_3_SLICE_3_DIALER_BRIEF.md` (the quiet-stretch paragraph and its wargame);
  - `P2P_3_SLICE_1_PEERLIST_BRIEF.md` (four lines);
  - `TOR_SUPERVISOR.md` `quiet_after`'s source and the quiet-stretch bound;
  - `NOISE_FLIP_REHEARSAL_BRIEF.md`'s K and S follow-up (C4);
  - `docs/benchmarks/p2p_tor_inflight_bound_20261025.md`;
  - the Unreleased CHANGELOG lines.
- **The measurement ledger:** editing `profile.rs` needs new acknowledgements on the clearnet and Tor span path sets. No constant's needle points at `profile.rs`.
- **No CI gate** names the guard, K, S or `quiet_after`.

## 6. The supervisor's quiet span (`OE-D10`; the Tor lane rules)

`quiet_after` governs one neutral posture sentence, "No connection through Tor is open, and none has opened in …" (`shekyl-tor-control-client/src/supervisor/core/dials.rs:78`, `posture.rs:777-788`). It is display only, never a cause. Today the daemon passes Tor's S, 364.5 s (`shekyl-daemon/src/tor/mod.rs:60-71`). Two sources:
- **(a) The supervisor's own derived span:** the same arithmetic S had, owned by the supervisor. That is `ceil(target / bound)` windows plus wakes, about 364.5 s, written once in its own crate.
- **(b) The judge's last corroborating instant:** the line says the link has shown no sign of working for a span. That reads the dialer's observation, and the span still needs one of (a)'s values.

The return proposed (a), as the smaller change, and left the choice to the Tor lane.

**Ruled 2026-10-31 (Rick), to the Tor lane:** option (a)'s formula silently swaps K for the target; it lands on 364.5 s only because both round to three. Derive the span from what the posture sentence claims, or take (b), the judge's last sign of life, rewording the sentence to say what the judge observes.

## 7. Wargame (§5 of the brief)

- **A total blackhole of the access link, both connectors.** Nothing is received and nothing opens, so nothing corroborates. White stays and nothing climbs. An excused address with no counted failure becomes eligible again after 10–15 s; one with counted failures holds its rung. Eligible only means drawable when a slot is free: the in-flight bound, and on Tor the attempts still running (left to run, TSR-Q14), decide when it is dialed. At the unblock the first success clears the excused cooldowns of addresses with no counted failure. *Records-was: "excused addresses are redialed every 10–15 s … the first redial opens and clears every excused cooldown".*
- **The same blackhole, with five Tor tests in flight at its onset.** Each fails with nothing after `t_f`, so all five are excused. Under "during the attempt" all five would count.
- **A short blackhole** (§3.3's residual, corrected 2026-10-31). On both connectors, a failure made inside an outage shorter than about 2δ (≈ 30 s) is bracketed by signs of life on both sides and counts. On Tor an attempt whose window spans a longer outage also counts if the outage ends more than δ before its deadline, up to the in-flight bound per outage. The Pi's 10, 20 and 30 s blackholes and the pulsed-loss run measure it. *Records-was: "Clearnet's 1.415 s window cannot hold one."*
- **Clearnet, an on-path party who passes only its own session.** Its session is outbound and talks, so it corroborates, and honest addresses that time out are judged and demoted.
  - That party already decides which peers this node reaches. Demoting them records what it enforces: the permanent clearnet residual.
  - Excluding inbound makes it be a peer this node drew. Requiring bytes makes it keep that session talking around each failure, which is cheap for it. The design does not claim more than that.
- **Tor, an attacker who keeps one session open during a block.**
  - An idle session corroborates nothing: a byte must arrive.
  - A talking session cannot exist through a silent guard link, and an observer on that link cannot pass one stream and drop the rest.
  - So both `StreamOpened` and `SessionReceived` hold on Tor. A session merely held would not: it is what the Pi's idle sessions were.
- **Clearnet fill from zero sessions, 50 % and 90 % planted dead (§3.4's numbers).** The fill takes as long as today's or less: 41 s and 241–259 s against 42 s and 269–277 s (medians). Decay does not matter at these sizes, since each dead address is dialed about once. Where it does matter (two live addresses, so two sessions, for hours), holding the rung keeps excusal from undoing the ladder: 256 dials an hour, against 346 for the first return and 102 today.
- **A dead-onion flood while the node is isolated.** Every failure is excused, so dead addresses cool for 10–15 s and never climb. The draw stays uniform over drawable seats, so honest addresses keep their turn. The first success clears the excusals. From then on dead onions fail with corroboration and climb as today, at the cost of one extra redial each.
- **A slow link (the 40 kbit case).** Streams open late but do open, and sessions receive slowly but do receive. Both corroborate, so a slow link is never taken for an outage. The reverse is unchanged from today: a live onion that misses the 105 s window on a slow link, while another stream opens, is counted.
- **A healthy clearnet link.** At target (12 outbound sessions) an Uncertain failure is excused in about 0.50 % of cases under §3.5's arrival model (two-sided), and judged as today otherwise, δ later. During fill the excusal rate follows §3.5's table; an excused dead address costs a redial per excusal, and may be excused more than once before a failure counts (§3.4's residual). Destination failures, the refusals, count at once as today. *Records-was: "about 0.25 %" (one-sided) and "an excused dead address costs one redial".*

## 8. The sub-PR's work (#1235, open off `dev`, 2026-10-31)

One PR off `dev`, by the dialer lane, [#1235](https://github.com/Shekyl-Foundation/shekyl-core/pull/1235), with these pieces:
1. **The type:** `DialFailure` and its enums (§2.2), the `Proof::Misbehaviour` constructor on `destination_authenticated`, and the marks deleted (§5) with `close_cause.h` regenerated. *Records-was: the two bits, the evidence constructor, the widened mask and header.*
2. **The stamping:** clearnet's split in `drive.rs` and `handshake.rs` (§3.1), and Tor's table (§3.2).
3. **The declarations:** `FailureJudging` beside `DialProfile`.
4. **The judge, the verdict and the deferral:** the judge, `Verdict`, the deferred-verdict owner, and the seat changes.
5. **The deletions in §5.**
6. **Tests:** the brief's §6 tests 1–8 as amended 2026-10-31 to the bracket and hold the rung, plus the onset test (invariant 7), each red first with the edit that breaks it named. Plus:
   - **`OE-D8`'s test:** with the bound's worth of verdicts pending (five on Tor), the dialer still starts new dials up to the bound, and the fill's target count excludes the pending ones. It fails if a pending verdict holds its slot or counts as a `Keep`.
   - **`OE-D6`'s tests:** an excused failure on an address with counted failures cools at its current rung, not shorter; the first sign of life clears only the excusals of addresses with no counted failure.
7. **The live runs** on the Pi after the Tor soak's claim ends (the brief's §7).

The supervisor's source (`OE-D10`) lands with it, in the Tor lane's form.
