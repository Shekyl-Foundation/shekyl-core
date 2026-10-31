# One judge of failed dials; each connector declares how its failures are judged

**Status: OPEN** — Round 0 return, proposed 2026-10-31, for Rick's ruling row by row (`OE-D1`…`OE-D10`). No code lands until §4 is ruled (rule 26's halt). The brief is [`DIALER_OUTAGE_EVIDENCE_BRIEF.md`](DIALER_OUTAGE_EVIDENCE_BRIEF.md), revision 2, ruled 2026-10-31.

**Read at:** `dev` `e543f0d329`, the brief's own pin. Every anchor the brief cites holds there (§1).
**Reviews:** the Tor lane reviews the Tor declarations (§3.2, §3.3, `OE-D4`, `OE-D5`) and rules the supervisor's new quiet-span source (`OE-D10`). The transport lane reviews clearnet's (`OE-D3`, `OE-D5`). This return is written by the session that also holds the transport lane, so clearnet's review is not independent; Rick may want another reviewer for it.
**Live runs** wait for the Pi, after the Tor soak's claim ends (about 2026-11-07 06:17Z).

The intent (Rick, 2026-10-31): each connector declares how its connections are tested and judged, as data, the way it already declares its escalation and backoff ladders. One judge in the dialer carries that out. The judge does not derive against a universal; it judges each connector by the stated characteristics of that network.

## 0. The decisions

| ID | Decision | Proposed | The alternative, and what breaks under it |
| --- | --- | --- | --- |
| `OE-D1` | The vocabulary | Three kinds: Destination, Local, Uncertain (§2) | A fourth kind, or a per-connector local meaning. Breaks "one judge": the judge would grow a branch per connector |
| `OE-D2` | Where a failure's kind is carried | In the close cause's marks: `NAMES_DESTINATION` plus two new bits; every cause carries exactly one; a kind whose meaning depends on its trigger has no default and is built only with its kind named (§2.2) | A parallel channel beside the cause. Breaks the 2026-10-24 rule that each layer owns its rejections in its cause |
| `OE-D3` | Clearnet's mapping | §3.1. Splits today's catch-alls (every connect error but a refusal is `LocalClose`; `TransportHandshakeFailed` holds the peer's bad answer and our own engine failure alike) | Keep the catch-alls. Breaks the mapping: a remote router's "host unreachable" would be Local, never counted; a peer's bad message 2 would be indistinguishable from ours |
| `OE-D4` | Tor's mapping | §3.2 (the Tor lane reviews) | Map unknown replies to Local. Breaks invariant 4's spirit: an onion that answers with an unlisted code never climbs |
| `OE-D5` | Corroboration | **Bracketed**: the link is shown working within δ before **and** within δ after the failure (§3.3). Tor: a stream opened, or bytes on any Tor session; clearnet: bytes on an outbound session. A session merely held never corroborates | "During the attempt", as the brief proposes. Breaks invariant 1 at an outage's onset: traffic from before the outage corroborates tests that the outage made fail (§3.3, the 5-in-flight case) |
| `OE-D6` | The clearing rule | The first corroborating event lifts every cooldown taken on an excused failure | No clearing; rely on the short excusal cooldown alone. Breaks nothing, but recovery waits up to one `outage_retry` after the first success |
| `OE-D7` | Values | δ 15 s on both; `outage_retry` 10 s + U(5 s) on both; the ladder, retries, waits and windows unchanged (§3.5) | A first-rung cooldown for excused failures (today's `FirstStep`). Breaks invariant 3: recovery waits 120–180 s, the Pi's 2 min 44 s |
| `OE-D8` | Where the judgment is | One function in `shekyl-dialer`, `judge`, returning a verdict; `Peerlist::apply` takes the verdict and keeps only seat mechanics (§4.1) | Keep `fail_test` deciding by marks in the peer list. Breaks "one point of judgment": the decision would sit half in each crate |
| `OE-D9` | Deletions | The quiet guard, its thresholds and the `Ladder` parameter (§5) | Keep the guard beside the judge. Breaks rule 15, and the 2026-10-31 ruling |
| `OE-D10` | The supervisor's quiet span | The Tor lane rules (§6). Two sources offered | Leave it reading Tor's S. Impossible: S is deleted |

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
| **Local** | This node's side failed: no route, address unavailable, proxy unavailable, our own request or close | **Excused.** Never counts: no ladder step, no white demotion, the failure count untouched. The address cools for the connector's `outage_retry` (§3.5) and is marked excused |
| **Uncertain** | The link or the destination: a timeout, an unreachable reply from the path | Counts only when the connector's corroboration holds (§3.3). Otherwise excused, as Local |

The vocabulary belongs to the dialer. A connector that needs a meaning outside it is a design round, not a new local rule.

### 2.2 Carried in the marks

- **Destination is `NAMES_DESTINATION`**, which already means "the far side answered about this destination". Two bits join it: `LOCAL` and `UNCERTAIN`. Every cause a dial can produce carries exactly one of the three. `PROVES_MISBEHAVIOUR` already requires `NAMES_DESTINATION` (`proving_misbehaviour_on`, `cause.rs:232-241`).
- **A kind whose meaning depends on its trigger has no default.** `TransportHandshakeFailed`, `LocalClose`, `IoError` and the clearnet connect failure are built only through a constructor that names the evidence, the way `new(ProxyRefused)` already refuses and needs `proxy_refused`. A site that forgets to name it does not compile. That is test 8's "a cause with no declared evidence kind fails the build", by type rather than by test.
- **`proxy_refused`'s mask and `Marks::ALL` widen**, and the C header gains the two mark constants (its test checks the mirror). Nothing in C++ reads the marks.
- **No persisted state changes.** The address file keeps addresses, not seats (every restart reloads every address as gray), so rule 42 is not touched.

## 3. What each connector declares

As data, in a `FailureJudging` declaration beside each connector's `DialProfile` in `shekyl-transport-layer/src/profile.rs`, one `const fn` row per connector (rule 71: data, never control flow):
1. **The mapping:** carried by the connector's own stamping (§3.1, §3.2); the declaration holds nothing extra, so there is one source.
2. **Its corroboration:** from the closed list in §3.3.
3. **Its clearing rule:** §3.4.
4. **Its values:** δ and `outage_retry` (§3.5), beside the ladder, retries, waits and window the profile already holds.

### 3.1 Clearnet's mapping (`OE-D3`; the transport lane reviews)

| What happened (where) | Today | Proposed |
| --- | --- | --- |
| Connect refused, direct (`drive.rs:292-309`) | `DialFailed`, `RETRY` | Destination |
| Connect reset, direct | `LocalClose` (catch-all) | Destination |
| Connect timed out by the kernel; host unreachable (ICMP from a router on the path) | `LocalClose` | Uncertain |
| Network unreachable, address not available, permission denied | `LocalClose` | Local |
| Any other connect error | `LocalClose` | Uncertain |
| Any connect error through the operator's SOCKS proxy (this node's proxy) | `LocalClose` | Local |
| The dial deadline, 1.415 s (`drive.rs:333-343`) | `TransportTimeout`, `RETRY \| WINDOW_TIMEOUT` | Uncertain |
| This node's ban on the address (`AdmissionRefused`); a socket-table or engine failure; a check that refuses the address | `AdmissionRefused` / `LocalClose` | Local |
| SOCKS reply through the operator's proxy: `0x05` | final, no marks | Destination |
| SOCKS reply `0x02`, `0x07`, `0x08`; SOCKS I/O, malformed or authentication failure | final / `ProxyUnavailable` | Local |
| Any other SOCKS reply | final, no marks | Uncertain |
| Handshake: the peer's message 2 does not verify; the prefix is another network's (`PrefixMismatch`) | `TransportHandshakeFailed` / `PrefixMismatch` | Destination |
| Handshake: EOF or reset from the peer mid-handshake | `TransportHandshakeFailed` (catch-all) | Destination |
| Handshake: our engine, crypto job or join failed | `TransportHandshakeFailed` | Local |
| Handshake deadline | `TransportTimeout` | Uncertain |
| After the channel: the Levin handshake times out; an I/O error | `LevinHandshakeTimeout` / `IoError` | Uncertain |
| After the channel: the peer closes; a record does not open; the Levin handshake or peer list is refused | `PeerClosed` / `RecordRejected` / `LevinHandshakeRejected` | Destination (clearnet never proves misbehaviour) |

A reset or a bad record can be forged by an on-path party. On clearnet that party already decides which peers this node reaches; counting what it forges records what it already enforces (the permanent clearnet residual: clearnet can encrypt and recognize, never authenticate).

### 3.2 Tor's mapping (`OE-D4`; the Tor lane reviews)

| What happened (where) | Today | Proposed |
| --- | --- | --- |
| The SOCKS port refuses or errors; authentication; malformed reply (`shekyl-tor/src/drive.rs:255-294`) | `ProxyUnavailable` / `LocalClose` | Local |
| Reply `0x01` (a live service's port refuses, after a working rendezvous), `0x05` (refused), `0xF1` (descriptor unusable) | final, `NAMES_DESTINATION` | Destination |
| Reply `0x02`; `0x07`, `0x08`, `0xF4`, `0xF5`, `0xF6` (this node's own request, `socks_reply_is_our_request`) | final, no marks | Local |
| Reply `0x04`, `0x06`, `0xF0`, `0xF2`, `0xF3`, `0xF7` | `RETRY \| WINDOW_TIMEOUT`, some `NAMES_DESTINATION` | Uncertain |
| Reply `0x03` (network unreachable) | `RETRY \| WINDOW_TIMEOUT` | **Uncertain, for the Tor lane to ground:** which stream-end reason produces it on a rendezvous stream. Local would mean never counted; Uncertain is the safe bucket until that is read in Tor's source |
| Any other reply | final, no marks | Uncertain |
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
- **What stays (a stated residual):** an outage that starts and ends inside a dial's window, ending more than δ before its deadline. That attempt times out with the link up on both sides of `t_f`, and it counts. On Tor, with a 105 s window and δ 15 s, that means outages shorter than about 90 s, up to the in-flight bound (5) per outage. On clearnet the window (1.415 s) is shorter than δ, so the case cannot arise.

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

### 3.4 The clearing rule (`OE-D6`)

The first corroborating event on a connector lifts every excused cooldown on that connector's addresses at once. Excused failures were never counted, so there is nothing to undo on the ladder or on white.

### 3.5 Values (`OE-D7`)

| Value | Clearnet | Tor | What it means for this connector's failures |
| --- | --- | --- | --- |
| δ (the bracket) | 15 s | 15 s | Long enough that a healthy node at target almost always sees traffic within it, and short enough that the onset and short-outage residuals stay small |
| `outage_retry` | 10 s + U(5 s) | 10 s + U(5 s) | How long an excused address waits before it can be drawn again. Bounds redials while the link is down; replaces the first-rung cooldown |
| Ladder, retries, waits, window, target, in-flight bound | unchanged | unchanged | As the profile holds them today |

**Why δ is 15 s.** A session receives about two messages a minute (§1). With `n` outbound sessions, the chance that none receives anything in δ is `exp(−n · δ / 30 s)`:

| Outbound sessions held | 1 | 2 | 3 | 6 | 12 (target) |
| --- | --- | --- | --- | --- | --- |
| A healthy link's Uncertain failure excused anyway | 61 % | 37 % | 22 % | 5 % | 0.25 % |

At target nothing changes, except that the verdict on an Uncertain failure waits 15 s. During fill, or at boot with no session, an Uncertain failure on a dead address is often excused. The cost is one redial after `outage_retry`, not a lost address. A Destination failure always counts.

**Recovery (invariant 3, by the numbers).**
- **Today:** the first rung is 120–180 s. The Pi recovered 2 min 44 s after the unblock, against 6 s in the refuse block.
- **Proposed:** the first redial after an unblock is at most 15 s away (`outage_retry`), and its stream opening clears every excused cooldown. Recovery is then at most 15 s plus one dial (Tor's median cold dial is 6.4 s), within the refuse case's order of magnitude.

## 4. The judge (`OE-D8`)

### 4.1 One function, and the peer list keeps seat mechanics

- **The judge.** `judge(outcome, declaration, observations) -> Verdict` in `shekyl-dialer` takes the place of `Dialer::ladder` in `record`. It reads the outcome's evidence kind, the connector's declaration, and the dialer's own observations (stream opens; the activity stamps of held sessions).
- **The verdict.** `Verdict` is `Counted`, `Excused` or `Drop`. `Peerlist::apply` takes a verdict and performs it: `fail_test` for `Counted`, a new `excuse` for `Excused`, `drop_tested` for `Drop`. It makes no decision of its own. That replaces the `Ladder` parameter, so the 58 `Ladder::Climb` call sites change mechanically.
- **Seat changes in the peer list:**
  - A gray seat's cooling phase records whether it was excused.
  - A white seat gains an optional excused-until instant, because white has no cooling state today. Without one, an excused white address would be redrawn at once, in a tight loop on clearnet.
- **The deferred verdict.**
  - The attempt's in-flight slot frees when it completes, and the seat stays `Outstanding` until the verdict.
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

The return proposes (a), as the smaller change, and leaves the choice to the Tor lane.

## 7. Wargame (§5 of the brief)

- **A total blackhole of the access link, both connectors.** Nothing is received and nothing opens, so nothing corroborates. White stays and nothing climbs. Excused addresses are redialed every 10–15 s, within the in-flight bound. At the unblock the first redial opens and clears every excused cooldown.
- **The same blackhole, with five Tor tests in flight at its onset.** Each fails with nothing after `t_f`, so all five are excused. Under "during the attempt" all five would count.
- **A short blackhole inside a Tor dial's window** (under about 90 s, ending more than δ before the deadline). The attempt counts, a stated residual: at most the in-flight bound per outage. Clearnet's 1.415 s window cannot hold one.
- **Clearnet, an on-path party who passes only its own session.** Its session is outbound and talks, so it corroborates, and honest addresses that time out are judged and demoted.
  - That party already decides which peers this node reaches. Demoting them records what it enforces: the permanent clearnet residual.
  - Excluding inbound makes it be a peer this node drew. Requiring bytes makes it keep that session talking around each failure, which is cheap for it. The design does not claim more than that.
- **Tor, an attacker who keeps one session open during a block.**
  - An idle session corroborates nothing: a byte must arrive.
  - A talking session cannot exist through a silent guard link, and an observer on that link cannot pass one stream and drop the rest.
  - So both `StreamOpened` and `SessionReceived` hold on Tor. A session merely held would not: it is what the Pi's idle sessions were.
- **A dead-onion flood while the node is isolated.** Every failure is excused, so dead addresses cool for 10–15 s and never climb. The draw stays uniform over drawable seats, so honest addresses keep their turn. The first success clears the excusals. From then on dead onions fail with corroboration and climb as today, at the cost of one extra redial each.
- **A slow link (the 40 kbit case).** Streams open late but do open, and sessions receive slowly but do receive. Both corroborate, so a slow link is never taken for an outage. The reverse is unchanged from today: a live onion that misses the 105 s window on a slow link, while another stream opens, is counted.
- **A healthy clearnet link.** At target (12 outbound sessions) an Uncertain failure is excused in about 0.25 % of cases, and judged as today otherwise, 15 s later. During fill the excusal rate follows §3.5's table, and an excused dead address costs one redial. Destination failures, the refusals, count at once as today.

## 8. The sub-PR's work, once §4 is ruled

One PR off `dev`, by the dialer lane, with these pieces:
1. **The marks:** the two bits, the evidence constructor, the widened mask and header, and no default on trigger-dependent kinds.
2. **The stamping:** clearnet's split in `drive.rs` and `handshake.rs` (§3.1), and Tor's table (§3.2).
3. **The declarations:** `FailureJudging` beside `DialProfile`.
4. **The judge, the verdict and the deferral:** the judge, `Verdict`, the deferred-verdict owner, and the seat changes.
5. **The deletions in §5.**
6. **Tests:** the brief's §6 tests 1–8, plus the onset test (invariant 7), each red first with the edit that breaks it named.
7. **The live runs** on the Pi after the Tor soak's claim ends (the brief's §7).

The supervisor's source (`OE-D10`) lands with it, in the Tor lane's form.
