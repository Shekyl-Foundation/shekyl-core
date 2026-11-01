# Brief: one judge of failed dials; each connector says how its failures are judged (dialer / p2p lane)

**Status:** Design
**Revision 2, 2026-10-31. Replaces revision 1 in full.**
**For:** the dialer (p2p) lane.
- Round 0 first: bring back the design (§4) for Rick's ruling, then build one PR off `dev`.
- The Tor lane reviews the Tor connector's declarations; the transport lane reviews clearnet's.

**Why now:** this has to be fixed before the daemon is called done (Rick, 2026-10-25, the same gate as the in-flight bound).
**Read at:** `dev` `e543f0d32`. Re-read every anchor at your own pin.

**Ruled (Rick, 2026-10-31):**
- **One judge.** There is one point of judgment for a failed dial, in the dialer and the peer list. It decides what a failure does to the address: the ladder, white demotion, the cooldown.
- **Each connector supplies its inputs.** Each connector supplies, as declared data, what each of its failures means and how its failures are to be judged, plus its backoff values. A connector supplies no judging code.
- **Why:** connectors fail in different ways. Tor differs from clearnet, and I2P or Nym will differ again. A strategy derived for all of them fits none. The K/S quiet guard is the evidence: one mechanism, fed per-connector numbers, failed on Tor.
- **The K/S quiet guard is deleted** (rule 15), with its profile thresholds. This reverses the parts of the 2026-10-26 and 2026-10-27 rulings that made it.

## 1. What happened

The Tor lane's Pi run of 2026-10-31 (shekyl-dev `8049fe7`, `data/tsr-acceptance/`; `TOR_SUPERVISOR.md` §7) put 10 minutes of silent drops on a running node:
- every session closed 2 min 10 s in;
- all six white entries were demoted to gray during the block, and came back to white 10 minutes after it;
- recovery took 2 min 44 s after the unblock, against 6 s in the refuse block of 2026-10-25, because the six cooled addresses were waiting out their first cooldown;
- Tor said nothing about its network the whole time (`TSR-Q14`).

**Why the guard failed.** `Dialer::ladder` (`shekyl-dialer/src/owner/quiet.rs:67`) returns the first step only after K unopened attempts and S elapsed: K = 13, S = 364.5 s on Tor.
- Each silent drop takes the full 105 s `SocksTimeout`, with 5 in flight, so the block produced 12 failures. K was never reached.
- Worse, every failure before a count-based guard engages is judged against its address. A white test that fails on the climb is demoted (`partition.rs:454`, `fail_test`'s white arm). With six white entries and K = 13, an outage can empty white before the guard can act.
- Tuning K and S lower narrows that window, but cannot close it.

**Why it matters: the eclipse lever.** White is the node's tested, known-working set. Fill draws white first, and gray is where an attacker plants addresses. Anyone who can black-hole this node's traffic for a few minutes can empty white:
- a hostile local network or ISP;
- a censor;
- whoever runs the captive network the node is on.

The node then refills from a gray list in which honest and planted addresses are drawn uniformly. That is the attack in `CLEARNET_ECLIPSE_THREAT_MODEL.md`, reached through an outage rather than through flooding.

## 2. Why one rule cannot serve every connector

The same observation means different things on different connectors.

**Tor has one link.**
- Every stream goes through the guard connection. An on-path observer cannot see which onion a stream is for, so cannot drop selectively.
- So any stream that opens during an attempt shows the whole link works.
- A silent block fails everything at the window, and every reply is the proxy's word.

**Clearnet has a path per destination.**
- An on-path party can pass its own session and drop every other. A working session to one peer says nothing about the path to another.
- Dials are fast, one at a time (bound 1), so there are rarely concurrent attempts to read.
- The OS can tell a local failure (no route, address unavailable) from a refusal by the far end.

A rule like revision 1's ("the link worked if a session was held or a stream opened") is sound on Tor but means something different on clearnet. So the judge is one, and the meaning comes from the connector.

## 3. What already exists

- **Each connector already marks its failures.** It stamps every close cause with marks (`shekyl-transport-layer/src/cause.rs`): `RETRY` (`:143`), `NAMES_DESTINATION` (`:146`), `PROVES_MISBEHAVIOUR` (`:149`), `WINDOW_TIMEOUT` (`:156`).
  - This is Rick's 2026-10-24 rule that each layer owns its rejections.
  - The Tor connector's reply table is `shekyl-tor/src/replies.rs` (`proxy_reply_marks`, `:89`).
  - Clearnet stamps its own causes, `LocalClose` among them (`shekyl-clearnet/src/drive.rs`).
- **Each connector already has its backoff values.** The dial profile (`shekyl-transport-layer/src/profile.rs`) holds retries, waits, the cooldown ladder and the window.
- **The judge ignores what a failure means.** `Peerlist::apply` (`shekyl-peerlist/src/peerlist.rs:594`) drops an address on proven misbehaviour. Every other failure goes to `fail_test`, the same way whatever the marks say.

The plumbing is there; the judgment does not read it. This work makes it read it.

## 4. The design to bring back (Round 0)

### 4.1 The vocabulary (closed, the dialer's)

Every failure a connector produces is one of three kinds of evidence:

| Evidence | What it says | What the judge does |
| --- | --- | --- |
| **Destination** | The far end answered or is shown absent: clearnet refused or reset; Tor `0x05` | Counts against the address: the ladder steps, a white address is demoted |
| **Local** | This node's side failed: no route, address unavailable, proxy unavailable, our own close | Never counts against the address. Say what it does instead: a first-step cooldown, or the draw released at the pace |
| **Uncertain** | Could be the link or the destination: a clearnet timeout; Tor `0x06` at the window; probably `0xF0` | Counts against the address only when the connector's corroboration (4.2) held during the attempt. Otherwise it is treated as Local |

The vocabulary belongs to the dialer. A connector that needs a meaning outside it is a design round, not a new local rule.

### 4.2 What each connector declares

As data, beside the dial profile:
1. **The mapping:** every close cause and reply it produces, mapped to one evidence kind. Extend the marks (`cause.rs`) rather than add a parallel channel. `NAMES_DESTINATION` is already half of it.
2. **Its corroboration:** what shows the link worked during an uncertain attempt, from a short closed list the dialer can observe. For example:
   - a stream opened on this connector during the attempt;
   - a session on this connector carried traffic during the attempt;
   - none.
   - Proposed for Tor: a stream opened during the attempt.
   - For clearnet: the wargame in §5 decides it.
3. ~~**Its clearing rule**~~ — **amended (Rick, 2026-10-31): clearing is the judge's behaviour, not a declaration.** The first corroborating event clears the excused cooldowns of addresses with no counted failure. *Rejected (rule 21):* a per-connector clearing rule; each connector's input is its corroboration declaration. *Reopen when* a connector shows signs of life while its dials still cannot succeed, so the first event must not clear. *Records-was: "what restores addresses that cooled on uncorroborated failures once the link is shown working. Proposed: the first corroborating event clears them."*
4. **Its backoff values:** what the profile already has (retries, waits, ladder steps and cap, window). Each value says what it means for this connector's failures.

### 4.3 What the judge guarantees, for every connector

These are invariants. Each is tested against every connector's declarations, not promised per connector:
1. **An outage never empties white.** A failure without corroboration never demotes white.
2. **An outage never climbs the ladder.**
3. **Recovery doesn't wait on outage cooldowns.** The first sign of a working link clears cooldowns taken on uncorroborated failures. The target: the blackhole recovery comes down toward the refuse block's 6 s.
4. **Proven misbehaviour still drops,** on a destination-authenticated connector, as today.
5. **The probe never counts as link evidence.** The probe of the node's own onion is not a session and not a peer dial (`TOR_SUPERVISOR.md` §4.5). Only the supervisor reads it.
6. **Nothing is inferred about Tor's network.** The judge reads only the dialer's own observations (`TSR-Q14`), and the supervisor's posture line is unchanged.

### 4.4 Deletions (rule 15)

- the quiet guard: `owner/quiet.rs`'s ladder choice and its unopened count;
- the profile's quiet thresholds: `QuietThreshold`, `quiet_attempts` and the derived S;
- the supervisor's `quiet_after`, which reads Tor's S today. It needs its own source, and the Tor lane rules that;
- the §97 rows and the brief text that state K and S.

## 5. Wargame in the Round 0 return

- **A total blackhole of the access link, both connectors.** Nothing corroborates, so white stays and nothing climbs.
- **Clearnet, an on-path party who passes only its own session.** That session corroborates, so honest addresses that time out are judged and demoted.
  - That party already decides which peers this node reaches on clearnet. Demoting them records what it already enforces. It is the permanent clearnet residual, since clearnet can encrypt and recognize but never authenticate.
  - Say whether clearnet's corroboration should exclude inbound sessions, or idle sessions, to make that party pay more.
- **Tor, an attacker who keeps one session open during a block.** On Tor an on-path party cannot pass one onion stream and drop the rest. Show which corroboration (stream opened, or session traffic) holds against an attacker-held idle session.
- **A dead-onion flood while the node is isolated.** Uncorroborated failures cool at the first step and never climb, so the node keeps redialing dead addresses. Show this does not starve honest addresses: cooling still rotates the draw, and the first success restores normal judging.
- **A slow link (the 40 kbit case).** Streams open late but do open. Show slow success still corroborates, and nothing here makes a slow link look like an outage.
- **A healthy clearnet link.** Show its behaviour is unchanged.

## 6. Tests that can fail (each names the edit that makes it fail)

1. **A Tor silent-drop block,** five dials in flight, no stream opened and no session receiving: every white test that fails stays white and, having no counted failure, cools for `outage_retry`; a gray address with counted failures cools at its current rung. Today it fails, because K is never reached.
2. **The same block, with the link shown working on both sides of a failure:** a sign of life within δ before the failure (another attempt's stream opening, or a byte received on a counted session) **and** one within δ after it. The failing white is demoted. With life on one side only, it is excused.
3. **After the block, the first corroborating event:** addresses with no counted failure that were excused during the block are drawable at once; addresses with counted failures keep their rung.

*Records-was (to 2026-10-31, amended on #1229's review to the ruled bracket, `OE-D5`, and hold the rung, `OE-D6`): test 1 "cools at the first step"; test 2 "one concurrent dial opens a stream mid-attempt: the failing white is demoted", which supplies neither the after-failure sign of life nor necessarily the before-failure one; test 3 "addresses cooled during the block are drawable at once".*
4. **A Destination failure with no corroboration:** it still counts against the address (a refusal is never excused as an outage).
5. **A Local failure:** never counts against the address, on either connector.
6. **Boot with the network down:** no demotion, no climb.
7. **The probe never corroborates.**
8. **Every invariant in 4.3, run against each connector's declarations.** A connector cannot leave a failure unmapped: each observation it can make is a variant its stamping matches totally into a `DialFailure` (the judge's own type, `DIALER_OUTAGE_EVIDENCE.md` §2.2), so an unmapped one does not compile; a test pins every row. *Records-was: "a test that a cause with no declared evidence kind fails the build", which the type now guarantees.*

## 7. Live (Pi; claim it in the ledger after the Tor soak's claim ends, about 2026-11-07 06:17Z)

Repeat the Tor lane's blackhole case (10 minutes of silent drops while running) and the refuse case. Add a clearnet blackhole. **Added 2026-10-31 (Rick):**
- blackholes of 10, 20 and 30 s;
- pulsed loss, 25 s down and 15 s up, for ten minutes;
- both connectors, counting white demotions;
- on Tor, the time from unblock to the first stream open.

Leave in-flight Tor attempts to run (TSR-Q14: Tor retries inside its own window).

**Pass criteria (the gate):**
- no white demotion in the 10-minute blackhole, on either connector;
- recovery after that blackhole within the refuse case's order of magnitude;
- an unchanged eclipse-share result: the in-flight bound's 90 % gray test, under the new judge.

**Measured, not gated:** the 10, 20 and 30 s blackholes and the pulsed-loss run measure the bracket's residual (`DIALER_OUTAGE_EVIDENCE.md` §3.3): a failure inside an outage shorter than about 2δ (≈ 30 s) is bracketed by signs of life on both sides and counts by design, so these can demote white with a correct judge. Their white demotions and Tor's unblock-to-first-open time are recorded; **their acceptance thresholds are Rick's to set** from the readings. *Records-was (2026-10-31, split on #1229's review): every case under "no white demotion in any case", which the ruled residual contradicts for the short and pulsed runs.*

## Out of scope

- the Tor supervisor's thresholds and posture line, beyond giving `quiet_after` a source the Tor lane rules;
- the in-flight bound;
- the fill rules and the draw;
- the targets.

No push without Rick's go-ahead.

## Records-was

- **Revision 1 (2026-10-31)** proposed one rule for every connector: a failure counts only if a session was held or a stream opened during the attempt. Rick ruled one judge, with each connector declaring how its failures are judged.
- **The K/S guard (ruled 2026-10-26 and 2026-10-27)** was one mechanism fed per-connector numbers. The 2026-10-31 blackhole showed it engaging too late on Tor.
