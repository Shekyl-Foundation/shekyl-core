# Tor cover posture — cover on every encrypted session; the relay is Tor payback

**Status: RULED 2026-11-15 and 2026-11-18 (Rick). The mechanism
(`CVR-R1`–`CVR-R6`) is built in #1431; the pass mark (`CVR-R7`) is not yet
measured. Last verified 2026-11-19.** Identifier families `TRC-1…TRC-n` (the
relay posture and its measurement) and `CVR-R1…CVR-R10` (the cover rulings),
both in [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md). Decision
authority: Rick.

**What this document records.** A node's cover against a watcher of its
links is the relay's cover carrier, on by default, on every encrypted
session whose timing a watcher can see, Tor's included. Running a Tor relay
is not cover. It is how Shekyl pays Tor back for what it uses (§4).

**Why.** Until 2026-11-15 this document recorded the opposite for Tor: that a
node whose Tor client was also a non-exit relay was covered by the relay's
volume, and needed no carrier. TRC-1's guard-connection reading
([`trc1_guard_connection_20261112.md`](../benchmarks/trc1_guard_connection_20261112.md),
#1388) measured it and found no cover. Every circuit a node builds for itself
goes through its three entry-guard connections, and those carried 0.47 % of
the relay's bytes. Summed over the three, in 100 ms windows, the window
holding one of the node's own transactions ranks above a random other window
93 % of the time (AUC 0.928), and 82.6 % of those windows are above the other
windows' 99th percentile. At 1 s and 10 s the AUC is 0.93 and 0.82. Limits:
one relay and one daemon on a quiet testnet, kernel counters read every
100 ms, six guard epochs over 38.7 h. The reading measured a node with a
relay; without one, a client's guard connections carry only its own traffic,
so the same follows by reasoning.

Terms: a *channel* is one stem slot's emission stream. A *window* is one
emission, always `WINDOW_BYTES`, real or dummy. *Cover* is the carrier
running on a channel. A *watcher* is anyone observing a link without being
the peer on it.

---

## 1. The ruling

**The goal: a watcher must never be able to tell that a stem was sent. The
receiving peer knows; nobody else does.**

Encryption hides what a send says. It does not hide when a send happens or
how big it is, and that holds on every encrypted link, clearnet under Noise
as much as Tor. So the cover is a carrier that makes a stem's send
indistinguishable from the sends around it, on each such link.

- **`CVR-R1` — cover is on by default, with an operator opt-out**
  (`relay-cover`, `on` unless set `off`). Cover starts as soon as a stem
  slot holds a covered peer; it does not wait for sync. A node that opts out
  relays no stems: a stem it receives is broadcast at once. Its own
  transactions still stem, bare, and it warns on every start. **The opt-out
  is provisional** (Rick, 2026-11-18): once cover is tested and validated it
  will not be optional; otherwise cover is dropped (§8).
- **`CVR-R2` — the relay reads the connector's `local_observer_visibility`
  cell.** There is no cover class. The class stored the 2026-09-04 ruling
  that Tor's volume was its cover as a fact of the connector.
- **`CVR-R3` — cover runs on a session that is encrypted and whose
  connector declares its timing visible, and on no other condition.** Tor
  sessions carry cover, the own-origin slot included. A plaintext clearnet
  session carries none while `dev-clearnet-encrypt` exists. The carrier adds
  no encryption; what it needs from the record layer under it is in
  [`P2P_TRANSPORT_LAYER.md`](P2P_TRANSPORT_LAYER.md), "What cover needs from
  the record layer".
- **`CVR-R4` — the cadence is memoryless, with no admission threshold.** The
  wait before a channel's next window does not depend on the time since its
  last. A one-window message is sent whole or not at all. After each epoch
  boundary a channel sends `MAX_FRAGMENTS − 1` more windows to the peer it
  was bound to, starting nothing, then takes its new peer, so a message that
  started before the boundary finishes on its own peer, and the switch comes
  at the same point whether or not one was in flight. Peer loss still
  restarts a half-sent message.
- **`CVR-R5` — the cover budget is 8,192 B/s per node, the one stated
  number of the schedule.** The mean cadence is derived from it: channels ×
  window ÷ budget, 5 s. A channel holds at most one full-size message pending
  (`MAX_FRAGMENTS` windows). The embargo is derived with every stem hop
  carrier-paced, at a channel's expected occupancy on a network of at least
  100 nodes (an Assumption): 1638 s on Tor and 1320 s on clearnet, inside
  the 30-minute limit. The budget counts plaintext: a connector's framing
  is that connector's cost, and the cadence is the same on every connector
  (Rick, 2026-11-19). A `p2p-upload-max` below twice the budget, 16 KiB/s,
  refuses the start and a runtime change; the factor is a stated rule, not a
  derivation. Cover is best effort under the limit: a window takes its turn
  at the link's limiter and nothing is reserved for it
  (`DAEMON_RELAY_PRIVACY.md` §93.2a).
- **`CVR-R6` — in the stem phase, a transaction leaves a covered session
  only inside a window.** Before its first send, a node's own transaction
  waits for its window; it is not broadcast as a fallback and not sent bare
  on a covered session. A relayed stem that cannot get a window ends its
  stem phase there and is broadcast. The embargo's reshape goes through the
  alternate's channel, or the stem phase ends. The emission tick does not
  wait on relay work. Broadcast (fluff) is outside the rule: it uses the
  ordinary connection to every peer, uncovered. Where no cover runs the rule
  does not apply, and a stem to a plaintext session goes bare. A node with
  no connector configured makes its own transaction public at once; a node
  whose peers are all down holds it, because mining its own unbroadcast
  transaction and publishing the block would attribute it to that node.
- **Once sent, a node's own transaction is treated as a relayed one**
  (Rick, 2026-11-18). It draws its embargo from the same random timer, and
  when that fires it takes the same two steps: a reshape to the alternate,
  then a broadcast. Any reaction that differed for own transactions would
  let a stem peer sort them out, by dropping every stem from a node and
  watching what the node does. The own/relayed distinction exists only
  before the first send, where a hold is not seen at all. This reverses
  RX-1's fixed origin retry interval.
- **Own transactions ride a stem slot** (Rick, 2026-10-08;
  `DAEMON_RELAY_PRIVACY.md` §95.3, §98). When a node has hidden-address
  sessions, slot 0 is reserved for them and the local source pins on its
  peer. A link that carried only originated traffic was ProxyMark's root
  cause.

## 2. What is built

The carrier lives in `shekyl-relay-privacy` (`params::carrier`, the cadence
and the embargo derivation) and `shekyl-relay` (the schedule, the queue and
the task that sends). Each node runs two channels, one per stem slot,
whatever connectors its sessions ride; a second network adds no channel and
no bytes. Every window is 20,480 bytes, sized to hold the modal transaction
whole at any tree depth. The carrier's schedule, each channel's binding and
tail, its queue and the session writers it sends on run in their own task,
so a busy relay owner delays what it hands the carrier and never a window:
on 2026-11-05 an owner blocked behind the pool's commit stopped the cover on
both channels for 28 s and 32 s.

The values, their bases and what would re-measure them are
`DAEMON_RELAY_PRIVACY.md` §97's rows ("Carrier cadence", "Smallest network
the embargo is sized for", "Carrier backlog cap").

### 2.1 COVER_TRAFFIC §1.7 Axis 3 stands

[`COVER_TRAFFIC_RESTORATION.md`](COVER_TRAFFIC_RESTORATION.md) §1.7 Axis 3
(ruled 2026-08-23) said relay cover cannot substitute for the carrier at any
measured relay traffic level. Between 2026-09-04 and 2026-11-15 this document
withdrew that for Tor; the measurement restored it. Its standing rule is
unchanged: **no protocol constant may be derived against an assumption of
relay cover.**

## 3. Why a carrier, on Tor as on clearnet

Substitution cover — an envelope the node emits whether or not anything is
happening — gives a watcher nothing to tell a stem from, by construction.
The alternative considered for Tor was volume: a relay's cells hiding the
node's own. It fails on where the cells travel. A node's own circuits enter
Tor through its guard connections, and relayed traffic rides other
connections, so the volume is not on the links the node's sends are on
(the reading above). Nothing a node can configure moves it there.

### 3.1 What cover costs

8,192 B/s sent per node while it has covered stem peers, and as much
received from the peers that stem to it: about 0.7 GB a day each way. A
transaction's stem takes a mean of 5 s per hop to leave. A transaction
dropped at its first hop is re-stemmed after one embargo draw (mean 1638 s
on Tor, 1320 s on clearnet) and broadcast after a second.

## 4. Reciprocity — a net contributor, not a consumer

This is a first-class term of the ruling, not a side benefit.

A Shekyl node using Tor consumes relay capacity: onion-service load
(introduction points, rendezvous circuits, HSDir publication), overlay P2P
transit, and archival shard fetches. That consumption scales with adoption and
is paid for by relay operators who did not volunteer to carry it.

**The project's commitment is that Shekyl contributes more Tor relay capacity
than the Shekyl network consumes, and that the contribution is legible.**

Two mechanisms, and the first does not depend on operator uptake:

- **Foundation-operated non-exit relays, sized to exceed measured network
  consumption, and grown as the node count grows.** These are operated by an
  entity whose IP is already public and whose enumerability is not a property
  the design protects, which is the same argument that already applies to seed
  nodes. A named Foundation relay family in the Tor consensus (`MyFamily`),
  contributing above what the protocol consumes, is a defensible public
  position in a way that diffuse per-node contribution would not be. Tor's
  path selection then refuses to place two family members in one circuit.
- **Operator-run non-exit relays**, documented as the cover posture and as a
  contribution, adopted per operator.

**Sizing is owed, not inherited.** With cover on by default, a node's Tor
consumption has a floor that does not idle: the carrier's 8 KiB/s on its stem
sessions, on top of onion-service and fetch traffic. The offset commitment is
the durable part; the number that satisfies it is derived from the testnet
measurement (§8, `CVR-R9`) before it is quoted anywhere.

**Path selection stays entirely Tor's.** Never route Shekyl traffic through
Shekyl-operated relays, and never prefer them (`COVER_TRAFFIC_RESTORATION.md`
§1.7 constraint 1, preserved). Otherwise an adversary running Shekyl nodes
acquires relay positions *on Shekyl circuits*, which is the worst outcome
available here.

## 5. Constraints on the relay

A relay is opt-in. It is payback, not cover, and nothing in the protocol
reads whether an operator runs one.

**Non-exit only.** Middle or guard relay, no exit policy. Stated explicitly
wherever this is recommended, because "run a relay" without the qualifier
will get an operator an exit relay and an abuse complaint.

**A separate Tor from the node's, preferably on a different host**
(`CVR-R9`). A relay's throughput and uptime are externally measurable by
design — that is how bandwidth authorities work — so a relay on the node's
host can link the node's onion address to the host's IP by uptime, and a
relay in the daemon's process turns the daemon's uptime into a remotely
probeable signal. The daemon's managed Tor stays client-only; relay flags
are never added to it.

**Not load-bearing on any protocol path.** No consensus rule, no mechanism
and no default behaviour may assume the node's operator runs a relay.

**Never prefer Shekyl-operated relays.** Path selection stays Tor's (§4).

## 6. What this discharges, and for whom

With cover on, which is the default: for every node, on each of its
encrypted stem sessions, a watcher of that link cannot tell a window that
carries a stem from one that carries nothing, subject to the pass mark (§8).
Not for a node that opted out, and not on a plaintext clearnet session.
Any document that claims more must be corrected rather than reinterpreted.

## 7. Known residuals

Stated here and in the user documents.

- **Cover marks a link as running Shekyl.** Fixed-size windows at a
  recognisable rate are a signature.
- **On clearnet, a watcher sees which of a node's connections are stems**,
  because cover runs on those and nowhere else, **and knows the last stem
  hop of a broadcast transaction**: the broadcast starts when the stem
  arrives. Earlier hops stay hidden. A hold before the broadcast would blur
  this; it is not built, and reopens before genesis (§8).
- **On Tor a watcher cannot separate a node's connections**, so neither of
  those applies there.
- **A transaction of two or more windows completes its stem less often than
  a one-window one.** The embargo is sized for one window per hop.
- **A transaction dropped mid-stem takes longer to recover than without
  cover.** The embargo is sized for carrier-paced hops, and a node's own
  transaction waits out the same embargo as a relayed one: a mean of
  1638 s on Tor to the reshape, and a second draw to the broadcast.
- **Under a low upload limit with sustained uploads, cover falls behind its
  schedule.** A window waits for the limiter and behind what its session
  already has queued. The delay does not depend on what the window carries.
  The lag ends when the session's send queue overflows, which closes the
  session (`DAEMON_RELAY_PRIVACY.md` §93.2a).
- **An opted-out node's own sends are visible to a watcher**, and it gives
  no stem privacy to others.

## 8. The pass mark, what reopens, and the measurement behind this ruling

**The pass mark (`CVR-R7`), fixed before measuring.**

- Deciding test: real against dummy windows at 100 ms, scored from each
  window's emission time. Pass: AUC upper 95 % bound ≤ 0.55, and the share
  of real windows above the dummies' 99th percentile has an upper 95 % bound
  ≤ 2 %.
- Timing test, same bound: the interval before a real window against the
  interval before a dummy.
- At least 2,000 real sends.
- Labels come from the carrier through the measurement-spans feature only. A
  default build never logs them.
- Valid only if the instrument can see: with cover off, under the same load,
  transaction-carrying windows against all others give AUC ≥ 0.80. Otherwise
  the run is void. Own against relayed (cover off) is reported separately.
- Reported, not deciding: 1 s and 10 s, each guard alone, the quiet run, the
  receiving side, both ends together, the inbound-to-outbound matcher, and
  the two reopen measurements below.
- Per network: Tor sums the guard connections of the managed client-only
  Tor. Clearnet is per stem-peer connection, and waits for encryption to be
  on.
- Real and dummy windows produce the same Tor cell count.

The instrument and its record are their own change after the mechanism.
It records each window's wire time beside its queue time: the carrier's own
line is the queue time, and a window can wait at the link's limiter after it
(`DAEMON_RELAY_PRIVACY.md` §93.2a).
`PM-3` stays a check under its own row, not the acceptance test
(`CVR-R8`). `DAEMON_RELAY_PRIVACY.md` §96 item 4's test is this pass mark.

**Reopen before genesis** (one row in
[`RELEASE_CHECKLIST.md`](../RELEASE_CHECKLIST.md)), decided together with
the measurement in hand:

- whether cover becomes always-on or is dropped. The intent is settled:
  once cover is tested and validated it is not optional, and otherwise it is
  dropped. The opt-out is provisional until then;
- a hold before a broadcast, to blur the last stem hop on clearnet
  (`CVR-R10`, ruled and removed on 2026-11-18 when the build was cut back to
  its core);
- the budget and cadence, and the upload floor stated beside the budget
  (twice it, 2026-11-19);
- the 30-minute embargo limit;
- what replaces cover, if the pass mark fails and it is dropped.

Two measurements feed it, reported with the `CVR-R7` run: how well a
clearnet watcher picks the predecessor that delivered a broadcast
transaction, split by the node's count of stem predecessors; and how often a
stem of two or more windows completes, against the 90 % the embargo is sized
for at one window.

**The Tor Project is told after the testnet measurement and before mainnet**
(`CVR-R9`), through the existing private channel. The run records: bytes
read and written per day on the managed Tor; cover bytes sent and received;
the hop count as a stated assumption, checked against the circuit types in
use; and the Foundation relays' own byte counts.

**The measurement the earlier ruling rested on** (the `TRC-1` falsifier
chain), kept as the record of why the ruling changed:

1. The relay posture was documented and that operator topology was running.
   **Met 2026-10-06**
   ([`trc1_relay_posture_20261006.md`](../benchmarks/trc1_relay_posture_20261006.md)).
2. Carried traffic was measured across hours and weights. **Met 2026-11-11**
   ([`trc1_carried_traffic_20261012.md`](../benchmarks/trc1_carried_traffic_20261012.md)).
3. If measured cover at ordinary operator scale was insufficient to make
   originated cells indistinguishable, the ruling reopened. **Met
   2026-11-15** (the guard-connection reading, above).

**Reciprocity falsifier.** Consumption is derived from the testnet
measurement (§4) and Foundation relay capacity is sized above it. If
measured consumption exceeds contributed capacity for a sustained period,
capacity is added; the commitment is not satisfied by intent.

## 9. Rejected alternatives

**Relay volume as Tor's cover.** Rejected by measurement (2026-11-15): the
volume is not on the node's guard connections. A second Tor, a shared Tor
and the managed Tor are alike in this; no Tor configuration is cover.

**Every node relays.** Rejected. Making relaying a default puts every node's
IP in a public directory and creates same-host correlation with a hidden
service dialling peers.

**Exit relay.** Rejected. Abuse-handling and legal exposure the project does
not ask of operators.

**A relay in the daemon's process, or in its managed Tor.** Rejected (§5).

**An admission threshold for multi-window messages.** Rejected 2026-11-18
for the epoch tail (`CVR-R4`), which removes restarts at an epoch end
without a probability to choose.

**A backlog bound derived against the embargo limit.** Rejected 2026-11-18
for a simple cap: at the 8,192 B/s budget every queued window adds about
1,000 s to an embargo sized with it present at every hop.

**Preferring Shekyl-operated relays for Shekyl circuits.** Rejected (§4).

## 10. Same-change doc tasks (rule 91)

Discharged with the mechanism's change, #1431:

- This document, restated as the current ruling.
- [`COVER_TRAFFIC_RESTORATION.md`](COVER_TRAFFIC_RESTORATION.md): the
  carrier's scope, budget and status.
- [`DAEMON_RELAY_PRIVACY.md`](DAEMON_RELAY_PRIVACY.md): the Cover bullet,
  §93.2, and §97's carrier rows.
- [`P2P_TRANSPORT_LAYER.md`](P2P_TRANSPORT_LAYER.md): what cover needs from
  the record layer.
- [`INPUT_GRAMMAR.md`](INPUT_GRAMMAR.md) and the generated option table:
  `relay-cover`.
- The user documents' residuals, and
  [`RELEASE_CHECKLIST.md`](../RELEASE_CHECKLIST.md)'s reopen row.
- [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md): `CVR-R1…CVR-R10`.

## 11. A complete-tree fetch can show a holding set — reported 2026-10-22

`ARCHIVAL_SUPPORT_DRAW.md` §8. Each read builds its own circuit
(`SF-D3`). Nothing spreads the fetches of one new holding over time or
across sources, so a complete-tree server asked for many shards of that
holding sees the set. A later bond for the same set is the link the
bond-post delay is there to break. Reported to that round
(`ARCHIVAL_BOND_POST_DELAY.md` §6.1). Not fixed here. BD-Q4's window
width is still open.
