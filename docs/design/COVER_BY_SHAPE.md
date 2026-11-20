# Round 0: cover by shape — 2026-11-19

**Status: OPEN — Round 0 (Rick, 2026-11-19). The direction in §2 is ruled; the decisions in §6 are open.** Nothing here is built. Read at PR #1431 head `88864d06` and dev `d86ef32f`; the file and line citations in §3 are at those trees. This is a second approach to wire-observer cover, beside the volume build of #1431, which is held unmerged (`CBS-E4`).

**Identifier family:** `CBS-`, registered at birth (rule 94) in [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2. `CBS-R1`–`CBS-R6` are the rulings of §2; `CBS-E1`–`CBS-E7` are the open decisions of §6.

## 1. The idea (Rick)

A link has an ordinary texture: small messages, irregularly spaced. A transaction is the one thing that does not fit, because it leaves as one large lump. Cut every transaction into pieces the size of ordinary messages and let them out at an ordinary pace. The link then looks somewhat busier for a moment, and there is no object for a watcher to find.

Rick: "If a transaction (or part of one) is indistinguishable from the rest of the traffic, it essentially hides all of the things at minimal extra cost."

## 2. What is ruled — RULED 2026-11-19 (Rick)

- **`CBS-R1` — the goal is shape, and shape is count-agnostic.** Count-denial is a volume metric and is not a requirement here. This supersedes the goal #1431 states in its `TOR_COVER_POSTURE.md` §1, "a watcher must never be able to tell that a stem was sent", and [`DAEMON_RELAY_PRIVACY.md`](DAEMON_RELAY_PRIVACY.md) §31.2's reading of count-denial as a free win.
- **`CBS-R2` — what is protected is who originates a transaction, not the transaction.** Every node carries every transaction eventually. The originator is the one node that sends it before receiving it.
- **`CBS-R3` — universal.** The mechanism works on Tor, encrypted clearnet, I2P and possibly Nym. The relay shapes; connectors carry; nothing is derived from one transport's framing.
- **`CBS-R4` — no slowing the network.** Volume cover slowed the network and capped how much could stem, which made each movement more distinct. Real traffic is the cover. **A stem leaves at once** (Rick, 2026-11-20): it is never held for a timer or a slot, and its pieces start leaving when it arrives.
- **`CBS-R5` — break the big package up; do not pad the small ones.** No padding unit.
- **`CBS-R6` — cover is best effort under an operator's upload cap** (ruled earlier the same day, on #1431).

## 3. What the code and data show

1. **TRC-1's watcher scored bytes per window on the guard connections** ([`trc1_guard_connection_20261112.md`](../benchmarks/trc1_guard_connection_20261112.md) §5). Share of the node's own sends above the other windows' 99th percentile: 82.6 % at 0.1 s, 3.2 % at 1 s, 6.2 % at 10 s. The transaction was exceptional only at 100 ms.
2. **The same table's ranking figure stayed high** (AUC 0.93 at 1 s, 0.82 at 10 s). A window holding a transaction still ranks above a typical window. So the data shows "not exceptional at one second", not yet "indistinguishable".
3. **That reading is one node with a Tor relay on a quiet testnet.** A node without a relay has quieter links.
4. **A stem leaves at once on an uncovered session; a broadcast waits for its link's random flush timer** (mean 2.5 s outbound, 5 s inbound; `shekyl-relay` `graph/mod.rs:909`).
5. **Every broadcast goes to every peer except its source** (`graph/mod.rs:924`).
6. **Stem successors are drawn only from sessions this node dialed** (`graph/stem_draw.rs:127`). Stems travel dialer to listener. On average a node is the successor of two peers; a node with no inbound connections relays no stems.
7. **Nothing announces a successor choice.** A node learns it only when a stem arrives. #1431 gives it away: the receiving peer sees the windows.
8. **The wire code already builds fragments** (`shekyl-levin`, `fragmented_notify`), and each session's send queue takes separate items that other traffic can interleave with.
9. **Clearnet's record layer encrypts record lengths** ([`P2P_TRANSPORT_LAYER.md`](P2P_TRANSPORT_LAYER.md), the record layer).
10. **Each second of per-hop wait cost about four minutes of embargo** in #1431's derivation. Dev's figure is about 8.5 minutes a fire; #1431's is about 27.
11. **Block notices and timed syncs are regular and small** (about every 120 s and 60 s per link). Their sizes, and the texture of a link generally, are not measured.
12. **How fragments reassemble today** (`shekyl-levin`, `fragment.rs` and `reader.rs`, read at dev `ac63d95d`):
    - The builder cuts one message into fragments of one equal size and zero-pads the last. Unequal or unpadded pieces need a builder change (`CBS-R5`).
    - The reader takes a fragment body of any length, so it needs no change for unequal pieces.
    - Each session has one reassembly buffer. A begin flag restarts it, so two fragmented messages cannot interleave on one session, and a second begin discards the first message's pieces.
    - Ordinary messages can arrive between fragments: the buffer is kept across them.
    - The buffer is bounded only by the session's packet limit, 100 MB after the handshake, and by no time limit. Nothing bounds how long an incomplete message is held (the "junk fragments" row of §7).
    - A fragment's header carries flags and a length, and no message identifier.

## 4. The design in outline

1. Every transaction message, stem or broadcast, leaves as pieces of ordinary size at an ordinary pace.
2. Nothing else is added: no windows, no cadence, no carrier, no padding, no upload floor, no opt-out.
3. Whether a quiet link also needs filler is decided by measurement.

## 5. What the volume build got wrong, for the record

- It capped stem capacity at about the network's whole design load.
- It marked the two stem links to any watcher, and told each successor it was one.
- Its cost was fixed and its benefit unmeasured.
- It coupled cover rate to stem delay, and stem delay to the embargo.

## 6. Open decisions — OPEN, not ruled

### `CBS-E1` — measure the texture first — RULED 2026-11-20 (Rick): measure first, built as its own PR

- **Problem.** "Ordinary size" and "ordinary pace" are not known numbers.
- **Recommendation.** Before any build, record per session, by message type, each send's size and time, on the test fleet, on every connector in use. The daemon knows its own messages, so this needs no packet capture. Piece size and pace are derived from it.
- **Universality.** "Ordinary" is defined by Shekyl's own message set, which is the same on every connector, not by one transport's traffic.

#### The measurement — RULED 2026-11-20 (Rick); the run is proposed

**What exists** (read at dev `ac63d95d`):

- A message-size record on clearnet sessions only (`shekyl-clearnet`, `sizes.rs`), in a measurement build (`measurement-spans`, held out of release builds by `scripts/ci/check_measurement_spans.py`).
- It writes one line per Levin message: size, direction, session number, and the command's class (control, transaction relay, block relay, bundle relay, sync). It keeps no command name on purpose.
- Its one time stamp for a sent message is taken when the writer takes the message off the session's queue (`shekyl-capped-stream`, `copy.rs`, the `encode` call). That is neither the time its sender queued it nor the time the write returned.
- Tor sessions have no such record.

**What is proposed.**

1. **One line per message, both directions, on every connector.** The record moves from `shekyl-clearnet` to where both connector drives can use it, and the Tor drive feeds it as the clearnet drive does. A line carries: connector, session number, direction, message type, size in bytes (header and payload), and its times.
2. **Three times for a sent message:** queued by its sender, taken off the queue by the writer, and written (the write of its last byte returned). The first needs a stamp carried with the queue item in a measurement build. **One time for a received message:** when its last byte arrived.
3. **Message type, not class — RULED 2026-11-20.** The line names the command. This reverses the existing record's choice to keep the class only, and it is needed: piece size is derived from the sizes of particular message types. A transaction message's line does not say stem or broadcast: the record reads message headers only, and that flag is in the payload.
4. **Nothing that identifies a transaction or a peer.** No transaction identifier, no address, no content. The session number is local to the node and to the run.
5. **Fragments are recorded as they are sent,** one line per fragment, typed as a fragment, so a later run with pieces on reads the same way.
6. **Where it runs.** Nodes with no Tor relay, on every connector in use: clearnet under the record layer, and Tor. Each run's host load is recorded beside it. The Tor node is paired with TRC-1's guard-connection sampler for the same hours, so the daemon's written times and the watcher's view of the guard connections are read together.
7. **Output.** A reducer turns the lines into the figures below, per connector and per link. Its sizes are plaintext, before the record layer's overhead, and it says so in its output.
   - bytes per window at 0.1 s, 1 s and 10 s, by the written time, in the layout of TRC-1's table (`trc1_guard_connection_20261112.md` §5), so the two line up;
   - the size distribution by message type;
   - the distribution of gaps between sends, by type and overall;
   - the lag from queued to written.
8. **It stays a measurement build, with no wire change.** The feature gate and its CI check are extended to the new owner. A release build's behaviour is unchanged and its record stays zero-sized.
9. **It is its own PR, aimed at alpha.12.** If it is not merged when the cut is ready, the cut goes without it. #1431 and `CBS-E2`–`CBS-E7` are not in alpha.12.

**Limits, stated before measuring.**

- "Written" is when the operating system accepted the bytes, not when they left the host. On Tor it is when the local Tor client accepted them; what a watcher sees on the guard connections is later and is Tor's to schedule. TRC-1's guard-connection counters stay the watcher's view on Tor.
- A test network's traffic is thinner than a live network's. The texture read here is a lower bound on how busy a link is.

**The run — PROPOSED 2026-11-20 (Rick may change it).**

- 72 hours on three test-fleet nodes with no Tor relay: one clearnet under the record layer, one Tor only, one both.
- Recording starts with the node, and the record notes when the fleet reports synced after the wipe.
- TRC-1's wallet send loop runs on one node, with some hours at a higher send rate.

### `CBS-E2` — does a relay wait for the whole transaction? — OPEN

- **Problem.** If each hop collects all pieces before forwarding, a hop adds about the spread (roughly a second), and the embargo grows by roughly four minutes a fire.
- **Options.** (a) Collect, verify, then forward. (b) Pass pieces on as they arrive.
- **Wargame of (b).** A relay forwards bytes it cannot verify, so junk travels a stem's length at no cost to the sender; and a node cannot record or embargo a transaction it has not yet identified.
- **Recommendation.** (a), with the embargo re-derived.

### `CBS-E3` — filler on a quiet link — OPEN

- **Recommendation.** None by default. Run the pass mark with pieces on; add filler only if it fails, and then as a lone dummy of real size on a uniformly drawn outgoing connection, dropped by the receiver.

### `CBS-E4` — PR #1431 — OPEN (held unmerged, Rick 2026-11-19)

- **Recommendation.** Hold unmerged. A salvage PR keeps what does not depend on windows: the `local_observer_visibility` reading, the uniform own/relayed timer, the stem recorded when its write lands.

### `CBS-E5` — the pass mark — OPEN

- **Recommendation.** TRC-1's own-against-other test, per connector, at 0.1 s, 1 s and 10 s, on a node with no Tor relay. Thresholds to be ruled. The keep-or-drop draft is revised to match.

### `CBS-E6` — large transactions — OPEN

- A 97 KB transaction is about six times the modal one. Under this design it is simply more pieces over a longer spread. Whether that spread is itself a mark depends on `CBS-E1`'s numbers.

### `CBS-E7` — one fragmented message at a time per session — OPEN

- **Problem.** Two fragmented messages cannot interleave on a session (§3 item 12). If every transaction is spread over about a second, a link carries about one transaction a second each way. That is about five times the design load, but it is a ceiling, and `CBS-R4` rules against slowing the network.
- **Options.** (a) Fragments carry a message identifier, so trains interleave. (b) The pace shortens as the queue grows: a busy link does not need the spread, because its own traffic is the cover.
- **Not yet recommended.** (a) changes the fragment header and the reader's one buffer, and makes the bound on incomplete messages per peer a count as well as a size. (b) changes no wire format, but makes the spread depend on load; whether that dependence is itself readable is a `CBS-E1` question.

## 7. Wargame

| Attack | What the watcher uses | Under this design |
| --- | --- | --- |
| Lump size at 100 ms (TRC-1) | 14 KB in one slot | Closed if no slot holds more than an ordinary message. To be measured. |
| Busier second | More bytes in a second than usual | Reduced: over 1 % of ordinary seconds already carry as much. Open on quiet links (`CBS-E3`). |
| Swell out of silence | The originator sends before it receives | Reduced to the "busier second" case. |
| Train of pieces | Regular spacing of equal pieces | Open: the pace must be irregular and the sizes ordinary, or the train is the new lump (`CBS-E1`). |
| Stem link marked | Steady traffic on two links | Closed: nothing is steady. |
| Successor learns its role | Dummy windows arriving | Closed: nothing is sent unless a stem is. |
| Watcher on two nodes | Compares both ends of a link | Unchanged. Stated limit; Dandelion++ does not claim it either. |
| Malicious successor | Reads the stem flag | Unchanged. Dandelion++'s own floor. |
| Junk fragments | Sends pieces that never complete | Needs a bound on incomplete transactions held per peer. |

## 8. Not yet read

Message sizes by type; the embargo derivation re-run at a one-second hop spread; I2P's and Nym's current specifications.
