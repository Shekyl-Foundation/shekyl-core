# Round 0: cover by shape — 2026-11-19

**Status: OPEN — Round 0 (Rick, 2026-11-19). The direction in §2 is ruled; the decisions in §6 are open.** Nothing here is built. Read at PR #1431 head `88864d06` and dev `d86ef32f`; the file and line citations in §3 are at those trees. This is a second approach to wire-observer cover, beside the volume build of #1431, which is held unmerged (`CBS-E4`).

**Identifier family:** `CBS-`, registered at birth (rule 94) in [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2. `CBS-R1`–`CBS-R6` are the rulings of §2; `CBS-E1`–`CBS-E6` are the open decisions of §6.

## 1. The idea (Rick)

A link has an ordinary texture: small messages, irregularly spaced. A transaction is the one thing that does not fit, because it leaves as one large lump. Cut every transaction into pieces the size of ordinary messages and let them out at an ordinary pace. The link then looks somewhat busier for a moment, and there is no object for a watcher to find.

Rick: "If a transaction (or part of one) is indistinguishable from the rest of the traffic, it essentially hides all of the things at minimal extra cost."

## 2. What is ruled — RULED 2026-11-19 (Rick)

- **`CBS-R1` — the goal is shape, and shape is count-agnostic.** Count-denial is a volume metric and is not a requirement here. This supersedes the goal #1431 states in its `TOR_COVER_POSTURE.md` §1, "a watcher must never be able to tell that a stem was sent", and [`DAEMON_RELAY_PRIVACY.md`](DAEMON_RELAY_PRIVACY.md) §31.2's reading of count-denial as a free win.
- **`CBS-R2` — what is protected is who originates a transaction, not the transaction.** Every node carries every transaction eventually. The originator is the one node that sends it before receiving it.
- **`CBS-R3` — universal.** The mechanism works on Tor, encrypted clearnet, I2P and possibly Nym. The relay shapes; connectors carry; nothing is derived from one transport's framing.
- **`CBS-R4` — no slowing the network.** Volume cover slowed the network and capped how much could stem, which made each movement more distinct. Real traffic is the cover.
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

### `CBS-E1` — measure the texture first — OPEN

- **Problem.** "Ordinary size" and "ordinary pace" are not known numbers.
- **Recommendation.** Before any build, record per session, by message type, each send's size and time, on the test fleet, on every connector in use. The daemon knows its own messages, so this needs no packet capture. Piece size and pace are derived from it.
- **Universality.** "Ordinary" is defined by Shekyl's own message set, which is the same on every connector, not by one transport's traffic.

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

Message sizes by type; the embargo derivation re-run at a one-second hop spread; I2P's and Nym's current specifications; how `fragmented_notify` reassembles and what it bounds.
