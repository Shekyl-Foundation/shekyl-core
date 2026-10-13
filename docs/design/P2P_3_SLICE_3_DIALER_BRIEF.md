# P2P-3 slice 3 — discovery and the dialer

**Status: REVIEWED — closed 2026-10-12 (Rick), on #1037 (R1–R5 and the
corrections); implementation is PR-3.** Design before code. Rule 26 is
cited. Every PR-3 commit implements this file as it stands at that commit.
*Records-was: OPEN — no implementation starts from this file until a
review of it has closed.*
**UPDATE 2026-10-13 (Rick):** the dialer lives in a new crate over
`shekyl-seam` and `shekyl-peerlist`; the C++ reaches it only through
`shekyl-ffi`. Neither of those two crates depends on the other, and
`Hub::connect` is already `dial.connect` followed by `Hub::adopt`
(`shekyl-seam/src/hub.rs`), so the split this brief asks for is at that
seam. The failed-address predicate is ruled the same day: it reads the
declaration's `destination_authenticated` cell ("Failed-address
memory" below).
**UPDATE 2026-10-13 (Rick), the received peerlist:** no C++ grows for
PWD-I2 or anything else in PR-3. `handle_remote_peerlist` is a
pass-through: the list as it arrived and the session id go to Rust
(`shekyl_peerlist_admit_received`), which reads the session's connector
and direction from the `shekyl-seam` board, applies D3, D-S1, address
validity, R4, the foreign-connector rule and PWD-I2, and answers accept
or refuse. The C++ closes only on refuse. A list on an inbound session
admits nothing and is not `PeerlistRefused`: no score, no failed-address
write, no close. `sanitize_peerlist`, the `P2P_MAX_PEERS_IN_HANDSHAKE`
check and the per-entry connector loop are deleted in PR-3. *Records-was
(2026-10-11): "`sanitize_peerlist` stays with `handle_remote_peerlist`
until slice 4".*

**UNFREEZE (Rick, 2026-10-13):** src/p2p/net_node.inl — `handle_remote_peerlist`'s body is replaced by one call into Rust (`shekyl::received_peerlist`), the line that reads `--allow-local-ip` reads it through `shekyl_peerlist_allow_local_ip`, and `sanitize_peerlist` is deleted. Step 2 (the same day): `detect_self_handshake` reads the dialer's nonce set through `shekyl_dial_take_handshake_nonce`; `set_max_out_peers` hands the cap to `shekyl_dialer_set_out_peers`; `--add-peer` enters the Rust gray list through `shekyl::admit_operator_peer`; the handshake and timed-sync responses take their sample from `shekyl::disclose`; `on_outbound_handshake` is the strand's read of the Rust dialer's handshake result, the lines kept from `do_handshake_with_peer`'s invoke callback, which step 3 deletes. §3.2 (the same day): the dial path is deleted (the table below); the `--add-exclusive-node` parse hands its list to the dialer through `shekyl::declare_exclusive_peers`; the `--seed-node` addresses enter gray through `shekyl::admit_operator_peer`.

**UNFREEZE (Rick, 2026-10-13):** src/p2p/net_node.h — the `sanitize_peerlist` declaration is deleted with its definition; `on_outbound_handshake` is declared (step 2).

**UPDATE 2026-10-09 (Rick):** `COMMAND_HANDSHAKE` carries no address
field on any connector (the handshake-address ruling below, which
replaces "The address we announce"); `disclose_count` is the protocol
constant `DISCLOSE_COUNT = 12` (slice 1 brief D3); the timed-sync
self-insertion is deleted at the cutover.
**UPDATE 2026-10-11 (Rick):** no subnet grouping in the Rust dialer —
the C++ `/24` pass leaves with the dial path and nothing replaces it,
so the PWD-B9 keys proposed as D1 and D2 are withdrawn, not ruled
("The candidate filter" below); **D5 is ruled** — slice 1 increment 3
lands with this slice as one cutover PR (PR-3); address validity moves
to Rust (slice 1 brief §2, "Address validity"). PR-3 is gated only on
this brief's review closing; no derivation and no measurement gates it
(Ruling B).
Lines below were read on `dev` at `f317d979c4` (2026-10-08), which
contains #991 and #1002. `record_addr_failed` takes the address, the
cause, and the reply (`net_node.h:675`). `shekyl_seam_session_cause`
is `rust/shekyl-ffi/src/cause_ffi.rs:55`, declared at
`shekyl_ffi.h:4430`. The C++ read is `net_node.h:229`.
*Records-was: the pin was `d93074d1c4`, and the declaration was
`shekyl_ffi.h:4448`.* This slice mints no identifier family. It is
the §4.2 row rescoped the same day.

**Ruling 2026-10-07 (Rick).** Order: #991 → slice 1 → this slice → RD.
Dialing moves to Rust. No further fixes to the C++ dial path. Slice 4
keeps the inbound handshake state machine and PWD-B1/B2. This slice
owns the outbound dial, the outbound handshake invoke, and the
outcome. Slice 4 owns the phases after a session exists.

The list writer is slice 1's `apply(DialOutcome)`. This slice emits
that value. It does not write gray or white itself.

---

## The composition

One record. Slice 1 reads it for `disclose_count` and the white
floor. This slice reads it for how many sessions to open. A later
ruling of the operating point edits this record, and both briefs move
together.

| Name | Value until a ruled operating point | Owner |
| --- | --- | --- |
| `hidden_out` | `MIN_PROVISIONED_OUT_PEERS` (12, `shekyl-relay-privacy/src/params.rs:203`) | This slice. The hidden-address pool. No hidden session above it |
| `clearnet_out` | `P2P_DEFAULT_OUT_PEERS` (12, `params.rs:179`), written by `set_max_out_peers` (`net_node.inl:2957`; the `arg_out_peers` call is `:621`) | The setter. A cap of 0 stays legal. A positive cap below the floor is refused. Clearnet is not folded into `hidden_out` |
| `DISCLOSE_COUNT` | 12, a protocol constant: the same on every node and every connector (D3, Rick 2026-10-09). Not tied to the outbound target | Slice 1. Replaces `P2P_DEFAULT_PEERS_IN_HANDSHAKE` (250, `cryptonote_config.h:193`) and `P2P_MAX_PEERS_IN_HANDSHAKE` (`:194`) as the sample size and the receiver limit. *Records-was: `disclose_count`, that connector's outbound target* |
| `white_diversity_floor` | `INTERIM_WHITE_DIVERSITY_MULTIPLE` (4) times `DISCLOSE_COUNT`, 48. **R5 (Rick, 2026-10-12): stays 48**, labelled `Assumption`, derived on the Rust path after PR-3; the review's one explicit open point, closed | Slice 1. The refill line (60, D-PR2-2) stays above the floor. The same floor gates disclosure (slice 1 §5) and the fill's keep draws (rule (b)) |

`hidden_out` is the outbound sessions whose connector declares
`address_hidden_from_peer`. On `dev`, `net_node.inl:984` assigns
`shekyl_relay_zone_min_provisioned_out_peers()` to
`max_out_connection_count`. This slice deletes that assignment and
keeps the target at `hidden_out`.

[`TOR_COVER_POSTURE.md`](TOR_COVER_POSTURE.md) and
[`TOR_RELAY.md`](../TOR_RELAY.md) already name that target.
*Records-was: `HOP0_OUTBOUND_TARGET` (4). The records-was comment is
`params.rs:201-202`. At `d93074d1c4`, `net_node.inl:939` still wrote
`shekyl_hop0_outbound_target`.* The 4 read the paper's 4-regular
anonymity graph (Dandelion++ §4.3, Algorithm 2: two outbound edges
plus about two inbound) as the size of the pool the relays are drawn
from. The paper draws those edges from the node's P2P outbound edges
(η = 8 in the simulations; the measured degree is 12).

The simulation plan is [`DAEMON_RELAY_PRIVACY.md`](DAEMON_RELAY_PRIVACY.md)
§95, **APPROVED 2026-10-08 (Rick).** The hidden-address pool and the
total outbound degree are lower limits. Each is at least
`MIN_PROVISIONED_OUT_PEERS`. The total floor is the fail-safe's
measured range (`fluff_return_ms = 3250` at degree 12). The operating
point above those floors, and any ceiling, are not chosen by the
approval. The ceiling comes from resources. `(h, 0)`, including
`(12, 0)`, is a measured case in §95.3. Recommending Tor-only waits
on §96. A total of 16 was an illustration in the §95.2 grid, and that
grid is records-was. It is not a degree this composition uses.

Stem-slot routing is §95.3: one slot from the hidden outbound
sessions, the other from the remaining outbound sessions, the local
source pinned on the hidden slot, relays forwarding with probability
`1 − q`. This slice does not restate a shorter routing. **UPDATE
2026-10-09:** the relay lane landed §95.3 as PR-1 (#1018,
`DAEMON_RELAY_PRIVACY.md` §98); `own_edge()` is deleted and
`NoOwnEdge` is the plan when no outbound session hides the address or
the origin's pin is exhausted. *Records-was: "`own_edge` and `NoOwnEdge`
stay on `dev` until the relay lane lands §95.3."* This slice depends
on nothing in them and does not choose the slot. Vocabulary (§98.11):
*dial candidates* are the gray and white lists; *hidden outbound
sessions* are the address-hiding subset of the live outbound sessions;
a *pin* is a source's frozen set in `StemMap`.

A later connector, I2P included, is a declaration column, that
connector's measured transit added in `verify_cost`
(`shekyl-relay-privacy`), which the declaration reads, and the
connector crate. `shekyl-relay` is not edited. The column's cells are
address hiding, cover class, and that transit. An unassessed transit
is not a stem edge. Its `disclose_count` is its own outbound target
once that target exists. Until then it has no row in this table.

Sharing one cap of 12 across both connectors would move the degree
the fail-safe was measured at. The two targets stay separate.

---

## The fill

One owner, one wake, one dial. **The wake (R3, Rick, 2026-10-12):**
`0.5 s + U(0, 1.0 s)`, mean 1 s — PWD-B2's bounded-uniform shape
(`P2P_2_DISPATCH_BRIEF.md`, cadence jitter) — drawn per dial. It is
labelled `Assumption` in `DAEMON_RELAY_PRIVACY.md` §97's "Dial wake
spacing" row and re-measured on the Rust dialer after PR-3 (Ruling B).
*Records-was: "the jittered spacing ruled on 2026-09-25", shape ruled
and no number.* The spacing has the same shape on every connector.
The connector changes which list is drawn, not the clock. The
60-second housekeeping timer is not the pace. The owner does not block
a p2p io worker.

**The population.** A closed network (`--add-exclusive-node`) is not a
dialer arm (Rick, 2026-10-11): an exclusive list is a network
declaration. The node's candidate set is the named addresses, and the
rules below — the uniform draw, the door, the cap, the clock — run
over that set. Nothing is skipped and nothing is reserved; the
population is smaller. Today the C++ dials the list at
`connect_to_peerlist` (`net_node.inl:2912`, from `connections_maker`
`:2111` at `:2116`), which goes with the dial path. Its help text
(`net_node.cpp:126`, today "Specify list of peers to connect to only")
is rewritten in PR-3 to say that it declares a closed network and to
name only peers the operator controls, because a single exclusive
peer is the first hop of every transaction this node originates. Its
users on `dev`: `scripts/bench/drs_bench.py:328` and
`scripts/bench/ba_t5_session2_run.sh:99`, both loopback test networks.

**Priority nodes — DELETED (Rick, 2026-10-11).** `--add-priority-node`
is deleted in PR-3 as a retired flag refused by name (`REMOVED_FLAGS`,
`src/common/removed_flags.cpp:70`). The deletion takes
`m_priority_peers` (`net_node.h:767`), its parse (`net_node.inl:558`),
the clearnet arm (`:2132`), and the priority half of
`is_priority_node` (`:2906`; its callers at `:1670`, `:1681`, `:1727`
and `:1737` only choose a log level), and the flag rows that still describe the live binary,
`docs/EXECUTABLES.md` and `docs/proxies.md`. `docs/USER_GUIDE.md`
already has no row. PR-3 deletes the flag and those two rows
together. *Records-was: "Exclusive, then priority" — a
reserved outbound slot outside the uniform draw, a guaranteed stem
candidate, redialled forever when unreachable.* Rick: priority nodes
"sound good but essentially bypass all the identity protections we
have built in and provide no actual value." `--add-peer` already
jumpstarts a node; it enters gray and takes its chances in the draw.

**The rule (R1, Rick, 2026-10-12, from the brief's review).** Each
wake, for one connector, takes the first of these that applies. Every
draw is uniform within its list, over addresses that pass the
candidate filter and are not already an outbound session or a pending
attempt on the connector.

- **(a) No kept outbound session on the connector.** The next
  successful dial is kept (`Keep`), whatever the draw. A node with no
  outbound connection keeps its first success. The draw is (b)'s
  (Rick, 2026-10-12): eligible white if white holds at least
  `white_diversity_floor`, otherwise gray if gray holds at least the
  floor; if neither reaches the floor, gray when it holds a drawable
  address, otherwise white. The dial is kept either way. *Records-was,
  the brief's reading: white when white holds an eligible address,
  else gray — struck because a node whose only session drops while
  white is a few early confirms, mostly seeds, would keep from that
  small list.*
- **(b) One or more kept sessions, and under the outbound target.** A
  keep-dial (`Keep`) draws uniformly from eligible white if white holds
  at least `white_diversity_floor`; otherwise from gray, if gray holds
  at least the floor.
- **(c) Otherwise, while white is below the refill line and gray holds
  a drawable address.** Confirm-and-close from gray (`Confirm`): one
  uniform gray draw, the handshake run, the peer's sample admitted to
  gray, `Confirmed`, the session closed in that turn. Adopting it
  inserts a row that does not count toward the target, is not refused
  because the target is met, and is not a reason to close a `Keep`
  row; the strand must accept the payload; the relay is not flipped.
  This one rule replaces the records-was arms 2 and 5 below: it is how
  a thin pool grows before the floors in (b) are reached, and how
  white reaches the refill line while every `Keep` slot is full.
- **(d) Under target, with gray empty** (a network smaller than the
  floor: genesis, a private testnet). Keep from white (`Keep`).

A `Keep` under (a), (b) or (d) is `SessionAccepted`: the outstanding
gray draw moves to white and the session stays; an already-white
address on a session this node opened moves its clock. It is not a
promotion when the draw was white — it re-contacts a white peer this
node is not connected to.

*Termination.* Every confirm under (c) moves an address out of gray —
`Confirmed` to white, `DialFailed` / `PeerlistRefused` dropped (slice
1 §5) — so (c) runs out when white reaches the refill line or gray
empties, whichever first. No peer's answer ends it; a feeder can only
extend it within D-S1's per-session cap. Bans, expiry and white-cap
demotion return asked addresses to gray, so gray is not "only unasked
addresses" (*records-was* wording struck); it is still finite per
wake, and each return is one more confirm at most.

*Wargame, the restart.* Slice 1's restart does not restore white
(§7): a node boots with gray only. Under the records-was arm 2
(confirm-and-close while white was below the floor) every boot held
the node to 48 sequential confirm dials before any session was kept —
sync delayed, its own transactions held (`NoOwnEdge`), 48 onion dials
on Tor, and a start-up burst an observer can fingerprint. Under (a)
and (b) a restart keeps at its first success and fills from the
reloaded gray. A brand-new node, whose gray is only the compiled
seeds, keeps its first success — at most one seed — and then confirms
under (c) until a pool reaches the floor, so the seeds never hold most
of a new node's outbound set, which is what the records-was arm 2's
deletion wargame was protecting.

*Records-was, same day and the day before (arms 2 and 5, struck by
R1).* **Arm 2**, in four readings, all 2026-10-11: (i) a harvest keyed
on identity — both lists empty (`has_no_known_peers`,
`net_peerlist.h:147`) or a fill pass that added nothing, then one
address per wake from the seed list (`get_seed_nodes`, filled at
`net_node.inl:2042`; clearnet once adds `get_ip_seed_nodes`, `:2084`,
after every seed has failed; the `break` after `connect_to_seed`'s
dial is `:2073`), the seed walk leaving with the dial path; (ii) a
harvest keyed on gray below the floor; (iii) that, and the previous
harvest yielded; (iv) confirm-and-close keyed on gray below the floor
and the previous completed confirm-and-close yielding a new gray
address, a failed dial neutral; and last, confirm-and-close keyed on
white below the floor and gray holding a drawable address. Its
wargames: (ii) never terminated on a network smaller than the floor
and let an attacker hold a victim in confirm-only; (iv) let one
hostile peer, answering with only known addresses, end a fresh node's
phase with gray still mostly seeds; deleting the arm outright would
have made the seeds every new node's first outbound peers and first
stem hop (first-spy, new-node eclipse); seeds on white early is
harmless (no outbound slot, nothing disclosed below the floor). Rule
(c) keeps what those readings were for and (a)–(b) remove the
start-up cost the last reading carried. **Arm 5**, `confirm_gray`: at
target with white under the refill line, one gray draw with aim
`Confirm`, closed in that turn — the same dial as (c), reached only at
target; (c) is that rule with the at-target condition removed. **Arm
3**, `draw_white`, and **arm 4**, `draw_gray` (white under the refill
line, under target, arm 3 not applying), are (b) with the floors
added.

*There is no harvest.* A handshake reply carries the peer's
disclosure sample, so a confirm-and-close dial learns addresses
exactly as the harvest did; the harvest's one difference — no white
write — existed for the seed special case, now withdrawn (slice 1
§3). `DialAim` is `Keep` and `Confirm`. `DialOutcome::HarvestDone` is
DELETED: the variant, its `address()` arm, its `apply` arm and its
test are gone. *Records-was: left for PR-3 because the removal was
called more than one line.*

The next wake can run while a dial is still in flight. Until
`Hub::adopt`, that address is not an outbound session and a `Keep`
row does not yet exist, so the rules above would not see it. The
dialer keeps a pending attempt from the moment `dial_channel`
returns until every `DialOutcome`. A pending attempt's address and
host are not candidates. A pending `Keep` counts toward the outbound
target. A pending `Confirm` does not. The set is empty
after the outcome, including failure before adopt.

**The `Keep` count is the dialer's.** It is adopted `Keep` rows plus
pending `Keep` attempts, per connector. It is not `Board::count`
(`rust/shekyl-seam/src/registry.rs:175`), which counts every outbound
row on the connector, a `Confirm` row included, and knows nothing of
a pending attempt. Lowering the cap at runtime, today
`release_outbound` from `set_max_out_peers` (`net_node.inl:3176`,
defined at `:2240`), moves to the dialer and closes `Keep` rows only.
A `Confirm` row is never what the cap closes.

**Interim in-flight bound: one dial per connector (2026-10-08).** The
fill is one dial per wake, so the interim needs no measurement. It is
measured and raised on the Rust path after the cutover, into the
register (`DAEMON_RELAY_PRIVACY.md` §97). Wargame: at boot, hidden
sessions open one at a time. The node's own transactions are held
(`NoOwnEdge`) only until the first hidden session, so originating does
not wait for all 12.

*Records-was: `connections_maker` (`net_node.inl:2134-2157`) branches
on `P2P_DEFAULT_WHITELIST_CONNECTIONS_PERCENT` (70,
`cryptonote_config.h:200`). Below that share of the cap it tries white
then gray. At or above it, gray then white.* PWD-I4 derives against
this loop. The 70% schedule is what the C++ does until this slice
deletes it.

---

## The dial

`Hub::connect` (`rust/shekyl-seam/src/hub.rs:274`) is the composition
of two operations that already have different jobs. The implementation
PR splits them. `Hub::connect` stays the composition, so the seam
tests keep one call. Callers of `Hub::connect` today are
`hub_tests.rs`. Production dial is still C++ `zone.m_connect`.

| Operation | What it does | Who calls it |
| --- | --- | --- |
| `dial_channel` | `Dial::connect`. Returns the channel. No row, no `adopt` | This slice's dialer |
| `Hub::adopt` (`hub.rs:288`) | Registers a channel the connector already admitted. `write_row` (`:414`) inserts the row with `established: false` and `phase: Arming`, then posts `Post::Established` (`:41`) | The handshake owner, after every well-formed response (*records-was:* that is not a harvest; there is no harvest since 2026-10-11). `Post::Established` creates the strand handler. It is not promotion and it is not the relay flip |
| `Hub::connect` | `dial_channel`, then `adopt` | Seam tests. The outbound dialer does not call it |

The dialer passes a `DialAim` with the channel. The aim is input. The
outcome is what the dial became. The owner does not infer one from
the other.

```rust
enum DialAim {
    Keep,
    Confirm,
}
```

*Records-was: a third aim, `Harvest`, absorbed into `Confirm`
2026-10-11 (the fill, rule (c)).*

The handshake owner reads frames on the channel. Those frames are not
`Post::Deliver`. On any failure before a well-formed response, the
owner does not adopt. There is no strand and no established delivery.

On a well-formed response whose aim is `Keep` or `Confirm`, the owner
adopts, then posts one handshake result. That post is not
`Post::Deliver`. `Post::Deliver` is one whole Levin message
(`hub.rs:48`) and the adapter feeds those bytes to `handle_recv`. A
handshake response arriving that way has no invoke handler on the
new strand and is the "no active invoke" close. The handshake owner
already decoded the response on the channel. The result post carries
the support flags, including zero, and the sync payload, and the
strand reads those fields. It does not parse them as a Levin
response. The post is the first strand post after `Post::Established`,
ahead of any later frame. The owner does not call
`process_payload_sync_data`.

In that one strand turn, before any later frame, the strand accepts or
refuses. On accept, `Keep` sets the session-established flag, flips
the relay registry (`shekyl_relay_zone_on_session_established`), and
the dialer emits `SessionAccepted`. `Confirm` does not flip the relay
and does not leave the row: the owner closes in that turn and emits
`Confirmed`. A confirm dial is never a stem edge. The outbound target
is the count of `Keep` rows on that connector. A `Confirm` row is
outside that count for the turn it exists. On refuse, either
aim closes the session and the dialer emits `PayloadRefused`. Nothing
enters the relay's peer set before the payload is accepted, and a
confirm dial does not enter it after.

The dialer does not wait on that turn. A slow strand cannot stall the
next wake. Until `SessionAccepted` or `Confirmed`, the session may be
up and the address is still gray.

**The clock (Rick, 2026-10-08).** The outbound handshake's only clock
is each connector's transport gap, from channel established to session
established ([`P2P_TRANSPORT_LAYER.md`](P2P_TRANSPORT_LAYER.md) D3, and
D11 item 5), armed by the connector with D9's values: clearnet 1.430 s
and Tor 2.6 s, set today in `transport_spans` (`net_node.inl:3527`,
`:3529`) and labelled `CppPath` in `DAEMON_RELAY_PRIVACY.md` §97. The
connector arms it when the channel exists. `dial_channel` returns that
channel with the gap already armed. Adopting later does not start
another clock. The 5 s Levin invoke timer
(`P2P_DEFAULT_HANDSHAKE_INVOKE_TIMEOUT`, armed at `net_node.inl:1414`)
is not the dialer's clock. Its outbound arm goes with
`do_handshake_with_peer` at the cutover. The owner does not arm a
second invoke timer. The gap firing is the connector's close. The
owner holds that cause. It does not call `shekyl_seam_session_cause`.
That read is the post-handshake race in the known-defect section.
*Records-was: the armed duration was the 5 s invoke timeout until D9
derived the per-connector value; D9 had already derived it. Before
that, the 5 s invoke was described as having no outbound-handshake
role.*

Test: no frame after the handshake reaches the strand before that
handshake result. With a refused payload, the relay registry never
holds the session. A second wake while a `Keep` dial has not yet
adopted does not dial that address or its host, and does not open
another `Keep` that would put the target over when both adopt.

---

## `DialOutcome`

One report. The dialer emits it on every end path. Slice 1's `apply`
is the only writer of gray and white, and the match is total. The
dialer is the only writer of the failed-address memory, and it reads
the same value. The score owner subscribes to `PeerlistRefused` and
writes neither store. The handshake task does not call
`add_host_fail`. That function stays: inbound and the open
`cryptonote_protocol_handler` row still use it. It is in flight, not
dead.

```rust
enum DialOutcome {
    DialFailed { address: NetworkAddress, cause: CloseCause, reply: u16 },
    PeerlistRefused { address: NetworkAddress },
    PayloadRefused { address: NetworkAddress },
    Confirmed { address: NetworkAddress },
    SessionAccepted { address: NetworkAddress },
}
```

| Variant | When the dialer emits it | List (`apply`) | Failed-address memory | Score |
| --- | --- | --- | --- | --- |
| `DialFailed` | The channel never reached a well-formed response, or `network_id` is not ours (`net_node.inl:1370`). The cause is the one the connector closed with | An outstanding gray draw is dropped. A white address stays white | Tor only (R2): written when `implicates_address` is set for that cause and reply, which on clearnet it never is. A `network_id` mismatch is `LevinHandshakeRejected`; on Tor it writes, on clearnet it does not. *Records-was: written on every connector* | No subscription. The mismatch does not call `add_host_fail` |
| `PeerlistRefused` | `handle_remote_peerlist` refuses (`net_node.inl:1377`). Same close as `LevinHandshakeRejected` | Same as `DialFailed` | Same as `DialFailed` with `LevinHandshakeRejected`: Tor only (R2) | The score owner subscribes. A peerlist this node refuses is the event the score records |
| `PayloadRefused` | Levin was well-formed and the strand refused the sync payload | No promotion, no demotion, no gray drop. An outstanding draw stays gray | Not written. The peer answered | None |
| *`HarvestDone` — DELETED (Rick, 2026-10-11; no crate symbol)* | *Records-was: a harvest handshake completed, the session closed, no `adopt`.* Absorbed into `Confirmed`: a confirm-and-close dial learns the peer's sample as a harvest did and writes white. The variant, its `address()` arm, its `apply` arm and its test are gone. *Records-was: left for PR-3 as "more than one line"* | — | — |
| `Confirmed` | Aim `Confirm`. The strand accepted the sync payload. The owner closed in that turn. The relay was not flipped | An outstanding gray draw moves to white and `last_observed` is set. No session remains. Anything else writes nothing | Cleared for that address | None |
| `SessionAccepted` | Aim `Keep`. The strand accepted the sync payload and the session stays | An outstanding gray draw moves to white and `last_observed` is set. An address that is already white, on a session this node opened, moves the clock. Anything else writes nothing | Cleared for that address | None |

*Records-was: slice 1's `handshake_confirmed` and `draw_failed` were
three endings sharing one name. Neither spelling is in Rust. They are
not the contract.*

A valid Levin response is not `SessionAccepted`. The strand can refuse
the payload after the response was well-formed.

Wargame: a peer completes the handshake and sends a payload the sync
driver refuses. `SessionAccepted` on the Levin response would put that
peer on white and hand the next draw an address this node drops on
sight. `PayloadRefused` keeps the peer on gray. The report does not
block the dialer. A session that dies before the report is not white.
A peer whose payload we refuse is never a stem edge.

---

## The handshake request

`do_handshake_with_peer` (`net_node.inl:1329`) fills
`COMMAND_HANDSHAKE` before the invoke. The sync payload is one field.
The request also carries `network_id`, the support flags we send, and
a self-connection nonce. *Records-was: "the address we announce" —
struck 2026-10-12; the handshake carries no address field on any
connector (the handshake-address ruling below).*

**Sync payload.** `get_payload_sync_data`
(`cryptonote_protocol_handler.inl:469`) reads the core on the caller:
height, top id, the ideal hard-fork version at that height, and
cumulative difficulty, low 64 and top 64, then adds one to the
height. The handshake request carries that `CORE_SYNC_DATA`.

The dialer does not call the core. The core publishes that snapshot
when the tip changes. The handshake reads the latest snapshot. A tip
that moves while the handshake is in flight stays the snapshot the
request already took. The fields are public chain data.

**Handshake address — RULED 2026-10-09 (Rick).** `COMMAND_HANDSHAKE`
carries no address field on any connector. A node's own dialable
address is one uniform member of that connector's disclosure
population (slice 1 brief §5a), with no special position; our clearnet
entry is included when it is known, as today. A node discloses nothing
on a connector until its eligible white list reaches
`white_diversity_floor`. The timed-sync self-insertion
(`net_node.inl:2717` to `:2735`, `outgoing_to_same_zone` inserting
`zone.m_our_address` into the peerlist it sends) is deleted at the
cutover; it is in the deletion table below. The ProxyMark rerun
(`DAEMON_RELAY_PRIVACY.md` §99, PM-1) measures step 1 — identity in the
cached sample — against this design, with per-boot and persistent
onions, shortly after restart and in steady state; its result decides
whether the onion stays per-boot (PWD-E7). This ruling replaces the
section that follows, kept as records-was of what `get_local_node_data`
does on `dev`.

**Mixed versions on the running testnet (checked 2026-10-13, PR-3).**
epee's `serialize_map<false>` discards each field's load result and
`END_KV_SERIALIZE_MAP` returns true, so an alpha node that receives a
handshake with no `address` reads it as the default address (type
invalid, port 0): `derive_advertised_endpoint(observed, 0)` is
nothing, and nothing is recorded. A PR-3 node reading an alpha
handshake ignores the key: `find_storage_entry` looks up only the
names asked for, and the Rust codec's `from_section` does the same.
The handshake interoperates both ways; the peerlist count does not (an
alpha node sends up to 250 entries, a PR-3 node refuses a list over
`DISCLOSE_COUNT`). **The testnet always upgrades all at once (Rick,
2026-10-13): no mixed-version handling and no release-note warning.**
*Records-was: "the release notes must ask testnet operators to upgrade
together".*

**The node's own address (Rick, 2026-10-13).** Tor: the per-boot onion
goes from `shekyl-tor`'s publish result to `Peerlist::set_own_address`
on the Rust side (`daemon_tor_ffi.rs`), and the operator onion of
`--anonymous-inbound` goes through `shekyl::note_own_address`, the one
replaced line. Clearnet stays dial-only in PR-3: the node does not know
its own public host, a host-0 address is non-global and `disclose`
drops it, and no public-host option is added in C++; the dialer logs at
startup that clearnet is dial-only until a public address is
configured. How a clearnet node learns its address is open: operator
configured, or learned from peers and proved by self-dial with the
nonce. Neither is implemented. The C++ `m_our_address` keeps its two
writers because `get_announced_address` reads it for the operator's
inbound-state log line and six unit tests do; the two dial-path readers
(`is_self_dial`, the candidate loop) go in step 3.

**The address we announce — SUPERSEDED 2026-10-09 (records-was).**
`get_local_node_data`
(`net_node.inl:2477`) writes it. The address is this node's own
address on the connector being dialed. The declaration decides the
shape. The rule does not name a connector.

- The declaration says our address is not hidden, the node is
  reachable on that connector, and inbound is open
  (`max_in_connection_count > 0`). The request carries a port only.
  The host is zero. For a connector that does not hide our address,
  the port is `m_external_port` when set, otherwise
  `m_listening_port` (`get_local_node_data`, `net_node.inl:2504`).
  The receiver pairs the port with the host it saw on its own socket.
- The declaration says our address is hidden, the node is reachable
  there, and inbound is open. The request carries this node's address
  on that connector. When that address is not a reachable address, the
  request carries that connector's unknown placeholder.
- Inbound is 0, or the node is not reachable on that connector. A
  hidden connector carries its unknown placeholder. A connector that
  does not hide our address carries a zero address. Nothing dialable
  is announced.

Wargame (records-was with the section above): a handshake whose
connector hides our address carries this node's address on that
connector, or the unknown placeholder. It does not carry the clearnet
port. A clearnet port on that handshake links the hidden identity to
the clearnet one. Under the ruling the handshake carries no address at
all, so the join it guarded against has no field to ride.

**`network_id` and the flags we send.** The same `node_data` carries
`m_network_id` and that connector's `support_flags`, the two
assignments after the address in `get_local_node_data`. Those are
what we send. The response's support flags are the section below.

**`HandshakeNonceSet`.** One set per connector, owned by the dialer.
The nonce is 32 random bytes, minted for this attempt
(`mint_recorded_handshake_nonce`, called at `net_node.inl:1347`,
defined at `:1497`). It is inserted before the request bytes are
written, and erased on every end path. The scope guard at `:1348` is
that lifetime in C++. The set moves to Rust with the dialer.

Until slice 4, the C++ inbound check (`detect_self_handshake`, called
at `net_node.inl:2789`, defined at `:1536`) reads it through
`shekyl_dial_take_handshake_nonce`. The query takes the inbound
session's connector and the nonce, returns whether that connector's
set held it, and erases it. The connector is the inbound session's,
not one the request names. The set contains the nonce before the
request bytes are written, because our own listener reads the request
before the dial's invoke can finish. Detection is that order, not a
timer. `detect_self_handshake` stays until slice 4. It is in flight.
The C++ mint and erase are deleted with the outbound function, because
the Rust set is the one the FFI read consults.

Test: a dial to our own listener is detected, and the session is not
kept as a peer.

---

## The candidate filter

Before a dial, `make_new_connection_from_peerlist`
(`net_node.inl:1789`) rejects a candidate. Rust takes every kept row.
A row that is not in this table, and not in the pending paragraph
under it, is dropped with the C++ dial path.

| Filter | Disposition | Reason |
| --- | --- | --- |
| Our own address (`zone.m_our_address`, and `is_self_dial` on a seed) | Kept, as one rule | A dial to ourselves is not a peer. The seed-specific `is_self_dial` was the C++ seed path's own copy of the check, needed because that path bypassed the peerlist; with seeds in gray (slice 1 §3) the one own-address rule covers them (exception audit, absorbed) |
| One outbound per host (`has_outbound_connection_to_host`) | Kept | One outbound session per host on that connector |
| Peer already in use (`is_peer_used`) | Kept | A second session to an address we already have |
| Banned (`is_remote_host_allowed`, `net_node.inl:243`) | Kept | Calls `shekyl_ban_remaining_ns` (`seam_ffi.rs:706`). A return of 2 is banned. The check is already Rust |
| Recently failed (`is_addr_recently_failed`) | Kept, Tor only (R2, 2026-10-12) | This slice's failed-address memory, which clearnet never writes; on clearnet the row is vacuous and a candidate is never skipped for a past failure |
| One candidate per host while the list is built | Kept | A host that advertises many ports is not drawn more often. The port kept for a host is chosen uniformly, not first in list order. The address that is dialed is still host and port |
| White-list index weighted by `last_seen`, and the cap of the 20 most recent (`net_node.inl:1948`, weighted pick `:1970-1974`) | Dropped | The uniform draw already ruled. A last-seen weight is the eclipse lever in the wargame below |
| Address validity (`peerlist_manager::is_host_allowed`, `net_peerlist.h:273`; *records-was* also `sanitize_peerlist`, deleted in PR-3, 2026-10-13) | Kept, in slice 1, at admit (Rick, 2026-10-11) | A network-learned address — a received peerlist, an inbound advertisement — is refused at slice 1's `admit_gray` unless dialable on the public internet, and a received list that carries one is refused whole (`PeerlistRefused`, R4); `disclose` never includes a non-global address (slice 1 brief §2, "Address validity"). Not a dial-time filter: a gray or white address is global or operator-named, and operator-named addresses (`--add-peer`, an exclusive list) are dialed whatever the range; priority nodes are deleted. `--allow-local-ip` is the one override, for private test networks |
| The `/24` subnet pass, both passes (`net_node.inl:1842-1933`, public zone only) | Dropped (Rick, 2026-10-11) | No subnet grouping. The draw is slice 1's: uniform over eligible addresses, and an address is a host and a port, not a `/24`. See the ruling below |

**No subnet grouping — RULED 2026-10-11 (Rick).** The C++ `/24` pass
(`net_node.inl:1842-1933`: the subnet-limited first pass and the second
pass that lifts the limit when the first yields no candidate) leaves
with the C++ dial path, and nothing replaces it. The draw is slice 1's,
uniform over eligible addresses; an address is a host and a port, not a
`/24`. So the two PWD-B9 keys this brief carried — (i) the
occupied-subnet set is outbound sessions on that connector only;
(ii) IPv6 that is not v4-mapped is grouped by `/32` — are **withdrawn,
not ruled**, and with no grouping rule there is no fallback question
(the proposed D1a). *Records-was: the keys were proposed as D1 and D2
of the 2026-10-08 close-out brief and sat here as "Pending Rick, not a
kept row" from `5ceb44a9`; they were never ruled until now.* The one
place a prefix still matters is the clearnet reconnect throttle's IPv6
key ([`P2P_TRANSPORT_LAYER.md`](P2P_TRANSPORT_LAYER.md), "Clearnet
reconnect throttle"), which is decided with `N` and `T` after the
cutover. *Reopen if* §99's PM-2a
([`DAEMON_RELAY_PRIVACY.md`](DAEMON_RELAY_PRIVACY.md)), run with a
many-address adversary on clearnet, shows occupation beyond the
attacker's share of honest addresses.

---

## Seeds, and the confirm-and-close dial

`connect_to_seed` (`net_node.inl:2032`) and `just_take_peerlist` were
one disposition in the C++: a harvest — the handshake runs, the
response peerlist is admitted to gray, the session is closed, no
`adopt`, no white. In Rust that disposition is rule (c)'s confirm-and-close
(`Confirmed`): the same handshake, the same sample admitted to gray, the
same close, and the drawn address moves to white as any confirmed draw
does. *Records-was, same day: `HarvestDone` writes no white for any
address; before that, white changed through `HarvestDone` for the
Foundation fleet.*

**Seeds are ordinary peers (Rick, 2026-10-11).** The compiled seed
addresses enter gray at each start as operator-named addresses do, and
reach white only through a drawn dial's `SessionAccepted` or
`Confirmed`. The peerlist a seed returns is network-learned, under
slice 1's address-validity check and D-S1's cap. The harvest is
absorbed into `Confirmed` (the fill, rule (c), R1): a node with no
outbound session keeps its first success, whatever the address; then,
while white is below the refill line and gray holds a drawable
address, draws that no floor admits to a keep are confirm-and-close.
The seed list is not an input to the dialer. *Records-was (2026-10-11):
while white is below the diversity floor and gray holds a drawable
address, every fill draw is confirm-and-close.* The exception audit
([`P2P_3_IMPLEMENTATION_ROUND.md`](P2P_3_IMPLEMENTATION_ROUND.md) §8,
row 7) records the arm as absorbed into `Confirmed`. *Records-was (same
day): the arm was an open point for this brief's review, pending a
decision whether it survived at all.*

The C++ gray probe is not that dial either. `gray_peerlist_housekeeping`
(`net_node.inl:3336`, declared `net_node.h:713`) dials one random gray
peer through `check_connection_and_handshake_with_peer` (`:1715`),
which calls `do_handshake_with_peer` with `just_take_peerlist`
(`:1735`), closes (`:1752`), and on success the caller writes white
(`:3363`) without keeping the session. It does not consult the
outbound cap. An exclusive list skips it. That probe is the ancestor
of arm 5, and it is deleted with the dial path: the function, the
60-second interval (`m_gray_peerlist_housekeeping_interval`,
`net_node.h:756`, the `idle_worker` call at `net_node.inl:2307`), and
the comment at `:1091`. Leaving them would dial gray on a second
clock, including while white is already above the refill line. Rule
(c) confirms only while white is under that line, and only after the
strand accepts the payload. The gray dial that keeps a session is
`make_new_connection_from_peerlist` (`:1789`) through
`try_to_connect_and_handshake_with_new_peer` (`:2019`,
`just_take_peerlist` false). That is a keep under (a), (b) or (d).
*Records-was: "arm 5" and "arm 4".*

A confirm the strand accepts is `Confirmed`, whether reached under
(c) with the pool thin or with every `Keep` slot full. One that fails
is `DialFailed` or `PeerlistRefused`, with the connector's cause.
*Records-was: a completed harvest was `HarvestDone`, deleted 2026-10-11.*

---

## Support flags

The handshake response carries `support_flags`. That value, including
zero, is what the handshake result hands the strand.
`try_get_support_flags` (`net_node.inl:1435`, defined at `:2677`) asks
again when the field is zero. The field is optional on the wire
(`KV_SERIALIZE_OPT`, default 0), and the second invoke is how an
omitted field was recovered. Shekyl sends the field. Zero is the
peer's answer. The dialer does not own a second command.

The inbound call (`net_node.inl:2837`, inside `handle_handshake`) is
the same ask. Slice 4 deletes it for this reason. This slice deletes
the outbound call. The function and the inbound call stay. They are
in flight.

---

## Failed-address memory

The key is the host and the port, the address that was dialed. A
refused port is not evidence about another port on that host. The C++
keys `addr.host_str()` only (`net_node.h:282`). That host key is
records-was.

The memory is not kept across restarts. It is the process map
`m_conn_fails_cache` (`net_node.h:788`). `store_config` writes the
peerlist and does not write this map. A restart dials again.

**Clearnet writes no failed-address memory (R2, Rick, 2026-10-12).**
On clearnet a refused dial is a TCP RST, and NN being unauthenticated,
an active path attacker can also forge `LevinHandshakeRejected`.
Either would suppress an honest address for an hour and refuse it at
gray admission — the forgeable-reset class D-S1 already keeps away
from bans (`P2P_TRANSPORT_LAYER.md`, the reconnect throttle), and the
memory's own doc names the lever: forgetting shrinks the dial set, and
a shrunken set favours whoever is feeding us addresses
(`shekyl-transport-layer/src/cause.rs:170`). So on clearnet
`implicates_address` returns `false` for every cause. `apply` still
drops the failed gray draw (slice 1 §5), and a dead white address is
bounded by the 24-hour expiry. The memory remains for Tor's
destination-naming causes: the replies `0x04 0x05 0xF0 0xF1 0xF2`,
which come from our own Tor process, not from the path, and a rejected
handshake, which on Tor comes from the service the onion address names
(2026-10-13, below).

**PR-3 code change (Rick, 2026-10-13):** `implicates_address(self,
connector)` counts a destination-naming cause on a connector whose
declaration says the destination is authenticated. It reads the
`destination_authenticated` cell of the connector declaration (Tor:
one-way; clearnet: no, NNhfs authenticates no one) and does not match
the connector by name. The destination-naming causes are
`LevinHandshakeRejected`, and `ProxyRefused` with a reply in `0x04 0x05
0xF0 0xF1 0xF2`. `DialFailed` is not one: on Tor it is this node's
SOCKS port. So on clearnet no cause counts, and on Tor exactly six do:
the rejection and the five replies. The cell already existed in
`shekyl-transport-layer/src/declaration.rs`; nothing was added to the
table. Its tests: clearnet, no cause counts; Tor, exactly those six and
no other kind; and the answer follows the cell for every connector.
*Records-was (2026-10-12, PR-3's first reading): on Tor only the five
replies counted, with `LevinHandshakeRejected` left out. That came from
the PR-3 brief's "the Tor memory is written only for the five replies",
which was the reviewer's imprecision, not a ruling. Records-was before
that: "the Tor arms are unchanged", which also kept `DialFailed`
writing on Tor.*

Windows come from `failed_addr_cache::window` (`net_node.h:263`).
Tor starts at the short window and doubles, capped at the hour.
*Records-was: clearnet is the hour.*

`implicates_address` decides the write, on `DialFailed` and on
`PeerlistRefused`. On Tor a rejected handshake and an onion reply in
`0x04 0x05 0xF0 0xF1 0xF2` write the memory. *Records-was: only the
onion replies.* A refused connect, a handshake timeout, a peer close, a
local failure,
a clearnet proxy reply, and — since R2 — every clearnet cause do not.
`PayloadRefused` does not. `Confirmed` and `SessionAccepted` clear the
address. *Records-was: a refused dial and a rejected handshake wrote
it on every connector.*

Slice 1's gray admission refuses an address the memory holds (an onion
address, after R2), and a banned one (`handle_remote_peerlist`,
`net_node.inl:2472`). Until this slice lands, slice 1 takes that
predicate from the C++ cache. This slice replaces where the predicate
comes from.

---

## What the C++ still calls into Rust, and which slice deletes each call

**UPDATE 2026-10-13 (Rick, PR-3 step 2).** After the cutover these are
the C++ calls into the Rust peerlist and dialer. Each is a line the C++
already had, replaced by one call. None returns list state for the C++
to hold. *Records-was: three calls — `admit_gray`, `disclose` and the
nonce query — and "a fourth call is a finding"; the finding is this
table.*

| Call | C++ site | Deleted with |
| --- | --- | --- |
| `shekyl_peerlist_admit_received` (a received list) | `handle_remote_peerlist`, one call | slice 4 |
| `shekyl::admit_operator_peer` (`--add-peer`) | the `--add-peer` loop in `init` | the daemon-config slice |
| `shekyl::disclose` (the sample for a response) | `handle_handshake`, `handle_timed_sync` | slice 4 |
| `shekyl_dial_take_handshake_nonce` (the self-connection check) | `detect_self_handshake` | slice 4 |
| `shekyl_dialer_set_out_peers` (`--out-peers`, the anonymity caps) | `set_max_out_peers` | the daemon-config slice |
| `shekyl_core_publish_tip` (the tip the next handshake carries) | `Blockchain::update_next_cumulative_weight_limit` | the DRS store cutover, or the chain-sync slice |
| `shekyl_dialer_handshake_verdict` (the strand's accept or refuse) | `zone_server::on_strand` | the chain-sync slice |
| `shekyl::note_own_address` (the operator onion of `--anonymous-inbound`) | the `m_our_address` assignment in `init` | the daemon-config slice |

The per-boot onion does not cross: `shekyl_daemon_tor_publish` hands
it to the lists on the Rust side. The operator onion does cross:
`shekyl::note_own_address` is the adapter of the
`shekyl_peerlist_set_own_address` config push (the §3.4 row below;
Rick, 2026-10-13). *Records-was (2026-10-13, step 2):
`shekyl_peerlist_set_own_address` existed with no caller.*

**The dial blocks its owner's thread — ACCEPTED for PR-3 (Rick,
2026-10-13).** The timing engine owns the wake (R3): the owner loop
arms its next deadline and blocks on `wait_wake`. Once woken, the
thread blocks on the TCP dial and on the handshake read until the
connector's gap deadline ends them; the dial itself is not an engine
event. With the in-flight bound at one dial per connector that thread
is the bound, so nothing waits behind it. Reopen criterion: if the
post-cutover in-flight bound is raised above one, the dial moves into
the connector as an event-driven step, and the owner loop stops
holding a thread across it.

## Measured after the cutover, on the Rust path

Dial pacing, the handshake gap per connector (D9), and the in-flight
bound are measured after the cutover, on the Rust dialer, into the
register (`DAEMON_RELAY_PRIVACY.md` §97, Ruling B). Then the white
floor, the refill line, `DISCLOSE_COUNT` and the per-session intake cap
(the per-source share is folded into it, slice 1 brief D-PR2-1) are
re-derived from those readings. No derivation and no measurement gates the
cutover PR; a number taken with the C++ dial path in front would be
thrown away.

## What else the cutover moves to Rust

Values Rust reads through C++ move to Rust in the cutover, so
retuning them no longer means editing C++. Each move removes the C++
lines; it does not add a second copy.

- `transport_spans` (`net_node.inl:3504`, declared `net_node.h:776`;
  the D9 deadlines, the send-queue cap, the shutdown wait, the thread
  budget) moves into `shekyl-transport-layer`. The three C++ call
  sites (`:967`, `:1127`, `:1158`) go with it.
- The hidden outbound cap assignment (`net_node.inl:984` to `:985`,
  `shekyl_relay_zone_min_provisioned_out_peers` into
  `max_out_connection_count`) and `set_max_out_peers`'s floor check
  (`:2957`; the refusal of a positive cap below
  `shekyl_relay_zone_min_provisioned_out_peers`, the F-8b floor) move
  to the dialer, which owns outbound targets. A cap of 0 stays legal
  there.

| What | Where, at `98fbd20acb` | `rg` when it has landed |
| --- | --- | --- |
| `transport_spans` | definition `net_node.inl:3504`, declaration `net_node.h:776`, calls `:967`, `:1127`, `:1158` | `rg -n -e transport_spans src/p2p` returns nothing. Before the move that command hits all five sites |
| The hidden cap assignment and the floor check | `net_node.inl:984` to `:985`; `set_max_out_peers` `:2957` | `rg -n -e shekyl_relay_zone_min_provisioned_out_peers src/p2p` returns nothing. Before the move it hits the assignment and the floor check |

---

## What is deleted

**D5 — RULED 2026-10-11 (Rick).** Slice 1 increment 3 (the C++
peerlist's deletion, slice 1 brief §13) lands with this slice as one
cutover PR, PR-3. The reasoning stands as the close-out brief gave it:
increment 3 alone would have the C++ dial path build `DialOutcome`
from a cause it reads after the strand can reap the row (the known
defect below), would add an FFI surface the dialer deletes one PR
later, and would need an exception to the freeze.

Each name is where it is on `dev` at `f317d979c4`. A deletion check
uses `rg -n -e`. A `\|` inside the pattern is a literal pipe under
ripgrep's default, so that form matches nothing and the gate is green
while the subject is still there (rule 47).

Before the deletion, the same command must hit the sites named in the
row. A before-run that matches nothing means the pattern is wrong, and
the implementation PR stops.

**The freeze (Ruling A, 2026-10-08).** Until the cutover deletes them,
these functions do not change. The list is
`scripts/ci/dial_path_freeze.tsv`, one row per function below plus the
two dial calls inside `idle_worker`, and `scripts/ci/check_dial_path_freeze.py`
compares each body with the base revision on every PR to `dev`: a
change fails, a deletion passes, a row it cannot find at base fails.
Deleted means gone: the row's witness identifier (its bare name, or
`open_outcome` for `zone_server::open`, whose bare name is an ordinary
word) matches nothing under `src/` at head outside comments and
string literals, and the body does not survive under another
signature. A definition moved out of `src/p2p` is still the dial path. **`net_node.inl`, `net_node.h` and
`src/cryptonote_protocol/levin_notify.cpp` take deletions only (Rick,
2026-10-09):** a change may add no code lines to them. A comment-only
addition is free; an edited line, or logic swapped for a call into
Rust, is an added code line, so each PR that moves something to Rust
carries one dated `UNFREEZE` line naming the file. *Records-was,
2026-10-08: the two p2p files were shrink-only, which an in-place edit
passed.* This table cites that file so the two cannot drift. The one
exception is a line in this brief, new in the PR, of exactly this
form, naming the row's full anchor or the file path:
`**UNFREEZE (Rick, YYYY-MM-DD):** <anchor or file path> — <reason>`.
Nothing looser is read. **Scope (Rick, 2026-10-09):** a line naming a
function covers that function's row and nothing else. Editing a frozen
function inside one of these files takes two lines, one naming the
anchor and one naming the file, because the two rules guard two
different things. At the cutover the same list is the deletion gate:
every body and calls row's function is absent, and the cutover PR
removes those rows. A shrink row is retired only when its file is
deleted, and deleted means gone: `git diff --name-status -M` over the
tree reports no rename or copy from the path, and no file under
`src/` at head holds half or more of the file's distinct code lines.
`net_node.inl` outlives the dial path, since slice 4 and RD still edit
it, and `levin_notify.cpp` is RD's. *Records-was: the cutover PR
empties the file.*

`do_handshake_with_peer` is the outbound invoke. Its callers are the
two dial sites (`:1677`, `:1735`). Inbound is `handle_handshake`
(`:2752`), which does not call it. Once those calls are gone the
function has no caller, so the definition and the declaration go with
them. That is dead, not in flight. `handle_handshake`,
`detect_self_handshake`, `try_get_support_flags`, and `add_host_fail`
keep the callers named below.

| What | Where, at `f317d979c4` | `rg` when it has landed |
| --- | --- | --- |
| `connections_maker` | `net_node.inl:2111`, declared `net_node.h:655` | `rg -n -e connections_maker src/p2p` returns nothing |
| `make_new_connection_from_peerlist` and `connect_to_seed` | `:1789` and `:2032` (the seed walk stops at `:2073`) | `rg -n -e make_new_connection_from_peerlist -e connect_to_seed src/p2p` returns nothing |
| `make_expected_connections_count` | `net_node.inl:2185` | `rg -n -e make_expected_connections_count src/p2p` returns nothing |
| `try_to_connect_and_handshake_with_new_peer` | `net_node.inl:1637` | `rg -n -e try_to_connect_and_handshake_with_new_peer src/p2p` returns nothing |
| `do_handshake_with_peer` | definition `:1329`, declaration `net_node.h:657`, calls `:1677` and `:1735` | `rg -n -e do_handshake_with_peer src/p2p` returns nothing. Before deletion that command hits all four sites |
| `check_connection_and_handshake_with_peer` | `net_node.inl:1715` | `rg -n -e check_connection_and_handshake_with_peer src/p2p` returns nothing |
| `m_conn_fails_cache`, `record_addr_failed`, `record_addr_success` | cache `net_node.h:788`; `record_addr_failed` `:1763`; `record_addr_success` `:1776` | `rg -n -e m_conn_fails_cache -e record_addr_failed -e record_addr_success src/p2p` returns nothing |
| The dial path in `idle_worker` | `idle_worker` is `:2303`. The fill call is `:2306`. The gray-probe call is `:2307` | `rg -n -e connections_maker -e gray_peerlist_housekeeping src/p2p` returns nothing. `idle_worker` itself stays until its other gates move |
| `gray_peerlist_housekeeping` and its interval | function `:3336`, declaration `net_node.h:713`, interval `:756`. The comment at `net_node.inl:1091` names the function and goes with it | `rg -n -e gray_peerlist_housekeeping -e m_gray_peerlist_housekeeping_interval src/p2p` returns nothing. Before deletion that command hits the declaration, the interval, the `idle_worker` call, the definition, and that comment |
| `zone_server::open` and its `open_outcome` result type | `zone_server.h:382`; `struct open_outcome` at `:376` | `rg -n -e 'open_outcome open\(' src/p2p/zone_server.h` returns nothing, and `rg -n -w open_outcome src/p2p` returns nothing: the struct is the freeze row's witness and goes with the function |
| `shekyl_seam_open`'s blocking wait | `rust/shekyl-ffi/src/seam_ffi.rs:303` | The function remains and returns the channel without waiting for the handler to arm. `rg -n -e shekyl_seam_open rust/shekyl-ffi/src/seam_ffi.rs` still hits the definition. Zero hits fails |
| `shekyl_seam_session_cause` | `cause_ffi.rs:55`, declared `shekyl_ffi.h:4430`, C++ read `net_node.h:229` | `rg -n -e shekyl_seam_session_cause rust src` returns nothing |
| The outbound call of `try_get_support_flags` | call `:1435`, definition `:2677`, inbound call `:2837` inside `handle_handshake`, declaration `net_node.h:673` | `rg -n -e try_get_support_flags src/p2p` still matches the declaration, the definition, and the call in `handle_handshake`, and nothing else. Zero matches fails. A match inside `do_handshake_with_peer` fails, because that function is gone |
| `node_data.address` (handshake-address ruling, 2026-10-09; deleted 2026-10-13) | The field in `basic_node_data` (`p2p_protocol_defs.h`), written by `get_local_node_data`, read by `handle_handshake` through `derive_advertised_endpoint` (`net_node.cpp`, declared `net_node.h`) and by `get_announced_address` / `get_announced_port`. The Rust codec's `BasicNodeData.address` and its fixtures go with it; the two announce getters compute the address directly and stay, for the operator log line and the tests | `rg -n -e derive_advertised_endpoint -e 'node_data.address' src tests rust` returns nothing. `rg -n -e get_announced_address src/p2p` still hits the declaration, the definition and `get_announced_port`; zero hits fails, because the getter was kept. The harness goldens are re-recorded from the seam in the same commit, 44 bytes shorter per handshake |
| The timed-sync self-insertion (handshake-address ruling, 2026-10-09) | `net_node.inl:2717` to `:2735`: `outgoing_to_same_zone`, the `max_peerlist_size` subtraction, and the `local_peerlist_new.insert` of `zone.m_our_address` | `rg -n -e outgoing_to_same_zone src/p2p` returns nothing. Before deletion it hits `:2717`, `:2718` and `:2730` |
| `peerlist_manager::is_host_allowed` and `m_allow_local_ip` (address-validity ruling, 2026-10-11) | `net_peerlist.h:273` and `:201`; they go with the C++ peerlist (slice 1 §11.4). The flag stays: `arg_p2p_allow_local_ip` (`net_node.cpp:123`) is read at `net_node.inl:486` through `shekyl_peerlist_allow_local_ip`, which makes it the Rust peer lists' constructor input (2026-10-13); `peerlist_manager::init` (`:1078`) stops reading it when the C++ peerlist goes. *Records-was: `sanitize_peerlist` was named here as not in this table, staying until slice 4; it has its own row below (2026-10-13).* | `rg -n -e is_host_allowed -e m_allow_local_ip src/p2p` returns nothing. `rg -n -e allow_local_ip src/p2p` still hits the argument and its read; zero hits fails, because the override was kept |
| **C++ this PR adds (Rick, 2026-10-13, step 2): the strand's handshake-result branch** | `zone_server::on_strand`, the `SHEKYL_SEAM_HANDSHAKE` arm | Deleted by the chain-sync slice, or slice 4, whichever moves the sync payload's acceptance to Rust. Until then `rg -n -e SHEKYL_SEAM_HANDSHAKE src/p2p/zone_server.h` hits that arm; zero hits before that slice fails |
| **C++ this PR adds: `node_server::on_outbound_handshake`** | `net_node.inl`, declared `net_node.h`; the lines kept from `do_handshake_with_peer`'s invoke callback | The same slice as the branch above. `rg -n -e on_outbound_handshake src/p2p` hits the declaration and the definition until then |
| **C++ this PR adds: the `levin_commands_handler` virtual and `commands_handler()`** | `contrib/epee/include/net/levin_base.h`, `levin_protocol_handler_async.h` | The same slice. `rg -n -e on_outbound_handshake -e commands_handler contrib/epee` hits both until then |
| **C++ this PR adds: `seam_link::context_mut()`** | `src/p2p/seam_endpoint.h` | The same slice |
| **C++ this PR adds: the `disclose` adapter** | `zone_server.h` | slice 4, with the two senders |
| **C++ this PR adds: the `admit_operator_peer` and `note_own_address` adapters** | `zone_server.h` | the daemon-config slice |
| **C++ this PR adds: `shekyl_core_publish_tip` in `blockchain.cpp`** | `Blockchain::update_next_cumulative_weight_limit`, one call | the DRS store cutover, or the chain-sync slice |
| **Config push this PR adds (Rick, 2026-10-13, §3.1 review): `shekyl_peerlist_set_own_address`, through the `note_own_address` adapter** | the `m_our_address` assignment in `init`: the operator onion of `--anonymous-inbound` is parsed only in C++, so it reaches the lists as a config push. The per-boot onion does not cross (`daemon_tor_ffi.rs` hands it to the lists) | the daemon-config slice, which parses the option in Rust |
| **Config push this PR adds (§3.2, the dial-path deletion): `shekyl_dialer_set_exclusive`, through the `declare_exclusive_peers` adapter in `zone_server.h`** | one line after the `--add-exclusive-node` parse in `handle_command_line`: the closed network is the Rust dialer's candidate population. *Records-was:* `connect_to_peerlist(m_exclusive_peers)` in `connections_maker`, and the early returns in `connect_to_seed` and `gray_peerlist_housekeeping` | the daemon-config slice, which parses the option in Rust |
| **C++ this PR adds (§3.2): the `--seed-node` admit loop in `init`** | two lines beside the `--add-peer` loop: each parsed `--seed-node` address enters the Rust gray list through `shekyl::admit_operator_peer`, as an operator-named candidate (slice 1 brief §3: seeds are ordinary peers). *Records-was:* `parse_peers_and_add_to_container` into `m_seed_nodes`, read by `connect_to_seed` | the daemon-config slice |
| **C++ this PR adds (§3.2): the `add-priority-node` row in `removed_flags.cpp`** | the row, its `rust_dialer` reason and the operator message: the flag is refused by name, not forgotten (the priority-node row above) | the daemon-config slice, when the retired-flag table moves with the options |
| `shekyl_close_implicates_address` (*records-was* a C++ question, deleted 2026-10-13 with its one caller) | `cause_ffi.rs`, read by `record_addr_failed`; the Rust dialer's memory asks `CloseCause::implicates_address` directly, pinned by `shekyl-dialer`'s memory tests and `shekyl-transport-layer`'s cause tests. The C++ unit test of the predicate went with the entry | `rg -n -e shekyl_close_implicates_address rust src tests` returns nothing |
| **Config pushes this PR adds: `shekyl_dialer_set_out_peers`, `shekyl_peerlist_allow_local_ip`** | `set_max_out_peers`; the `--allow-local-ip` read in `init` | the daemon-config slice, which creates the options in Rust |
| `sanitize_peerlist`, the `P2P_MAX_PEERS_IN_HANDSHAKE` check and the per-entry connector loop in `handle_remote_peerlist` (Rick, 2026-10-13) | *Records-was* definition `net_node.inl:2417`, declaration `net_node.h:510`, the check and the loop in `handle_remote_peerlist`. Rust holds every rule; the handler is one call | `rg -n -e sanitize_peerlist src/p2p` returns nothing. `rg -n -e P2P_MAX_PEERS_IN_HANDSHAKE src/p2p` returns nothing; the define stays in `cryptonote_config.h` as an input of the Levin ingress byte bound (`shekyl-levin/src/ingress.rs`, `check_levin_constant_parity.sh`). `rg -n -e handle_remote_peerlist src/p2p` still matches the declaration, the definition and its two callers until slice 4 |
| Priority nodes (Rick, 2026-10-11) | `arg_p2p_add_priority_node` (`net_node.cpp:125`, declared `net_node.h:820`, added `net_node.inl:118`); `m_priority_peers` (`net_node.h:767`); the parse (`net_node.inl:556-558`); the clearnet arm (`:2132`); `is_priority_node` (`:2906`, declared `net_node.h:679`), whose callers (`:1670`, `:1681`, `:1727`, `:1737`) only choose a log level. The live flag rows: `docs/EXECUTABLES.md` and `docs/proxies.md`. `docs/USER_GUIDE.md` already has none. The Q12 run record is historical and is not in this gate | `rg -n -e priority_node -e m_priority_peers -e priority-node src/p2p` returns nothing. Before deletion it hits the argument, its registration, the parse, the arm, the predicate and its four callers. `rg -n -e add-priority-node src/common/removed_flags.cpp` hits the retired-flag row; zero hits fails, because the flag is refused by name, not forgotten. When the deletion has landed, `rg -n add-priority-node docs/EXECUTABLES.md docs/proxies.md docs/USER_GUIDE.md` returns nothing. Today the first two still document the live flag |
| The C++ in-flight nonce mint and erase | call `:1347`, guard `:1348`, `mint_recorded_handshake_nonce` `:1497`, `erase_outbound_handshake_nonce` `:1516` | `rg -n -e mint_recorded_handshake_nonce -e erase_outbound_handshake_nonce src/p2p` returns nothing. `rg -n -e detect_self_handshake src/p2p` still hits the declaration and the call in `handle_handshake` (`:2789`). Zero hits on `detect_self_handshake` fails. The dialer's `HandshakeNonceSet` is what `shekyl_dial_take_handshake_nonce` reads |

---

## Wargame

**Dial timing as a fingerprint.** An observer who sees when this node
dials can tell a fresh process from a steady one, and can tell Tor
from clearnet if the spacing is the connector's RTT. The answer is
the per-dial wake of `0.5 s + U(0, 1.0 s)` (R3), not a fixed delay
and not the 60-second timer; the uniform term is what an observer
cannot predict from the last dial, and the 0.5 s floor keeps two
dials from landing in one RTT. The spacing is the same shape for every
connector. The connector changes which list is drawn,
not the clock.

**Candidate-draw bias as an eclipse lever.** A draw that prefers
recent, front-of-list, or attacker-supplied addresses lets an eclipse
fill the outbound set. The answer is slice 1's uniform draw within a
connector. This slice does not sort by `last_seen` and does not give
`--add-peer` a better chance than any other gray address. An exclusive
list is the draw's population, not an exception to it; priority nodes
are deleted (the fill, "Priority nodes").
There is no subnet grouping (ruled 2026-10-11, "The candidate
filter"): an attacker who spreads addresses across prefixes gains
nothing a prefix rule would have denied, and an attacker within one
prefix is bounded by the uniform draw's share, which is what PM-2a's
clearnet variant measures.

**The failed-address memory as something an attacker can drive.** A
peer, or a directory, that can force a forgetting cause can suppress
an address for the window. The answer is `implicates_address` on
`DialFailed` and `PeerlistRefused`: on clearnet nothing writes the
memory (R2: a TCP RST and, NN being unauthenticated, a forged
`LevinHandshakeRejected` are both a path attacker's to produce, and
either would have suppressed an honest address for an hour); on Tor
only a reply in `0x04 0x05 0xF0 0xF1 0xF2` writes it, and those come
from our own Tor process. A handshake timeout, a peer close, a local
failure, and a clearnet proxy reply never did. The window is the one
`failed_addr_cache::window` already derived. An attacker who can force
reply 4 still buys only the short Tor window. That residual is
unchanged. The key is host and port, so a refused port does not
suppress another port on the same host. The memory dies with the
process. *Records-was: a refused dial and a rejected handshake wrote
the memory on clearnet too.*

**Dial concurrency.** Many simultaneous onion dials are a load the
managed Tor process was not sized for, and a way to stall every other
dial behind one SOCKS exchange. Many simultaneous clearnet dials pin
the dialer's tasks and the peers' handshake slots the same way. Each
connector has its own in-flight bound, owned by this slice. The
interim is one dial per connector (the fill section). It is measured
and raised on the Rust path after the cutover, not before it: a bound
measured with the C++ dial path in front is a `CppPath` reading
(`DAEMON_RELAY_PRIVACY.md` §97) and nothing is derived from it.
*Records-was: both numbers are measured before the implementation PR
names them.* The fill's one-dial-per-wake is the schedule, not that
bound.

**Full-pool capture.** The chance an attacker holds every hidden
session is `p_h^h`. `p_h` is the onion-candidate spy share, as §95
defines it. Holding the pool means every hidden stem slot, every
epoch, is the attacker's: they see the first hop of every transaction
this node originates, and rotation protects nothing. Hidden
addressing keeps the IP off that hop. It does not keep the
transactions from linking to one origin. Until the sweep is ruled,
the pool the dialer keeps is `hidden_out` (12), which is also what
`dev` writes at `net_node.inl:984`. The cost at that interim is 12
onion circuits on the managed Tor, where the old target opened 4. The
in-flight dial bound limits how fast they open. Total outbound is
`clearnet_out` plus `hidden_out`, and relayed stems are drawn over
all of them. Both the hidden outbound sessions and that total are lower limits.
*Records-was: the capture was written `p^k`.*

**What a peer can make us dial.** A peerlist, an advertisement, and a
timed-sync payload are gray entries. They become dials only through
the uniform draw, at the paced rate. A peer cannot name an address
and have this node dial it next. An exclusive list is not accepted
from a peer.

---

## Tests

Property tests against this brief's rules, not against the C++: the
C++ dial path is deleted in the same PR, and Ruling B makes the model
the reference (*records-was:* "differential against the current C++
wherever the behaviour is kept", struck 2026-10-12). The properties:
the Tor failed-address windows and which onion replies write the
memory, and that no clearnet cause does (R2); an exclusive list as the
whole candidate population; white promotion only on `SessionAccepted`
or `Confirmed` of an outstanding gray draw; each kept row of the
candidate filter. There is no subnet pass to assert (ruled
2026-10-11). Address validity is slice 1's falsifier §11.6: a
network-learned address in each listed range, and port 0, is refused
at `admit_gray` and refuses its list whole (R4), an operator-named one
is admitted, and `disclose` carries no non-global address. No
handshake carries an address field, on any connector (*records-was:*
"a hidden-connector handshake does not carry the clearnet port"). A
dial to our own listener is detected.

Property tests on draw uniformity, within one connector, including a
full gray list.

A starvation test: no p2p io worker is blocked while a dial is in
flight. The pair-run repro is the before and the after. Before: a
dial on the 2-worker io pool can leave `get_connections` with claims
unknown. After: the same dial leaves every io worker free, and the
claim post lands.

The handshake-result test above. `PayloadRefused` leaves the address
off white and still on gray when it was an outstanding draw. The fill
rule (R1), as properties: with no kept session the first success is
kept whatever list it came from; with a kept session and under
target, a keep draws white only at or above the floor and gray only at
or above the floor; below both floors and under the refill line the
draw is confirm-and-close and takes no slot; with gray empty and
under target the keep is from white; a restart (gray only) keeps at
its first success; a brand-new node (gray is the seeds) keeps at most
one seed before confirming (*records-was:* arm 2's two conditions; a
harvest left white unchanged; `HarvestDone` is deleted).
`Confirmed` of an outstanding gray draw writes white, leaves no
session, and never appears in the relay registry. That dial, started
while `Keep` rows are already at the target, leaves the `Keep` count
unchanged: no `Keep` peer is closed to make room, and the adopt is
not refused for being at the target. `SessionAccepted` of that draw
writes white and the session stays. When every white address is
already an outbound session and white is under the refill line, the
next wake draws gray, not another dial of a live white peer.

The deletion section is the gate. Each before-command hits the sites
it names. Each after-command does what its row says, including the
rows whose subject must still be present.

## Known defect this slice carries

`idle_worker` dials on the 2-worker io pool. While a dial is in
flight, one thread runs every strand, and the operator view can
report claims unknown. Recorded on #991. The reopen is this slice
landing the dial off that pool. Do not fix it in C++.

The post-handshake cause race is the same carrier. The dial thread
reads `shekyl_seam_session_cause` after the strand has queued the
reap, so a cause that does not implicate the address can be read as
`LocalClose`. The closed post logs the cause and does not hand it to
the strand. No counted cause takes that path. The closeout pair's
shut-write row was `PeerClosed` once and `LocalClose` otherwise, not
recorded either way. This slice's handshake receives the cause
directly. Do not patch the C++. The record is
`LV3_CONNECTION_OBJECT.md`. Reopen if the Rust handshake still
classifies a shut write by reading a row the strand can reap first.
