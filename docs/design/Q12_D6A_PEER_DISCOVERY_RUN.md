# Q12-D6a — the peer-discovery run

**Design, opened 2026-08-11.** The run specification for the measurement
registered as **Q12-D6a** in
[`Q12_FORWARD_DELAY_AND_ZONE_FIELD.md`](Q12_FORWARD_DELAY_AND_ZONE_FIELD.md):
*"the most expensive measurement the arc has proposed and the only one that
cannot be faked."*

**Status: the `{15, 30, 60}` sweep (§§13–15) and Q12-R5's late-joiner control
(§15.2) are RUN, 2026-08-14, and every readout is committed. §16 settles what
the floor actually counts and CLOSES the distinctness question; §17 discharges
§16.4's gate and overturns D9(b)'s implementation; §18 re-rules D9 — stem
anyway, the check becomes an admin-only diagnostic, and the achieved count
never selects wire behavior.**

Corrected twice, and the second correction supersedes the first. This line
originally read *"No VM stood up, no arm run"*, which its own body had already
outgrown: §§10–11.13 record a six-host ring sampled for an hour across three
providers, a 60-service dialability rig, and 20 hidden services restarted and
polled to recovery — all on VMs, and all after §9.4's privileged install
cleared. **A status line that disagrees with its own document is the failure
rule 94 exists to catch**, and this one was read as current in a later session
(`DAEMON_RELAY_PRIVACY.md` §90.3) and used to justify a claim about what had
been measured.

The 2026-08-13 correction kept *"no arm run"*, which was true when it was
written and is no longer: §§13–15 ran the arms the next day. Read §§10–12 as
instrument-building and dress rehearsal, §§13–15 as the arms, and §16 as what
the floor's number means. The seed estate carries a current binary and four
hidden services. Ground findings below are verified at source and against the
live estate on 2026-08-11 at pin
[`14c2ee599`](https://github.com/Shekyl-Foundation/shekyl-core/commit/14c2ee599).
Identifiers `Q12-R1…R7` extend the already-registered `Q12-` family (rule 94 §1;
no new prefix is minted).

---

## 1. What the run answers

Q12-D6a's question, unchanged: **does the anon peer graph form at all, and at
what adoption fraction `t`?** Readout is the *achieved* anon outbound peer
count per node against `t`; reference is F-8b's floor of 12.

The reason no existing instrument reaches it is also unchanged: everything the
arc has measured so far is local and synthetic, while peer discovery is a
**population dynamic** — onion addresses propagating through peerlists over
time. A static graph cannot answer it, because the question is whether the
graph forms.

---

## 2. Ground findings

### 2.1 The mechanism, verified at source

Four facts, all in [`src/p2p/net_node.inl`](../../src/p2p/net_node.inl):

1. **Peerlists are zone-segregated on receipt.** `handle_remote_peerlist`
   (`:2109-2117`) reads the zone off the *connection* and rejects the whole
   peerlist if any entry's zone differs. Onion addresses travel only inside
   anon-zone gossip.
2. **A node advertises its own onion only on outgoing same-zone connections.**
   `outgoing_to_same_zone` (`:2625`) gates the self-insert at `:2637-2643`.
   The in-source comment gives the reason: a Tor *inbound* connection arrives
   via the local tor daemon and carries no peer address, so self-announcement
   on an outgoing link is the only way an onion enters the network.
3. **Per-zone compiled seed lists** exist — `get_seed_nodes(zone)`
   (`:753-786`) — consulted by the connection maintainer when a zone has no
   peers (`:1713-1726`).
4. **`--add-peer` routes by parsed zone**: `m_command_line_peers` is dispatched
   through `m_network_zones.at(p.adr.get_zone())` (`:845-846`), so
   `--add-peer <addr>.onion:12021` lands in the **tor zone's white peerlist**.
   `--seed-node`, by contrast, feeds `public_zone.m_seed_nodes` only
   (`:527-533`).

Fact 4 is the fleet unlock: **anon bootstrap needs no code change.**

### 2.2 The request "put the seeds' onions in the peerlist they push" cannot work

Not merely unimplemented — **actively rejected by every receiver, with a
penalty.** `handle_remote_peerlist` returning false is not a soft skip:

- from the handshake path (`:1072-1077`): `add_host_fail(...)` and the
  connection closes;
- from the timed-sync path (`:1152-1157`): the connection is closed *and*
  `add_host_fail(...)`.

`add_host_fail` accumulates toward a ban. A seed that appended its onion to the
peerlist it pushes over clearnet would have that peerlist rejected wholesale by
every bootstrapping node, and would accumulate failure counts until those nodes
**ban the seed**. The cure is worse than the disease by a wide margin.

**There is no seed exception in the wire format, and adding one would be
wrong.** Cross-zone peerlist entries are precisely the deanonymization
primitive the segregation exists to kill — an entry saying *"this IP and this
onion are the same node"* is the link. A seed's own linkage is public by
construction and costs the seed nothing, but the check is receiver-side and
unconditional: an exception that lets *some* peers send cross-zone entries
weakens the guarantee for every non-seed node, because the receiver cannot
verify that the sender is a seed. Mission hierarchy: privacy is the product and
is not a per-peer setting (`00-mission` §2, `10-shekyl-first`).

### 2.3 The intent *is* served — by two different mechanisms

"A bootstrapping node immediately gets seed IPs **and** Tor addresses" is a
correct goal. It is met by:

- **hop one — the compiled per-zone list.** `get_seed_nodes(zone::tor)` gives a
  node with a tor zone its anon seeds without any peerlist exchange. This is
  the mechanism that should carry the four Shekyl seeds' onions.
- **hop two onward — seed self-announce.** Once the four seeds interconnect
  over tor, each has outgoing anon connections and so self-announces
  (`:2637-2643`), and their onions enter anon gossip normally.

### 2.4 The compiled tor/i2p seed lists are still Monero's — rule 60 defect

`net_node.inl:762-769` returns six `.onion` addresses on port **18083** —
`plowsof3t5hogddwabaeiyrno25efmzfxyro2vligremt7sxpsclfaid.onion` and
siblings — which are **Monero's mainnet hidden-service seeds**. `:775-779`
likewise returns three Monero `.b32.i2p` addresses. The IPv4 list (`:726-731`)
is correct and is the four Shekyl seeds.

So a Shekyl **mainnet** node started with `--tx-proxy tor,...` today attempts to
bootstrap its anon zone against Monero's infrastructure. This is a live
[`60-no-monero-legacy`](../../.cursor/rules/60-no-monero-legacy.mdc) violation,
not a stylistic one: it is a wrong-network connection attempt over Tor.

Both anon lists return `{}` for testnet — so **testnet has no anon seeds at
all**, which Q12-R2 turns from a defect into a convenience for this run.

### 2.5 The seed estate is not currently configured correctly

Probed over ssh, 2026-08-11:

| host | IP | daemon | binary date | tor | note |
| --- | --- | --- | --- | --- | --- |
| `skl-seedaus` | 134.199.166.22 | testnet, up | 2026-03-30 | **none** | RPC 127.0.0.1:12029 |
| `skl-seedeu` | 45.77.66.189 | testnet, up | 2026-03-30 | **none** | RPC 127.0.0.1:12029 |
| `skl-seeduse` | 45.77.147.65 | testnet, up | 2026-03-30 | **none** | restricted RPC public :12029, unrestricted :12030 |
| `skl-seedusw` | 45.76.171.128 | **DOWN** | 2026-03-30 | **none** | conf is the pristine `(example)` file |

Four findings:

1. **All four binaries date to 2026-03-30** — 4½ months stale. They predate the
   entire relay-privacy arc: per-zone embargo, coherence, the memoryless
   forward delay, PRs #384–#386, #430, #431. **They do not contain the code
   under test.** Measuring discovery against them would be the stale-daemon
   oracle in its purest form.
2. **`skl-seedusw`'s daemon is not running** and its config is the unedited
   example template.
3. **No tor process on any host** — but ~~the SP-T3 spike's pinned Tor Expert
   Bundle is gone~~ **CORRECTED: the bundle is present on all four**, at
   `/opt/shekyl/tor-expert-bundle-15.0.17/tor/tor`, with signed tarballs in
   `~shekyl`. The original claim was drawn from `pgrep tor` returning nothing,
   which shows that no service is *running*, not that the software is absent —
   the wrong observable for the question. No onion service existed at the time
   of the probe; §9.3 has since generated four.
4. **Configs diverge**, but `skl-seeduse`'s split (unrestricted RPC on
   127.0.0.1:12030, *restricted* RPC public on :12029) is **correct for its
   `shekyl-web` role**, not a defect. The other three are simply plainer.

Also: the testnet chain is at **height 1, difficulty 1** — genesis, nothing
mined, `grey_peerlist_size: 0`. §6 depends on this.

---

## 3. Decisions

**Q12-R1 — the onions go in the compiled per-zone seed list, not the pushed
peerlist.** §2.2 forecloses the pushed peerlist; §2.3 names what replaces it.
The four seeds' onions land in `get_seed_nodes(zone::tor)`, and their
propagation past hop one is ordinary self-announce gossip — which is *the
mechanism this run measures*, so seeding it any harder would defeat the run.

**Q12-R2 — the run uses a current-`dev` build and bootstraps purely via
`--add-peer`; the compiled testnet list lands AFTER the runs.** These collide:
if the four testnet onions are compiled in before the fleet is built, every
fleet binary carries four anon seeds that **no CLI flag can suppress**
(`--offline` and exclusive-peers both change semantics too much to serve as a
suppressor). The late-joiner control in Q12-R5 depends on "exactly one seed"
meaning exactly one. Current `dev` already returns `{}` for testnet tor, so the
resolution is free: build from `dev`, control bootstrap entirely with
`--add-peer`, land the compiled testnet list once the measurements are taken.

The **mainnet** Monero-seed deletion (§2.4) is separable and lands immediately —
it does not touch the testnet fleet.

**Q12-R3 — clearnet-only nodes stay in the fleet, as the isolation detector.**
They contribute nothing to *discovery* — zone segregation makes them invisible
to anon gossip — but they are the only instrument that can detect the
propagation failure in §6. A Tor-capable node receiving a transaction tells you
nothing about whether it crossed zones. Colocation does not distort this: the
`is_same_host` check at `:1202` is ANDed with `peer_id` equality, so it
suppresses dialing one node twice via two addresses, not two nodes on one host.
Colocated nodes carry distinct random peer IDs and form a normal clearnet graph
at degree 12. What colocation still cannot measure is anti-eclipse realism,
which is not this run's question.

**Q12-R4 — `A`, the absolute anon-capable node count, is the independent
variable; `t` is derived.** Q12-D6a says `t`, and `t` is the quantity of
interest — but clearnet-only nodes contribute nothing to the anon graph, so `t`
only matters through the `A` it produces. Setting `A` directly and skipping the
ballast is the same experiment with less spend. The regime that makes the
result meaningful is `A` relative to the floor of 12:

| `A` | 12/`A` | what it measures |
| --- | --- | --- |
| 15 | 80 % | degenerate — nearly everyone; selection is not selective |
| 30 | 40 % | meaningful |
| 60 | 20 % | comfortable; closest to a real network |

Six nodes would be *below the floor itself*: every node trivially fails and
nothing is learned.

**Q12-R5 — the bootstrap control is a late joiner, not a seed-count sweep.**
The risk is that every node's anon peers trace back to the seeds, in which case
the run measured the bootstrap rather than gossip. Varying seed count conflates
two things. The direct test: after the fleet converges, start **one more node
with exactly one `--add-peer` onion**. If gossip works it reaches 12. If only
seeds matter it reaches 1 and stops.

**The single peer must be a non-seed fleet node — and both variants are worth
running.** Pointed at a *seed*, the control measures gossip-from-seed: a seed is
a well-connected hub by construction, so reaching 12 from one says the hub knew
12, not that the graph gossips. Pointed at an ordinary fleet node, it measures
gossip proper. Each variant is one node and costs nothing against an arm; **the
difference between them is the interesting number**, because it prices how much
of discovery is hub-mediated.

One run each, clean isolation — and it is also
the realistic case, a new operator joining an established network, which is
exactly what the floor has to survive.

**Q12-R6 — one tor process per node, each with its own `DataDirectory`;
multiple nodes per VM is fine.** An earlier one-node-per-VM requirement was
stated for the propagation work and does not transfer here: anon gossip travels
over Tor — onion addresses, rendezvous circuits, self-announce on outgoing anon
links — and the underlying IP is invisible to every mechanism under test.
The hard condition is the tor process, not the VM: guard sets are
per-process/`DataDirectory` (SPIKE-F-12), so sharing one tor across nodes gives
them correlated guards and possibly correlated behaviour, which is not the
topology being modelled.

### Amendment to Q12-D6a's condition (2)

Q12-D6a says peerlists "cannot be seeded". Taken literally the run is
impossible: anon discovery has **no out-of-band bootstrap**, so without at least
one a-priori onion nothing can make a first outgoing anon connection. The
correct form: **nodes receive anon *seed addresses* only, never a populated
peerlist.** Hop one is bootstrap; everything after it must be gossip. That is
the distinction the condition was reaching for.

---

## 4. What must happen before the fleet exists

**Q12-R-W1 — repo PR (small, C++).** Delete the Monero onion and i2p seed
lists (§2.4).
[`20-rust-vs-cpp-policy`](../../.cursor/rules/20-rust-vs-cpp-policy.mdc) is
named explicitly rather than slid past: the p2p layer has no Rust counterpart
and is not on the current migration front, and the change is a **data
constant**. It adds no C++ surface area for the Rust rewrite to pay down.

> **RETRACTED, 2026-08-11 — the `.at()` abort does not exist.** This section
> also claimed that `--add-peer <x>.onion` with no tor zone configured reaches
> `m_network_zones.at(...)` at `:846` and throws `std::out_of_range` uncaught.
> **It does not.** `handle_command_line` calls `add_zone(adr->get_zone())` at
> `:494` *before* pushing to `m_command_line_peers` (and `:2869` does the same
> for the `--add-exclusive-node` / `--add-priority-node` container), so the
> zone always exists by the time `:846` looks it up.
>
> Worse for the original claim, the diagnostic it asked for **already
> exists**: `:638-645` sweeps every zone after the `--tx-proxy` loop and
> refuses to start with *"Set outgoing peer for tor but did not set
> --tx-proxy"*, a message that names the fix. The behaviour was already
> correct.
>
> The claim was written from the `.at()` call site without reading the
> callers that populate the map — Q12-D8's own test applied to a control-flow
> assumption instead of a number. Recorded rather than deleted: the retraction
> is the finding.

**Q12-R-W2 — the seed estate.** Rebuild `shekyld` from current `dev` on all
four (§2.5 finding 1 is on the critical path for any measurement); restart
`skl-seedusw` with a real config; install the pinned Tor Expert Bundle;
generate one hidden service per seed; add `--anonymous-inbound` and
`--tx-proxy`; cross-`--add-peer` the four onions so the seeds interconnect and
begin self-announcing.

**The four HS private keys are infrastructure the moment they are compiled into
source** (Q12-R1) and must be backed up off-host before the addresses are
committed. Losing one means a source change to replace a seed.

**Build target.** The dev box is Debian 13 (glibc ~2.41); the seeds are Ubuntu
24.04 (glibc 2.39). A trixie-built binary will not run there. Build in an
Ubuntu 24.04 container (or on one seed) and distribute that artifact — and
provision the fleet VMs on the same image so one binary serves both.

**Q12-R-W3 — guard the anon-zone `peer_id` sentinel.** Independent of the run,
adjacent to `add_zone`, and it protects something much larger than it is. §8.

---

## 5. The fleet

**Shape.** 8 VMs × 10 nodes = 80 node slots, spread across DigitalOcean,
Linode and Vultr (all three API keys are available). Each node: one `shekyld`,
one `tor` with its own `DataDirectory`, distinct P2P/RPC ports, distinct
`data-dir`. 4 vCPU / 8 GB per VM — the daemons are idle at height 1 but ten tor
processes are not free.

**Cost.** Roughly $0.07–0.09/hr per 4/8 instance ⇒ **~$14–17/day** for eight,
plus a few dollars of egress. Stated so the number is a decision rather than a
surprise; the fleet is destroyed at the end of each arm, so the real bill is
hours, not days.

**Arms.** Anon-capable count `A ∈ {15, 30, 60}`, with a **fixed 15
clearnet-only** detector set held constant across all three so `A` is the only
variable. Top arm is 60 + 15 = 75 nodes.

**Readout.** `get_connections` over the loopback RPC on each node, polled over
ssh. `connection_info` carries `bool incoming` and `address_type`
([`cryptonote_protocol_defs.h:50-88`](../../src/cryptonote_protocol/cryptonote_protocol_defs.h#L50-L88)),
and `address_type` distinguishes i2p (3) from tor (4)
([`enums.h:39-46`](../../contrib/epee/include/net/enums.h#L39-L46)) — so outbound
anon peer count per node needs **no new instrument**.

> **Amended by Q12-R12 (§11.4):** the *production* seeds run testnet and cannot
> join a stagenet fleet at all. What follows applies unchanged to the **stagenet
> bootstrap instances** run alongside them on the same six hosts — they are
> bootstrap targets and gossip participants, and they are not in the histogram.

**The four production seeds are in the graph but not in the histogram.** After
Q12-R-W2 they run anon zones on the same testnet, so they participate whether or
not this doc says so — and at `A = 15` four well-known hubs are a quarter of the
population, distorting exactly the arm where selection pressure matters most.
So: seeds serve as **bootstrap targets and gossip participants**, and the
reported distribution is over **fleet nodes only**. `A` counts fleet nodes.
(Q12-R5's late joiner answers *"did we measure the bootstrap?"*; this answers
*"what population is the histogram over?"* — two different confounds.)

> **The readout must never turn a refusal into a zero.** `get_connections` is
> unavailable in restricted mode (`-32601`), and a reader that does
> `result.get("connections", [])` reports that refusal as **zero connections** —
> i.e. as an isolated node, **which is the run's headline claim**. The
> instrument would then manufacture the finding it exists to test. Caught on the
> production testnet estate, where all five nodes read `0/0/0` and all five were
> fine; `utils/fleet/read_anon_histogram.sh` now distinguishes an RPC error, an
> absent `result`, and an absent `connections` field from an empty list, and
> exits nonzero naming which.

**Convergence.** Poll until the distribution stops moving. *Time to converge is
itself a result*, not overhead: "does it converge at all, and how long" is half
the question.

**Teardown.** Every VM destroyed at arm end via the same provider APIs. A
teardown check runs before the session closes; leaked instances bill silently.

### 5.1 The caveat that goes on every number this run produces

The testnet can validate **mechanism** — whether the anon graph forms, whether
gossip propagates onions, whether the floor is reachable. **It cannot produce
representative anonymity numbers**, because the graph is too small relative to
the stem length. A testnet-derived precision figure read as a network property
is `peers = 8` again. Every reported figure carries this banner.

---

## 6. The isolation arm, and the code it is waiting on

**What "isolation" means here.** Not a stem-graph partition — Q12-D5 retracted
that; coherence makes stem paths zone-uniform and the two graphs overlap. The
real failure mode is **propagation**: a transaction that fluffs on the anon zone
failing to reach clearnet-only nodes.

### 6.1 There is nothing for the detector to detect today

> **SUPERSEDED 2026-08-12 by Q12-U2.** This subsection is the 2026-08-11
> snapshot: a non-public arrival was classed `forward` and the pool cycle
> put still-stemming anonymity traffic on clearnet, so isolation was
> unreachable by construction. Q12-U2 deleted `forward`. An arrival now
> stems on the zone it arrived over, relays at arrival, and R-1 coherence
> keeps it there for the rest of the stem. Isolation is now a real
> detector for the stem phase (does the tx stay on the anon zone until it
> fluffs?). The pool cycle is unchanged beyond losing its `forward` arm:
> expired stems leave as fluff at `zone::public_`, which is the
> Dandelion++ exit, not a leak. The table below is historical — `forward`
> no longer exists, and the line numbers it cites have moved.

The arm would report a **trivial pass**, and that is worse than not running it.

Verified at source on 2026-08-11. **The pool cycle sends every class except
`local` to `zone::public_`, and it does so as a literal** — not a
fall-through, not a fallback:

| arrival class | pool-cycle route | destination |
| --- | --- | --- |
| `forward` | `stem_req` ([`:1070-1071`](../../src/cryptonote_core/cryptonote_core.cpp#L1070)) | `zone::public_` ([`:1091`](../../src/cryptonote_core/cryptonote_core.cpp#L1091)) |
| `fluff` / `stem` / `block` | `public_req` ([`:1073-1077`](../../src/cryptonote_core/cryptonote_core.cpp#L1073)) | `zone::public_` ([`:1087`](../../src/cryptonote_core/cryptonote_core.cpp#L1087)) |
| `local` | `private_req` | `zone::invalid` → anonymity zone |

**Both anon-arrival branches are covered, which matters because arrival is not
classed purely on the zone.** `cryptonote_protocol_handler.inl:968-970` assigns
`forward` when `zone != public_` — but `:974-976` **overrides that to `fluff`**
when the sender set `dandelionpp_fluff`. So an anon arrival is `forward` *or*
`fluff` depending on how the sender relayed it. It makes no difference to the
outcome: `:1087` and `:1091` are the same destination reached by two paths.

So anon-originated traffic takes **one** anon hop, and at hop two the receiving
node relays it publicly on the pool cycle whichever class it carries. **Every
anon transaction that reaches a second node crosses to clearnet by
construction.**

The one way clearnet-only nodes do not receive an anon-originated transaction
is if it never reaches a second node at all — `send_txs` takes the anonymity
zone with `require_usable = false` for originated traffic and **fails closed**
(`net_node.inl:2293-2299`), sending nothing rather than falling back to
clearnet. That is the origin failing to transmit, not the zones failing to
bridge, and it does not produce §6.3's signature: a transaction sitting in
*every* anon node's pool has by definition reached second nodes, each of which
would have relayed it publicly.

**Isolation is therefore unreachable, not merely unlikely** — a clearnet-only
node failing to receive an anon transaction that propagated is an event the
current code cannot produce.

**This has to be stated where the arm is specified, not discovered afterwards.**
A green isolation result is exactly the kind of number that gets cited later as
evidence that the zones bridge correctly — and it would be evidence of nothing
except that the branch which makes crossing unconditional was still in place.
That is Q12-D8's lesson applied before the measurement instead of after: *does
the thing this number describes currently run?*

### 6.2 The two arms have different inputs, and neither is blocked

**This is a sequencing fact, not a deferral** ([`22-no-lazy-deferral`](../../.cursor/rules/22-no-lazy-deferral.mdc)).
The isolation arm is waiting on **Q12-U1 and Q12-U2 — code this arc already owns
and is next to build**, ordered by Q12-D7: the txpool origin-zone field, then
the receive path that makes anon arrivals relay at arrival. Nothing external
gates it, and no design question is open in front of it.

| arm | input |
| --- | --- |
| **Discovery** | the seed estate (Q12-R-W2). Independent of U1/U2 — runnable as soon as the onions exist. |
| **Isolation** | Q12-U1 + Q12-U2 built, plus mining and funding for spendable outputs. |

Writing U1 and U2 is what gives the detector something to detect: with the
origin zone remembered and anon arrivals relaying in-zone, `forward`'s
unconditional hop to `zone::public_` stops being the only path, and a
transaction failing to cross becomes an event the code can produce. Until then
the clearnet-only set is instrumented and unread — it stays in the fleet
(Q12-R3) because it costs little and is the instrument the arm will need.

### 6.3 What the arm measures once U1 and U2 are written

The bridge is R-1's `tx_relay` exit — an anon fluff reaches anon peers, who are
dual-stack, and they relay publicly at the next hop. That *should* work by
construction. But "should work by construction" is exactly what was said about
coherence, and coherence turned out to be dormant (§89.8). So it is measured —
after there is something to measure.

**Measurement.** Originate on a Tor-capable node with the anon path forced;
measure arrival fraction and time-to-arrival at the clearnet-only set. The
failure signature is unambiguous: the transaction sits in every anon node's
pool and no clearnet node's. **Reverse arm**: originate clearnet-only and
confirm arrival at Tor-capable nodes — the easy direction, serving as the
control.

#### 6.3.1 Second readout — origin class, added 2026-08-13

**Amendment, and its provenance is weaker than §6.3's: this is a scope change
argued from text, not a finding anchored in code.** Read it as a requirement
added to the arm, not as something the arm already implied.

**Why it is needed.** `6af23439` names this arm as
`txpool_tx_meta_t::origin_zone`'s consumer — *"distinguish originated-on-anon
from relayed-on-anon"* — with a rule-15 reopen if the run ships without a
reader. **No such measurement exists in §6.** The readout above is arrival
fraction and time-to-arrival at the clearnet-only set, keyed by txid; the zone
is fixed by the arm's construction rather than observed, and nothing in the arm
reads the field. As written, the arm runs, produces its result, reads
`origin_zone` nowhere, and the reopen fires at teardown **by default**.

**And it cannot be recovered afterwards.** The arm originates on one node and
measures at another, and both origin classes produce the same pool-membership
event. Arrival fraction is not disaggregable by origin class after the fact, so
this must be a second readout with its own failure signature rather than a
different way of reading the first.

**Second readout.** On each anon-capable node, partition its pool entries by
recorded `origin_zone` — anonymity-arrived against clearnet-arrived and
locally-originated — and report the split alongside arrival fraction.

**Failure signature.** Anonymity-arrived entries at or near zero on nodes that
demonstrably received anonymity traffic. That is the field failing to record,
or coherence failing to hold, and it is distinct from §6.3's signature: a
transaction can arrive everywhere it should (§6.3 green) while every entry
carries the wrong origin.

**Scope, not consequence.** Whatever the arm needs to produce this split is the
arm's work and belongs in §7's order. Leaving it to fall out of the run is what
makes the reopen fire on a technicality rather than on evidence.

**Why discovery goes first.** The testnet is at height 1 with difficulty 1:
**no spendable outputs exist.** The isolation arm needs mining
(`skl-miner-test`), coinbase maturity and funded wallets on top of U1/U2.
Discovery needs none of that — it is pure peerlist gossip with zero chain
activity. Running it first keeps the fleet off the critical path of both the
funding step and the U1/U2 build, and its result could invalidate the anon-stem
design outright, which is the cheapest thing to learn early.

---

## 7. Order

1. Q12-R-W1 — repo PR: Monero seed deletion. **Q12-R-W3 rides this PR** —
   independent of the run, but both touch `add_zone`'s neighbourhood, so they
   share a validation surface
   ([`19-validation-surface-discipline`](../../.cursor/rules/19-validation-surface-discipline.mdc)).
2. Q12-R-W2 — seed estate: rebuild from `dev`, restart `seedusw`, tor + HS ×4,
   cross-`--add-peer`, **keys backed up**. This is **real scope, not
   configuration** — four binaries predating the arc, one host down, no tor
   anywhere.
3. Ubuntu 24.04 build artifact; fleet image pinned to match. **No isolated
   variant is built** — the fleet runs this same artifact with `--stagenet`
   (Q12-R12, §11.4).
3b. **Stagenet bootstrap instances on the seed hosts** — a second daemon, tor
   process and hidden service per seed host, up before the fleet, with their
   onions passed to fleet nodes as `--add-peer`.
3c. **The suppression fix lands first** (Q12-R13, §§11.5–11.13). Ruled
   2026-08-12, after the fleet had been provisioned once and destroyed. Under
   the unfixed constants the histogram measures *suppression dynamics* as much
   as discovery, and the two are not separable in the readout — the same defect
   Q12-R10 named for testnet contamination. D6a asks "does the anon graph form
   at population `A`"; an arm run first would answer "does it form under a
   1 : 80 timeout-to-suppression ratio at population `A`", which is not the
   configuration that ships. Running against a configuration already decided to
   be wrong spends VMs measuring something intended to be replaced.
4. **Discovery arms** — `A ∈ {15, 30, 60}`, 15 clearnet detectors, converge,
   record. **Per-node time series, not fleet totals** (§11.9): a node steady at
   20 and a node oscillating across 12 are indistinguishable in a sum, and the
   floor is per node. **Three readings** (§11.5), and every node's `get_info`
   must report `stagenet: true` before its readings count (§11.4).
5. **Late joiner** (Q12-R5) — two runs, one node each: one `--add-peer` at a
   seed, one at an ordinary fleet node.
6. Teardown; verify no instance survives.
7. Land the compiled **testnet** tor seed list (deferred by Q12-R2).
8. **Q12-U1** — the txpool origin-zone field.
9. **Q12-U2** — the receive path, so anon arrivals relay at arrival. Steps 8–9
   are what give the isolation arm something to detect (§6.1); they are ordered
   by Q12-D7 and are next regardless of the fleet.
10. Mine and fund the testnet — spendable outputs for the isolation arm.
11. **Isolation arm** — per §6.3.

---

## 8. Q12-R-W3 — the anon-zone `peer_id` sentinel

**Can `peer_id` correlate a Tor peer to a clearnet IP? Today, no — but the
safety is a default, not an invariant.** Verified at source, 2026-08-11.

### 8.1 Why it is safe today

`peer_id` is **per-zone, not global**: `m_config` is a `network_zone` member,
default-constructed `m_config{}` in both zone constructors
([`net_node.h:167-210`](../../src/p2p/net_node.h#L167-L210)), and `config_t`'s
constructor sets `m_peer_id(1)` ([`net_node.h:157`](../../src/p2p/net_node.h#L157)).

**Only the public zone is ever randomized** —
`public_zone.m_config.m_peer_id = crypto::rand<uint64_t>()` at
[`net_node.inl:147`](../../src/p2p/net_node.inl#L147). `add_zone`
(`:788-796`) constructs an anonymity zone by `emplace_hint` passing only the
io_context, and never touches `m_config`. So **every Shekyl node announces
`peer_id = 1` on its Tor zone** — uniform across the network, zero entropy,
correlates nothing.

Every *comparator* is gated to match: `:1097` and `:2691` test
`azone == zone::public_`, `:1196` and `:1221` test `is_public`. The
`is_same_host` clause at `:1202` sits inside an `is_public &&`, so it never
evaluates on an anon connection.

### 8.2 The wire surface is three emitters, not two

`m_config.m_peer_id` reaches the wire at:

- [`:2130`](../../src/p2p/net_node.inl#L2130) — `node_data.peer_id`, the handshake;
- [`:2641`](../../src/p2p/net_node.inl#L2641) — the anon-zone **self-announce**
  peerlist entry;
- [`:2767`](../../src/p2p/net_node.inl#L2767) — `handle_ping`'s response,
  `m_network_zones.at(context.m_remote_address.get_zone()).m_config.m_peer_id`.

The third is worth naming separately. It is **ungated and zone-dynamic** — it
reads the peer_id of whichever zone the connection arrived on. That is *correct*
today and would remain correct under any per-zone scheme, which is exactly what
makes it invisible: it is the shape the code would take if per-zone `peer_id`
were a deliberate design, so a reviewer scanning for "sites that leak the public
id over tor" finds nothing wrong with it. It emits the sentinel because the
sentinel is what is there, not because anything checks.

**The value is already on the wire today. It just happens to be 1.**

### 8.3 The mistake that would break it looks like a cleanup

Nothing asserts that an anon zone's `peer_id` stays constant. A maintainer
factoring the init code — *"why is `peer_id` only randomized for the public
zone? that looks like an oversight"* — moves the `crypto::rand` call into
`add_zone`, and every node acquires a stable unique identifier announced on
**both** its clearnet and its Tor connections.

The correlation is then trivial and passive: connect to the onion, read
`peer_id` from the handshake, scan clearnet for a match. Onion→IP, no timing
analysis, no traffic correlation, no statistical work at all. It would be the
single worst privacy defect in the tree, and it arrives as a tidying commit.

### 8.4 The guard, and where it must sit

The device is the one used by `derive.rs` refusing a block-time term and `f`
refusing a timing parameter: **make the mistake require a visible edit to a
thing that names its own consequence.**

**Placement matters, and the obvious site does not work.** A check at the *top*
of `add_zone` catches only a change to the constructor default — it runs
*before* the feared edit's `crypto::rand` call would execute, so the very edit
it exists to catch sails past it. The guard must sit **downstream of every
construction path**: an invariant checked once after zone setup completes in
`init()`, asserting that every non-public zone's `peer_id` equals the sentinel,
and **refusing to start** if not.

Shape:

- a named constant (`ANON_ZONE_SENTINEL_PEER_ID = 1`) used in `config_t`'s
  constructor, carrying the reason in a comment at the definition —
  *randomizing this correlates the node's onion address with its IP*;
- a fail-closed invariant after zone construction in `init()`;
- a gtest that stands up a node with a tor zone and asserts the announced value.
  The assertion is on the **config value**, one step from the wire — legitimate
  only because all three emitters in §8.2 are direct unmodified member reads, so
  the forwarding layer is invisible to the oracle. If any emitter ever
  transforms the value, the test must move to the wire.

**The premise is now verified.** All four `add_zone` callers — `:494`
(`--add-peer`), `:615` (`--tx-proxy`), `:654` (`--anonymous-inbound`) and
`:2869` (`parse_peers_and_add_to_container`) — are reached from
`handle_command_line`, which `init()` calls first. No zone is constructed after
`init()`, so the invariant sits after `init_config()`: downstream of every
construction path *and* downstream of the randomization it guards.

Filed as **Q12-R-W3**: independent of the run, small, and adjacent to the
`add_zone` neighbourhood that Q12-R-W1 already touches.

### 8.5 Built and negative-controlled

Landed on `fix/p2p-anon-zone-hygiene`. Both legs were proven by injecting the
feared edit — randomizing `m_config.m_peer_id` inside `add_zone`:

- **defect alone** — `init` refuses to start, logging the correlation as the
  reason;
- **defect with the guard deleted** — the announced-value assertion fails and
  prints the leaked identifier (`15317140264242224297`), so the test catches
  the defect **independently of the guard**.

The test carries its own negative control: the public zone must *not* read as
the sentinel, so a harness unable to observe the per-zone value cannot pass.
Full unit suite 1055 passed, 0 failed.

---

## 9. Q12-R-W2 progress — the unprivileged half is done

State as of 2026-08-11. Everything below was done without root; the remainder
is blocked on privileged access (§9.4).

### 9.1 Q12-R7 — build at a portable baseline, not at the build host

**Ruled after the binary crashed on a seed.** The first Ubuntu 24.04 artifact
ran on three seeds and died with `Illegal instruction` on `skl-seedaus`:

| host | provider | CPU | AVX-512 |
| --- | --- | --- | --- |
| `skl-seedaus` | DigitalOcean | `DO-Regular` | **no** |
| `skl-seedeu` / `skl-seeduse` / `skl-seedusw` | Vultr | Xeon Skylake | yes |
| dev box | — | i9-11950H (Rocket Lake) | yes |

`CMakeLists.txt` defaults `ARCH` to `native` (`set_default_arch`), so the
container compiled for the machine that was handy — **exactly the failure
[`76-device-provisioning-floor`](../../.cursor/rules/76-device-provisioning-floor.mdc)
names**, reached through a build flag rather than a constant.

Rebuilt with `-DARCH=x86-64` and `-C target-cpu=x86-64` for the Rust side.
**The intersection of today's four hosts would also be the wrong baseline**:
the fleet is arbitrary instance types across three providers, so the floor is
generic `x86-64`, not "what all four seeds happen to share". Verified: zero
AVX-512 instructions emitted, and the artifact runs on all four.

Relay nodes are not compute-bound, so the cost is nil — and RandomX carries its
own runtime dispatch, so mining is unaffected by the daemon's baseline.

### 9.2 The build artifact

Built in an Ubuntu 24.04 container (`glibc` 2.39) because the dev box is
Debian 13 (`glibc` 2.41) and a trixie-built binary will not run on the seeds.
Requires at most `GLIBC_2.38` / `GLIBCXX_3.4.30`. Stripped and `zstd -19`
compressed to 17 MB for transfer; `sha256 f7e35f3c…` verified identical on all
four hosts, `--version` returning `Shekyl 'Shekyl NG' (v3.1.0-unknown,
protocol 3)` on each.

Staged at `~shekyl/shekyld-u2404`. **Not installed** — see §9.4.

### 9.3 Hidden services, and where the keys live

One v3 service per seed, generated from the pinned Tor Expert Bundle already
staged by SP-T3 (`/opt/shekyl/tor-expert-bundle-15.0.17/tor/tor`). All four tor
processes are running, bootstrapped, SOCKS up on 9050.

| host | testnet `.onion` |
| --- | --- |
| `skl-seedaus` | `aghoxa757l2wqribeto2hv2rk3wjwcwdqzvu5hjkqdjcm24nuhaszjqd.onion` |
| `skl-seedeu` | `aks2vbpjb5ojfyqcataqedodws7ardjxczy76bqwmlv55mgfunsxoiyd.onion` |
| `skl-seeduse` | `23dkgevx7qnhrx2wmhmjvhsz2mpp54xomkujcvhuhm3ajgdciwztypad.onion` |
| `skl-seedusw` | `nqkfnallpz5kaoxkj2y6bmeifk4helrwp5z2fdtayo3rfzbx4q7z2tqd.onion` |

**These are testnet services** — `HiddenServiceDir ~/tor-hs-testnet`,
`HiddenServicePort 12021 127.0.0.1:12023`. Mainnet gets its own directory and
its own addresses; one onion must not serve both networks.

**The two ports are not a typo, and 12023 must not be "corrected" to 12021.**
A seed runs **two** p2p listeners:

| listener | bound | reached by |
| --- | --- | --- |
| clearnet p2p | `0.0.0.0:12021` (`p2p-bind-port`) | direct IP |
| anonymity-zone p2p | `127.0.0.1:12023` (`--anonymous-inbound` local port) | tor, forwarded from the onion |

`HiddenServicePort 12021 127.0.0.1:12023` reads *virtual port → local target*:
the onion is **advertised on 12021**, which is why `--add-peer <onion>:12021`
is right and matches the clearnet port. Only the *forwarding target* differs.

It differs because it has to. `p2p-bind-ip=0.0.0.0` already occupies
`127.0.0.1:12021`, so pointing the hidden service at 12021 would make the
daemon's anonymity-zone listener collide with its own clearnet listener and
fail to bind. The asymmetry looks like an inconsistency precisely because the
virtual port and the local port are different kinds of thing.

Verified on the running estate — every seed shows both `0.0.0.0:12021` and
`127.0.0.1:12023` listening.

**Keys are backed up off-host** to `~/.shekyl/seed-hs-backup/<host>/` on the dev
box, `0700`, with every `hs_ed25519_secret_key` sha256-verified against its
source. That discharges §4's requirement — but **the backup itself is now a
single copy on one machine**, alongside the genesis wallet, and wants a second
location before these addresses are compiled into source.

They are **not** in `get_seed_nodes` yet, per Q12-R2: compiling the testnet list
before the runs would give every fleet binary four unsuppressable anon seeds and
contaminate the late-joiner control.

### 9.4 ~~Blocked: privileged install~~ — CLEARED 2026-08-11

`sudo` requires a password on all four hosts and no `NOPASSWD` entries exist, so
the remainder is not reachable unattended: installing to `/usr/local/bin`,
editing `/etc/shekyl/*.conf`, converging the systemd units, and restarting.

**Two estate defects found while grounding, both needing that access:**

1. **`skl-seedusw` is in a restart loop, not crashed.** Its unit runs
   `/opt/shekyl/shekyld --config-file …` with **no `--non-interactive`** — the
   daemon starts, finds no console, exits `status=0/SUCCESS`, and systemd
   restarts it forever. It also points at `/opt/shekyl/shekyld` where the others
   use `/usr/local/bin/shekyld`.
2. **The units have diverged into two naming schemes** —
   `shekyld-testnet.service` on `seedaus`/`seedeu`, `shekyld-test.service` on
   `seeduse`/`seedusw`. Worth converging while the estate is open.

---

## 10. The estate is built — and two findings the building produced

Q12-R-W2 is **complete**. Five hosts (`skl-seedjp` added), all running the same
binary, all with a hidden service, all meshed over Tor at 3–4 anonymity peers
out of a possible 4. §9.4's blocker is cleared: a scoped `NOPASSWD` set covering
`install` to pinned destinations and `systemctl` on named units, with an
out-of-scope command verified denied on every host.

Both findings below come from the deployment rather than from the design, and
both change how the fleet must be run.

### 10.1 Q12-R8 — the arms need a defined start ordering and settle time

**A node that is down when its peers dial does not get dialled again for a long
time.** The anonymity zone's connection maintainer backs off after failed
attempts, and the backoff outlives the outage that caused it.

**This is a controlled result, not an explanation after the fact.** It was
observed, predicted, and then reproduced by restoring the condition:

| pass | condition | outcome |
| --- | --- | --- |
| first rolling restart | peers' daemons still restarting when each node dialled | `seedaus` **0** Tor peers; `seedeu`/`seeduse` paired only with each other |
| `seedaus` restarted alone, peers now live | dial targets up | **2** Tor peers immediately |
| second rolling restart, all 5 tor + HS live beforehand | dial targets up | **full mesh first pass**, 3–4 peers everywhere |

The effect appears when the condition holds and disappears when it is removed —
the same shape as a pre-registered prediction rather than a story fitted to one
observation. Twice at zero, once at full mesh, with the difference being solely
whether dial targets existed at dial time.

**Why it threatens the run.** At `A = 60`, a rolling start guarantees that early
nodes dial peers that do not yet exist. Their backoff then suppresses the
achieved anonymity peer count — **the exact quantity this run measures** — for a
reason that has nothing to do with peer discovery. It would present as a low
`x` against `A`, i.e. as *"the graph did not form"*, which is the run's headline
finding. A backoff artifact is indistinguishable from the result unless the run
is designed to separate them.

So the arms are ordered:

1. **All tor processes and hidden services up first**, every one bootstrapped and
   its SOCKS port listening, before any daemon starts.
2. **Then daemons**, and a **settle period** before the first reading.
3. **Readings taken twice**, separated by longer than the backoff. A count that
   rises between them is a settling artifact; a count that is stable is a
   result. *An arm whose two readings disagree is not reported as a
   measurement.*

This is not a workaround. A real network is not rolling-started, so it
is an artifact of the harness, and removing it makes the testbed resemble the
thing being modelled. Recording the discriminator matters more than the
ordering: without the two-reading rule, a future run with a slower fleet
reproduces the artifact and reports it as adoption sensitivity.

### 10.2 Q12-R9 — a destructive operation guarded by a predicate that cannot see its own subject

The deploy script retired each host's LMDB with:

```sh
[ -d /var/lib/shekyl/testnet/lmdb ] && mv .../lmdb .../lmdb.pre-v9.bak
```

**The intent was a schema version; the test was existence.** The predicate is
true whenever a daemon has ever run, so on the second pass it moved aside the
*freshly built V9* databases — the ones that had just been created to replace
the pre-V9 ones. The cost here was nil (height 1, genesis only), but the same
line on a synced chain deletes the chain.

**The more useful half is the backup.** The safety claim rested entirely on the
`.bak` suffix — and `rm -rf ...bak` earlier in the same script overwrote it on
the second pass. So **reversibility was never a property of the operation; it
was a property of running it exactly once.** The second invocation destroyed the
recovery path silently, and only the worthlessness of the current state made
that free.

**This is the third instance of one class in this arc**, each in a different
costume:

| instance | looked like | actually did |
| --- | --- | --- |
| `\| tail -200` on a build log | capturing output | discarded the artifact and swallowed the exit code |
| `;` between gate commands | chaining a gate | made the gate decorative — it could not fail |
| `.bak` + existence predicate | a reversible move | lost the ability to undo, on the second run |

**All three look defensive, none is, and none fails loudly.** The first two lost
data; this one lost the ability to recover it. The common shape is a construct
whose *appearance* of safety is doing the work that its *behaviour* does not.

Two changes, and the second is independent of the first:

- **Test the version, and refuse on unknown.** Read the schema version; act only
  on a version the script recognises as needing retirement. If it cannot read
  one, **stop** rather than guess — the same device as refuse-don't-clamp.
  Guessing is precisely what `-d` was doing.
- **Never overwrite an existing backup.** Timestamp it, or fail if one exists.
  **Fixing the predicate alone would not have saved the backups**; the
  overwrite is a separate defect on the same line, and only its independence
  makes it easy to miss while congratulating oneself on the first fix.

**This lands before the fleet.** At 75 nodes the same script runs 75 times, and
the current version is safe only because there is nothing to lose.

**Landed** as [`utils/fleet/check_chain_db_compatible.sh`](../../utils/fleet/check_chain_db_compatible.sh) —
**a classifier that touches nothing.**

It began as a retirement tool that located, backed up and moved the database.
**Four review rounds found four defects, and all four were one mistake:**

| # | defect | what it really was |
| --- | --- | --- |
| 1 | database located from a `data-dir` **argument**, compatibility judged from a **config** with its own `data-dir=` | the caller named a different tree than the daemon uses |
| 2 | probe timeout read as "compatible" | the caller inferred a state it could not see |
| 3 | `find` on an unreadable directory returns nothing | the caller's permissions, not the daemon's |
| 4 | `[ ! -e "$DATA" ]` false when a **parent** is unsearchable | the caller's permissions again — reported as a fresh node |

(1) is a wrong vantage point. (2)–(4) are the caller inferring, from **its own
uid, cwd and permissions**, the state of a tree the daemon opens from **its
own** (`User=shekyl`, systemd's `WorkingDirectory`). *The caller's silence was
repeatedly taken for the daemon's absence.*

**A fifth guard would have been a fifth chance to make the same mistake.** So
the vantage point was removed rather than defended: the script now performs **no
filesystem introspection and no destructive action**. The daemon opens its own
data directory with its own identity and reports what it found — the only
observer that cannot be wrong about it — and the caller decides, in the open,
where a `rm -rf` is visible in a provisioning script rather than hidden behind a
`.bak` that proved reversible exactly once.

It answers one question — *will this daemon start with this config?* — as
`0` usable / `10` incompatible / `2` refused. 141 lines became 97, of which the
comment explaining the four defects is the largest part.

| case | expected | result |
| --- | --- | --- |
| fresh node, no data-dir at all | usable, exit 0 | usable |
| existing current-schema database | usable, exit 0 | usable |
| corrupt database | refuse, exit 2 | refused (`rc=1`), no conclusion drawn |
| **unreadable data-dir** | the **daemon** reports, not our `find` | refused — defect (4) closed by construction |
| non-executable daemon | refuse up front | refused |
| matcher vs a future `pre-V10` | still fires | version-invariant (`pre-V[0-9]+`) |

**The retirement path is gone rather than untested.** The earlier version could
not be exercised end-to-end because producing a genuine pre-V9 database is no
longer possible — Q12-R9's own defect destroyed the last copies. That gap is now
moot: there is no retirement path to test, only a classification, and the
classification is verified against the real refusal text captured from
`skl-seedaus`'s journal.

---

## 11. Two findings from the density test — one of them a blocker

### 11.1 Q12-R10 — the fleet must be NETWORK-ISOLATED, and this is a blocker

The density host showed a node holding an outbound **clearnet** peer.
`get_ip_seed_nodes` returns the four production seeds for testnet, so fleet
nodes bootstrap onto the **live testnet** automatically.

**This was first written up as consistent with Q12-R3. That was wrong.** R3
ruled the production seeds out of the *histogram*; what this is, is a path to
the live testnet — an **unbounded, unmeasured population outside the fleet**.

**It breaks `A` as the independent variable.** At `A = 15`, a node's anonymity
peers may come from its 14 fleet peers *or* from however many Tor-capable nodes
exist on the live testnet. The floor could be reached entirely from outside the
fleet, and the histogram would report a healthy 12 that has nothing to do with
`A`.

**And the contamination is inversely correlated with the variable.** It matters
most where the fleet population is smallest — which is precisely the arm the
finding rests on. A confound that grows as the signal shrinks.

**It cannot be corrected afterwards.** A converged histogram does not record
whether a peer was fleet-sourced or testnet-sourced, so this is a
decide-before-running matter, not an analysis-time adjustment.

The counter-argument — *a real network is not sealed either* — is true and
beside the point. Under it, `A` is not what is being measured: the run would be
measuring the testnet's Tor population with a fleet attached, and the sweep
would be meaningless.

> **The REQUIREMENT below stands; its REMEDY is superseded — see §11.4
> (Q12-R12), 2026-08-11.** Both properties this section demands already exist in
> the shipped binary as `--stagenet`, so no fleet build is made. The requirement
> was right; what was missed is that it was already met.

**Ruled: a fleet build with a distinct `NETWORK_ID` and empty compiled seed
lists.** Verified at source, `--seed-node` alone is **not** sufficient:
`net_node.inl:1749-1759` appends `get_ip_seed_nodes()` as a *fallback* when no
configured seed connects, so the production seeds re-enter through a path that
overriding the seed list does not close.

| candidate | verdict |
| --- | --- |
| distinct `NETWORK_ID` + empty compiled seeds | **chosen** — isolation by construction; a foreign peer fails the handshake whatever is dialled |
| `--seed-node` override alone | rejected — the compiled fallback re-adds production seeds |
| `--add-exclusive-node` | rejected — it *changes peer selection*, which is the mechanism under test |
| firewall the seed IPs | rejected alone — the daemon still dials and fails, burning backoff slots (Q12-R8) |

Emptying the compiled lists as well as changing `NETWORK_ID` is not redundant:
`NETWORK_ID` alone still leaves nodes *dialling* production seeds and failing,
and under Q12-R8 those failures cost backoff on the very connections being
measured.

#### The load-bearing check: does a rejected handshake still leak a peerlist?

`NETWORK_ID` isolation would be **nominal** if a rejected handshake still
exchanged peer addresses — external onions would enter the fleet anyway, just
without a usable connection. Verified in both directions at
[`src/p2p/net_node.inl`](../../src/p2p/net_node.inl):

| direction | check | peerlist handling |
| --- | --- | --- |
| **outbound** — we dial a foreign node | `rsp.node_data.network_id != m_network_id` at `:1078`, `return` at `:1081` | `handle_remote_peerlist(rsp.local_peerlist_new, …)` is at `:1084` — **after** the return, so their peerlist is **never merged** |
| **inbound** — a foreign node dials us | `arg.node_data.network_id != m_network_id` is the **first statement** of `handle_handshake` (`:2674`) | `drop_connection` + `return 1` at `:2678-2680`, with `rsp` still default-constructed — **no peerlist is assembled or sent** |

The inbound ordering is the stronger of the two: the check precedes the zone
lookup, `get_local_node_data`, and every line that would populate
`rsp.local_peerlist_new`. There is no path by which a foreign peer obtains fleet
onions, and none by which a fleet node ingests foreign ones.

**So the isolation is real, not nominal.** The response bytes are received
before the check — that is unavoidable in a request/response protocol — but they
are discarded rather than merged, which is the property that matters: an onion
that never enters a peerlist never becomes a dial target.

#### Why the confound is not merely a labelling problem

`get_connections` reports `address_type` and `incoming` and **nothing that
distinguishes a fleet onion from a testnet onion**. A converged count of 12 reads
identically whether it is 12 fleet peers, 12 testnet peers, or any mix, and no
post-hoc separation exists because the distinguishing fact was never recorded.

But filtering the readout would not save the run even if it were possible,
**because the outside population changes the mechanism and not just the count.**
Discovery is gossip: a fleet node learns onions from its anonymity peers'
peerlists, and a testnet peer's peerlist carries testnet onions, which propagate
into the fleet and become dial targets. `A` then stops being the candidate pool
at all.

The spiral Q12-D6a exists to test — *no outgoing anonymity connection ⇒ no
self-announcement ⇒ no inbound* — **is a property of a closed population**. It
cannot manifest while there is an open supply of external onions to bootstrap
from. An unsealed fleet would report *"the spiral does not occur"*, and the
reason would be the confound rather than the network.

**What differs from production, and why the oracle survives.** The fleet binary
differs only in `NETWORK_ID` and the compiled seed constants. Peer discovery —
peerlist gossip, zone segregation, self-announcement, the connection maintainer
and its backoff — is byte-identical. `NETWORK_ID` gates *handshake acceptance*,
not discovery, so the quantity under measurement is unchanged. This is recorded
rather than assumed, because a modified binary is a different oracle unless the
difference is argued.

### 11.2 Q12-R11 — at `A ≤ 12` the floor is unreachable by arithmetic

The density host ran 10 anonymity-capable nodes and no node exceeded 8 outbound
anonymity peers, against a floor of 12 and 9 possible peers.

**That is not a shakeout artifact; it is a result.** `12 > A − 1` means the
floor cannot be met by any node, so **every** node sits below it — not because
discovery failed, but because the population is smaller than the requirement.

**Which makes Q12-U2's open question the launch condition rather than an edge
case.** Whatever a below-floor node should do — not stem, stem anyway, hold — is
what *every* node does while the anonymity population is under 13. A young
network with few Tor-capable nodes **is** that state. Q12-D6a recorded that no
such rule exists and that F-8b floors the configured cap rather than the
achieved count; this bounds when the gap is load-bearing, and it is at exactly
the moment a network launches.

**And it narrows what the `A = 15` arm can say.** With 15 nodes and a floor of
12, the arm asks *whether near-complete connectivity forms*, not whether
selection is selective — 12 of 14 possible peers is nearly the whole
population. It should be reported as that question, not read as the low end of a
trend across the sweep. The `A = 60` arm is the only one where the floor is a
genuine selection among candidates.

### 11.3 Recorded for the next fleet: the release path supplies a binary, not a topology

The `.deb` is correct for its purpose and resolves dependencies declaratively —
the right answer to the boost/libevent hunt. It does **not** supply the fleet's
service topology: its unit is single-instance and hardcodes `--data-dir
/var/lib/shekyl`, a fixed log path, `StateDirectory`, and `ReadWritePaths`, with
no `--config-file` at all.

Ten instances per host therefore need `skl-node@.service` and `skl-tor@.service`
templates carrying `%i` into every path the shipped unit pins, with
`Requires=skl-tor@%i` so Q12-R8's ordering is **structural rather than a
convention in a start script**. Kept here so the distinction is not
re-litigated at the next fleet: the release path is right for releases, and the
fleet's needs are genuinely different.

**Density verified** on one host (4 vCPU / 8 GB): 10 daemons + 10 tor, 0
restarts, 3.6 GB of 7.9 GB used, all ports bound, 10 distinct guard
directories. **Q12-R8's two-reading rule earned itself immediately** — 29
outbound at `t+0` against 62 at `t+240`, so a single reading would have reported
less than half the converged count.

### 11.4 Q12-R12 — the isolated network already exists; no fleet build is made

**Ruled 2026-08-11. Supersedes §11.1's remedy, not its requirement.** Q12-R10
demanded two properties — a distinct `NETWORK_ID` and no compiled seed dial
targets — and then specified a modified build to obtain them. **`--stagenet`
already has both, in the shipped binary.**

| property R10 requires | stagenet, at source |
| --- | --- |
| distinct `NETWORK_ID` | `::config::stagenet::NETWORK_ID` ([`cryptonote_config.h:429-431`](../../src/cryptonote_config.h#L429)) shares no bytes with testnet's at `:418-420` |
| no compiled IP seeds | `get_ip_seed_nodes()`'s `STAGENET` branch is empty — `else if` at [`net_node.inl:737`](../../src/p2p/net_node.inl#L737), the block `:738-740` holding only the comment at `:739`; the four production seeds are inside the `TESTNET` branch |
| no compiled anon seeds | `get_seed_nodes()` returns `{}` for `tor` and `i2p` on **every** network ([`:770-772`](../../src/p2p/net_node.inl#L770)) — Q12-R2 has not landed the testnet list yet |

Everything else is the same chain: `stagenet_hard_forks[]` is `{1,1,0,…}`,
byte-identical to testnet's ([`hardforks.cpp:41-50`](../../src/hardforks/hardforks.cpp#L41)),
so stagenet is v3-from-genesis with every feature active exactly as testnet is.
It differs in `NETWORK_ID`, genesis tx, ports (13021/13029) and address prefix —
and in nothing that peer discovery touches.

**Verified empirically, not only read.** A stock `shekyld --stagenet` on a fresh
data-dir starts, creates genesis, brings up p2p and RPC, and **dials nothing**:
no `134.199.*` / `45.7*` appears in its log, because the seed set it is given is
empty rather than overridden.

#### What this buys beyond convenience

**§11.1's oracle paragraph is discharged by construction rather than by
argument.** That section had to reason that a modified binary was still a valid
oracle — "`NETWORK_ID` gates handshake acceptance, not discovery, so the
quantity under measurement is unchanged." The reasoning was sound, but it was
reasoning. With stagenet the fleet runs **the same artifact a user installs**,
and the argument is not needed at all. An assumption that never has to be made
cannot be wrong.

It also deletes a build: no depends/gitian pass, no second `.deb`, no risk that
the fleet artifact and the release artifact drift.

#### Four consequences, none of them optional

1. **The production seeds cannot participate.** They run testnet; a stagenet
   fleet node fails their handshake — which is the point. Each seed host
   therefore runs a **second** daemon on stagenet with its **own** tor process,
   `DataDirectory` and hidden service (SPIKE-F-12), giving the fleet six
   bootstrap hosts that were up before it. §5's rule is unchanged: seeds are
   **bootstrap targets and gossip participants, and are not in the histogram**.
2. **The fleet's seed onions stay out of source.** They are passed as
   `--add-peer` flags at provisioning. Q12-R1's "HS keys are infrastructure the
   moment they are compiled into source" therefore does **not** attach to them:
   these are disposable fixtures, destroyed with the fleet, and carry no backup
   obligation. The *testnet* seed keys in `~/.shekyl/seed-hs-backup/` are a
   separate thing and still do.
3. **Bootstrap must use `--add-peer`, not `--seed-node`.** Verified at
   [`net_node.inl:527-533`](../../src/p2p/net_node.inl#L527): `--seed-node`
   parses into `public_zone.m_seed_nodes` **only** — it is public-zone by
   construction and cannot carry an onion into the anonymity zone. `--add-peer`
   routes by parsed zone (`add_zone(adr->get_zone())` at `:494`), which is the
   mechanism Q12-D6a already relies on.
4. **Ports change.** Stagenet defaults are 13021/13029. Templates, configs and
   any firewall rules written against 12021/12029 must be swept — a hardcoded
   testnet port is the one way a fleet node could still reach the live network.

#### What the smoke test established before any VM was paid for

Three stagenet daemons on the dev box, each with its own tor process,
`DataDirectory` and v3 hidden service, chained `A ← B ← C` so that **C is given
only B's onion and must learn A by gossip**. This tests the thing the run
measures, on the network the run will use, for the price of one local box.

**And it produced a finding on the first attempt.** The daemons refused to start
with `--tx-proxy tor,127.0.0.1:<port>,10`:

> `--tx-proxy outbound count 10 is below the floor of 12 that the relay embargo
> derivation assumes; refusing to start under-provisioned.`

F-8b's floor is **enforced at startup and refuses rather than clamps** — the
posture Q12-D9 §12.2 requires of the *live* check. Worth recording because
Q12-R11 says every node sits below the floor by arithmetic at `A ≤ 12`: the
*configured* floor is enforced, the *achieved* one is not, and the smoke test
walked into exactly that seam from the enforced side.

### 11.5 Q12-R13 — the backoff is one hour, and the ordering rule was too weak

**Q12-R8 said "two readings separated by longer than the backoff" without
knowing what the backoff was. It is 3600 seconds**, and the density test's
240-second separation was short of it by a factor of fifteen.

The smoke test's three nodes sat at **zero connections** with a single dial
attempt in the log:

> `Timeout on socks connect (127.0.0.1:29051 to y6l247vv….onion:13021)` — at
> `t+47s`, then nothing for the next hour.

At source, one failed connect is remembered for an hour and suppresses every
subsequent selection of that address:

| step | site |
| --- | --- |
| a failed connect records the address | `record_addr_failed` → `m_conn_fails_cache[addr.host_str()] = now` ([`net_node.inl:1404-1408`](../../src/p2p/net_node.inl#L1404)) |
| the filter | `is_addr_recently_failed` returns true until `now - t > P2P_FAILED_ADDR_FORGET_SECONDS` ([`:1411-1421`](../../src/p2p/net_node.inl#L1411)) |
| the constant | `#define P2P_FAILED_ADDR_FORGET_SECONDS (60*60)` ([`cryptonote_config.h:201`](../../src/cryptonote_config.h#L201)) |
| where it bites | white/gray selection `:1439`, the maintainer's candidate loop `:1698`, and peerlist appending `:2135` — the log line `No available peer in white list filtered by 1` **is** this filter |

**The cache is keyed on `host_str()`, so an onion is filtered by its full
address** — there is no per-zone exemption, and no way to clear it short of a
restart.

#### Why the *first* dial failed, and what the ordering rule must actually say

Q12-R8 ruled: all tor and hidden services up **first**, then daemons. The smoke
test did exactly that — three tor processes at `Bootstrapped 100%` before any
daemon started — **and the first dial still failed**, because a hidden service
being *published* is not the same as its descriptor being *fetchable* by another
client. Reaching the same onion by hand through the same SOCKS port minutes
later succeeded immediately.

**So the rule is strengthened, not restated:**

| Q12-R8 as written | Q12-R13 |
| --- | --- |
| tor + HS up before daemons | every onion **verified reachable through the SOCKS proxy that will dial it** — not through any convenient one — before any daemon starts (`utils/fleet/wait_onions_reachable.sh`, and §11.5.1) |
| two readings "longer than the backoff" apart | **three readings, or one well after `t + 3600 s`** — see below |
| — | a fleet whose first dials failed is **restarted**, not waited out: the cache is in-memory and has no other clearing path |

**`> 3600 s` of separation is necessary and not sufficient.** If a node burned
its addresses at `t+0`, the entries expire at `t+3600` — but the node then has
to *retry and converge*, and a reading taken at the moment of expiry catches it
mid-recovery. The second reading must come after that retry has settled, which
is why the rule is three readings rather than two with a bigger gap. An arm
whose last two readings disagree is not a measurement (Q12-R8).

**This is the run's largest scheduling fact.** At `A = 60`, a rolling start
means early nodes dial onions that are not yet fetchable; each such failure
costs an hour of suppression on the exact quantity being measured, and a
histogram read at `t + 20 min` would report a sparse graph caused entirely by
the start procedure. Q12-R8 predicted this shape from the seed estate; R13 gives
it a number and shows the ordering rule as written does not prevent it.

#### A hidden service can silently never publish, while its own tor reports 100 %

The gate found this on its first real use, and it is **not** the propagation
window. Of the smoke test's three services, **one was unreachable from both
other nodes more than an hour after `Bootstrapped 100%`** — while answering from
*its own* tor, which proves only that the local listener is up, since tor
short-circuits a request for a service it hosts. Every local indicator said
healthy: tor bootstrapped, the daemon's anonymity listener bound, the onion
present in `hostname`.

Running that tor at `info` level named it. A working service logs

> `handle_response_upload_hsdesc(): Uploading hidden service descriptor:
> finished with status 200 ("HS descriptor stored successfully.")`

once per HSDir, and the broken one had **never logged it at all**. On restart it
uploaded to every HSDir within **6 seconds** and was reachable on the next probe.

| stage | observable | value |
| --- | --- | --- |
| tor bootstrap | `Bootstrapped 100%` | present in **both** cases — says nothing |
| descriptor upload | `hsdesc … status 200` at `info` | **absent** in the broken case, ~6 s after start in the healthy one |
| external reachability | another node's SOCKS | the only signal that separates them |

**Three things follow.** The gate is a **health check**, not a settling delay —
a wait of any length would not have fixed this. The remedy is a **tor restart**,
and it is reliable. And a node whose onion never publishes would enter an arm as
an isolated node, biasing the statistic **in the direction of the run's headline
claim**; such nodes are restarted before the arm, and if a restart does not fix
one, it is dropped and the drop count reported.

#### The constant, confirmed to within four seconds

The three-node smoke test was left running and polled every 60 s. It is the
whole finding in one timeline:

| time (UTC) | event |
| --- | --- |
| `00:58:25` | three daemons start; `B` holds `--add-peer <A.onion>` |
| `00:59:12.622` | `B`'s only dial fails: `Timeout on socks connect` |
| `00:59:12` → `01:59:12` | **zero connections on all three nodes, for sixty minutes**, polled once a minute |
| `01:59:12.622` | `+3600 s` — the cache entry ages out |
| `01:59:16.106` | **`B` connects to `A`** — 3.5 s later |
| `02:00:26` | converged: `A` 2 out / 2 in, `B` 1/2, `C` 2/1 — 5 of 6 possible links |

**Nothing changed except the clock.** Same binaries, same tor processes, same
configs, no restart, no intervention. The graph the code could not form for an
hour formed completely in under sixty seconds once the suppression expired, and
`C` — which was never given `A`'s address — reached it by gossip.

That is `P2P_FAILED_ADDR_FORGET_SECONDS` measured rather than read, and it
settles the mechanism beyond argument: the hour is not a symptom of a broken
peer, an unreachable service or a misconfiguration. It is the daemon declining
to retry.

### 11.5.1 The gate must probe from the proxy that will dial — a correction

**Written after the six-node rehearsal contradicted the first version of this
section.** That run gated all six onions, *passed*, wired the ring, started the
daemons — **and dials still failed**:

> `jp` at `01:35:38Z`: `Timeout on socks connect (127.0.0.1:21003 to
> x5ll6ukod….onion:13021)` — the very onion the gate had passed minutes earlier.

Seven such timeouts across the six nodes (2/1/1/0/1/2) against ~23 successful
links. **The gate was not wrong; it was asked the wrong question.** It probed
through *one* tor — the dev box's — and every fleet node dials through **its
own**, which must fetch the descriptor independently over its own circuits. A
descriptor published and fetchable by one client says nothing about whether a
different client can fetch it inside its timeout.

**So the requirement is per-proxy, and it has a second benefit.** Probing onion
`Y` through node `X`'s SOCKS caches `Y`'s descriptor in `X`'s tor, so `X`'s
daemon then dials against a warm cache. The gate stops being only a check and
becomes a **cache primer** — which is why running it from the dialing proxy is
both the correct test *and* the mitigation.

**And it does not scale to a full graph, which is the finding.** Priming is
`O(A²)` — 3540 probes at `A = 60` — and **gossip-learned onions cannot be primed
at all**, because they are not known until the run is under way. Every such
address is a fresh 45-second gamble against an hour of suppression. Burn-in is
therefore **not eliminable by procedure** at fleet scale; the run must expect a
residual, measure it, and report it.

#### The asymmetry, stated as a number

| quantity | value | source |
| --- | --- | --- |
| patience for a SOCKS connect | **45 s** | `P2P_DEFAULT_SOCKS_CONNECT_TIMEOUT` ([`cryptonote_config.h:191`](../../src/cryptonote_config.h#L191)), applied at [`net_node.cpp:415-419`](../../src/p2p/net_node.cpp#L415) |
| penalty for exceeding it | **3600 s** | `P2P_FAILED_ADDR_FORGET_SECONDS` ([`:201`](../../src/cryptonote_config.h#L201)) |
| ratio | **1 : 80** | — |

A node waits 45 seconds for a descriptor fetch and, on missing it, buys an hour
of blindness to that peer. Neither constant is unreasonable alone; **the ratio
between them is what makes a transient fetch permanent-ish**, and neither was
chosen with the other in view.

**Measured first-dial failure rate: ~7 in 30**, on six well-provisioned hosts
across three providers with every descriptor confirmed published. That is the
input the derivation in §11.6 needs, and it is not small.

#### Correction to the record

An earlier reading of this rehearsal attributed `use`'s low inbound count to
suppression left over from **restarting its tor**. That mechanism was wrong: no
node dialled anything before the gate passed, because the phase-2 daemons are
peerless and stagenet has no compiled seeds. The real cause is the post-gate
failure above — `jp` burned `use` at `01:35:38Z` and will not retry it until
`02:35:38Z`. The *conclusion* survives (a node needing a restart carries
depressed inbound, and inbound is half the readout); the *reason* was
misattributed, and the corrected reason is worse, because it needs no restart to
occur.

**Found for the price of one dev box.** The smoke test existed to check that
stagenet's anonymity zone forms at all; it found the scheduling defect that
would have silently corrupted the first paid arm — and then a second one.

### 11.6 Q12-R13 is one onboarding defect, not two findings

**Ruled 2026-08-11.** The suppression window and the publication failure are
filed together deliberately. **Neither is serious alone**; composed, they
produce a silent failure at first launch that the operator cannot diagnose:

| ingredient | measured | alone it is |
| --- | --- | --- |
| a hidden service that starts, reports healthy, and never publishes | **2 of 2 trials showed one**; ~1 in 5 instances | an annoyance — restart tor |
| a first dial that misses its 45 s window | **~7 in 30** post-gate | a retry — except there is no retry for an hour |

**Composed, the observed behaviour is: "Tor works after you restart it once."**
A new node's hidden service fails to publish; it dials its seeds anyway; the
dials fail; all seed onions are suppressed for 3600 s; the operator sees a node
with no anonymity peers and — reaching for the standard remedy — restarts it,
which clears both the tor-side publication failure *and* the daemon-side
suppression cache at once. **It then works, and nothing in the logs at default
verbosity says why.** Roughly one operator in five meets this, concludes Tor
support is flaky, and is right for reasons no one can see.

**The gate this run builds is the fleet's workaround. Mainnet has no operator
running it.** That is precisely why this is filed as a defect against the daemon
rather than as a run precondition.

The suppression half is not a property of fleets either. Run the same sequence on
mainnet with a real new user:

1. A node starts with `--tx-proxy tor` and dials the compiled onion seeds
   (Q12-R1's list, once it lands).
2. Its tor is freshly bootstrapped and its circuits are new. Some or all seed
   descriptors are **published but not yet fetchable through those circuits** —
   exactly what the smoke test reproduced.
3. Every dial fails. Every seed onion is now suppressed **for an hour**, keyed on
   the onion, with no retry path and no clearing path.
4. The node has no anonymity peers, cannot self-announce, and therefore receives
   no inbound. **On restart it does the same thing**, because the state that
   would have made the second attempt succeed is tor's and the state that
   suppresses it is the daemon's.

**This is Q12-D6a's spiral reached by a mechanism the design did not predict.**
D6a's spiral is *no outgoing anonymity connection ⇒ no self-announcement ⇒ no
inbound*. R13 supplies a new entrance to it: **one badly-timed dial round costs
an hour, and the failure is at the descriptor layer rather than the peer's.**
The peer is up. The peer is correct. The peer is unreachable for a reason that
has nothing to do with the peer.

**The constant is inherited from the IP era and its justification does not
survive the transport change.** `P2P_FAILED_ADDR_FORGET_SECONDS = 3600` is
reasonable for an IPv4 address: a failed dial usually means a down host, and an
hour of not retrying a down host is polite and cheap. A failed *onion* dial is
frequently a transient descriptor fetch against a host that is up, and an hour
is neither. Same shape as `FORWARD_DELAY` and `peers = 8`
([`16-architectural-inheritance`](../../.cursor/rules/16-architectural-inheritance.mdc)):
a constant carried across a boundary its derivation never crossed.

**Ruled: the suppression window is a property of the transport, and the anon-zone
value is derived, not picked.** The shape is settled here; the number is not
invented here ([`76-device-provisioning-floor`](../../.cursor/rules/76-device-provisioning-floor.mdc)
— provisioned at the floor, from a measurement, never at whatever was handy):

- `is_addr_recently_failed` must consult a **per-zone** window rather than one
  global constant. The public zone keeps 3600 s; its justification is intact.
- The anonymity-zone window is provisioned from the **descriptor-fetch latency
  distribution**, which this run can measure directly — the fleet dials 60
  onions from 60 tor processes and `wait_onions_reachable.sh` already times
  every one. **The run therefore gains a deliverable it was not built for.**
- Repeated failures escalate; a *first* failure must not cost an hour.
- **The two constants are provisioned as a pair, not separately.** §11.5.1's
  1 : 80 ratio is the defect — 45 s of patience bought with 3600 s of
  blindness — and it exists because
  `P2P_DEFAULT_SOCKS_CONNECT_TIMEOUT` and `P2P_FAILED_ADDR_FORGET_SECONDS` were
  each chosen without the other in view. Whatever the anon-zone window becomes,
  it is derived *against* the connect timeout from the same latency
  distribution, and a change to either reopens the other.

Deriving it needs the run's own numbers, so the constant lands after the arms.
That is a named dependency rather than a deferral
([`22-no-lazy-deferral`](../../.cursor/rules/22-no-lazy-deferral.mdc)): the
measurement that supplies the input is scheduled, and the finding is registered
now so the value cannot be quietly picked in the meantime.

#### Consequence for Q12-D9: the below-floor state is stickier than the ruling assumed

§12 ruled `x = 0` — a node below F-8b's floor stops stemming until the floor is
met. **That rule assumes the node can climb back**, which is the whole reason
`x = 0` was preferred over holding: the exposure is *bounded* because the node
recovers.

Under R13 it may not. A node that drops below the floor because a round of dials
failed has those addresses suppressed for an hour, and the peers it would climb
back with are precisely the ones it just burned. The below-floor state is
therefore **stickier than §12.1's trade priced**, and on a young network — where
Q12-R11 says *every* node is below the floor by arithmetic — the two interact:
the population is too small to reach the floor, and the retry path that would
find the few peers there are is suppressed.

**This does not reverse §12's ruling** — `x = 0` remains right, and the
alternatives are worse under stickiness rather than better. It changes the
**cost side of the trade**, which §12.1 stated as "the operator's own and
bounded". The bound is an hour longer than it appeared, and the live floor check
(§12.2) must be read against a peer count that cannot recover promptly. Recorded
here rather than silently inherited by the implementation.

### 11.7 The two constants have different derivations — and the suppression one is not a latency question

**Ruled 2026-08-11, correcting §11.6.** That section said the anon-zone window
is derived from the descriptor-fetch latency distribution. **That is the
coupling error again**, applied to the fix rather than to the defect: the two
constants form a ratio that matters, but they are not one decision.

| constant | the question it answers | derived from |
| --- | --- | --- |
| `P2P_DEFAULT_SOCKS_CONNECT_TIMEOUT` | *how long before concluding this dial failed?* | the fetch-latency **tail** — `P(fetch > t)` on a cold descriptor cache |
| `P2P_FAILED_ADDR_FORGET_SECONDS` | *how long before retrying a failed address?* | the cost of **retrying** against the cost of **blindness** — no latency in it at all |

On an anonymity zone the cost of retrying is one SOCKS connect over an existing
circuit. The cost of blindness is a candidate removed from a pool that is small
by construction and governed by a live floor. Those point at a far shorter
suppression than 3600 s regardless of what the latency distribution says.

#### The maintainer sweeps the whole pool long before the hour is up

`m_connections_maker_interval` is `once_a_time_seconds<1>`
([`net_node.h:498`](../../src/p2p/net_node.h#L498)) and `connections_maker`
loops `while (conn_count < max_out_connection_count)`
([`net_node.inl:1795`](../../src/p2p/net_node.inl#L1795)) — it keeps dialling
until the target is met or candidates run out. Failed dials cost up to 45 s
each and run sequentially, so a pool of a dozen candidates is **fully attempted
within minutes**, against a suppression measured in hours.

**So the burned set is not accumulated slowly; it is established almost at
once**, and the node then sits with whatever survived for the rest of the hour.

#### Floor reachability, which is the actual derivation

With `A` anonymity-capable nodes, a node has `A − 1` candidates and needs `F = 12`
of them. If each dial independently burns its candidate with probability `p`,
the node reaches the floor only if at most `A − 1 − F` burn:

| `A` | candidates | `p = 0.10` | `p = 0.23` (measured) | `p = 0.35` |
| --- | --- | --- | --- | --- |
| 13 | 12 | 0.282 | **0.043** | 0.006 |
| 15 | 14 | 0.842 | **0.343** | 0.084 |
| 20 | 19 | 1.000 | 0.950 | 0.666 |
| 30 | 29 | 1.000 | 1.000 | 0.997 |
| 60 | 59 | 1.000 | 1.000 | 1.000 |

**At `A = 15` and the measured failure rate, two nodes in three cannot reach the
floor** — not because the peers are absent, unreachable or refusing, but because
the node has blacklisted them for an hour.

#### This widens Q12-R11 substantially, and changes its reason

R11 said the floor is unreachable by **arithmetic** at `A ≤ 12`, because
`12 > A − 1`. This says it is unreachable by **suppression** up to roughly
`A ≈ 19` — a band half again as wide, for a completely different reason, and one
that no amount of population growth inside that band fixes. Both bite exactly
where rule 76 says to provision: at a young network.

**It also confirms the sequencing ruling.** An `A = 15` arm run under the
current constants would report roughly a third of nodes at the floor and
two thirds below it — and that would have been written up as a discovery
finding. It is a suppression finding wearing discovery's clothes.

#### What the fix has to satisfy

`p` cannot be tuned; it is the network's. What can be tuned is **how many
attempts a candidate gets inside the node's time-to-floor budget**, because
independent attempts compound: at `p = 0.23`, three attempts leave `p³ ≈ 1.2 %`.

- The suppression must be short enough that each candidate is retried **~3
  times** within the window in which a node is expected to reach the floor.
- With a sweep costing minutes, that puts the **first-failure** window at
  **order 60–120 s**, not 3600 s.
- **Escalate on repeated failure** — doubling toward the public-zone value — so
  a genuinely dead peer is not dialled forever while a transient one recovers
  quickly. This is what makes the short first window safe.
- The public zone is untouched: 3600 s remains right where a failed dial means
  a down host.

The exact first-failure value is set once the fetch-latency tail is measured,
because it must exceed the timeout it is retrying against — that is the only
place the two constants genuinely couple.

### 11.8 Measured: the timeout is already right, and the whole defect is the suppression

**60 cold descriptor fetches**, from a warm bootstrapped tor to 60 freshly
provisioned hidden services published 180 s earlier, probed at a **120 s cap** so
the distribution is observed rather than censored at the 45 s constant under
test.

| statistic | value |
| --- | --- |
| median | **7.9 s** |
| p85 | 78.3 s |
| failures | **8 / 60 = 13.3 %** |
| dials exceeding 45 s | **9 / 60 = 15.0 %** |

**The distribution is bimodal, not heavy-tailed.** Every one of the eight
failures sat at the 120 s cap — `119.2, 119.4, 119.5, 119.5, 119.5, 119.6,
119.6, 119.7` — and exactly one success landed between, at 78.3 s. A fetch
either resolves in **under ~30 s** or it does not resolve at all.

Which makes the timeout question answerable without judgement:

| timeout | dials that fail |
| --- | --- |
| 30 s | 15.0 % |
| **45 s (current)** | **15.0 %** |
| 60 s | 15.0 % |
| 75 s | 15.0 % |
| 90 s | 13.3 % |
| 120 s | 13.3 % |

**Anything from 30 s to 75 s gives the identical result.** Going to 90 s buys
one dial in sixty. **So `P2P_DEFAULT_SOCKS_CONNECT_TIMEOUT = 45` is not
changed** — no value in a sane range does better, and a longer one only makes a
node wait longer to learn the same thing.

**This measurement's value is a negative one, and it should be cited that way.**
The obvious response to "15 % of dials fail" is *raise the timeout*. Bimodality
forecloses it, and the single success in the gap is `n = 1`. The measurement
earns its cost by killing the plausible wrong fix before a round is spent on it,
leaving the suppression as the entire defect. **Equally, nothing here justifies
*lowering* 45 s**: `n = 60` through one client tor is far too thin to move a
constant downward, and the failures are not slow dials that a shorter timeout
would catch sooner — they are dials that never resolve. The earlier framing of "45 s of
patience" as the deficient half was wrong: it is generous by six times over the
median, and the failures are not slow, they are *absent*.

**The entire defect is therefore the suppression.** That is a one-constant
change plus escalation rather than a re-provisioned pair — smaller, and better
justified, than §11.7 anticipated.

**And it makes the suppression's disproportion worse, not better.** The failing
15 % are attempts against services that are *fine*, whose descriptors publish or
refresh within minutes. The daemon responds to a condition that resolves itself
in minutes by refusing to look for an hour.

#### Replicated five times, and every intermediate estimate was reported at whatever `n` was to hand

| round | failures |
| --- | --- |
| 1 | 8/60 = 13.3 % |
| 3 | 3/60 = 5.0 % |
| 5 | 9/60 = 15.0 % |
| 6 | 5/60 = 8.3 % |
| 7 | 13/60 = 21.7 % |
| **pooled** | **38/300 = 12.7 %**, 95 % Wilson CI **[9.4 %, 16.9 %]** |

The single-round spread is 5.0 % to 21.7 %, and this section's estimate moved
**13.3 % (n = 60) → 9.2 % (n = 120) → 12.7 % (n = 300)** as rounds accumulated.

**Each intermediate figure was reported as though it were the estimate**, and the
"correction" from 13.3 % to 9.2 % was itself premature — it happened to be a
second draw from a wide distribution. The eventual value is within a point and a
half of the first one. **The defect is not any of the numbers; it is publishing a
point estimate from a sample too small to distinguish it from its neighbours**,
which is the same shape as reading a latency experiment at 48 of 60. A rate
quoted without an interval invites exactly this.

Recorded because the conclusion never depended on it: §11.7's reachability table
is evaluated at 0.10, 0.23 and 0.35 precisely so that no single estimate is
load-bearing.

**The general form, since this arc produced it twice.** *When a measured rate
feeds a decision, carry the interval through the decision — do not pick a value
and then defend it.*

That is what made the correction chain harmless here. The reachability table was
evaluated across the plausible range before any estimate had settled, so
13.3 % → 9.2 % → 12.7 % moved no conclusion; the answer at `A = 15` is "the floor
is not reliably reachable" at every rate in the interval. Had the table been
computed at one number, each revision would have required re-deriving it, and
the natural move at that point is to defend the number rather than redo the
work.

**Precision claimed by revision is the failure mode to watch for.** A sequence of
restatements reads as convergence even when no estimate in it was
distinguishable from its neighbours at the sample in hand — the same shape as
reading a duration experiment at 48 of 60, with the bias source moved: there,
incompleteness correlated with the quantity; here, a small sample was mistaken
for a better one because it arrived second.

The same discipline is why `P2P_ANON_FAILED_ADDR_FORGET_SECONDS` **names its
quantile at the constant** (§11.12). A bare `240` invites a later reader to
adjust it toward a value that looks more central; `240 = p90 of measured
recovery` states what would have to be re-measured to move it.

#### The measured rate is a floor, and the ring says by how much

**12.7 %** (CI 9.4–16.9 %) here against **~23 %** in the six-host ring. The gap is the
self-selection this rig was built with: freshly provisioned, healthy services
published by one tor on one well-connected host. Real peers may be mid-restart,
throttled or dead.

**Which rate is used matters, and the two are not interchangeable:**

| rate | population it describes | floor reachable at `A = 15` |
| --- | --- | --- |
| 12.7 % (rig) | healthy services on one well-connected host — a **floor** | ~74 % — marginal |
| ~23 % (ring) | real nodes across three providers — **representative** | **~34 % — decisive** |

So the reachability finding **rests on the ring**, which is why the rig was
labelled a floor from the outset rather than after the numbers came in. Quoting
the two as a range would let a later reader take the convenient end; §11.7's
table is computed at 0.10, 0.23 and 0.35 precisely so the conclusion can be read
off at whichever rate a reader believes.

**The ring's failures also name the mechanism**: four of its seven timeouts
targeted the *same* node — the one whose tor had been restarted 3.6 minutes
earlier — and the failures cluster on **targets**, not on dialers. A restart
republishes with new introduction points while clients may still hold the old
descriptor. **So the documented remedy for a service that never published
(restart tor, §11.5) creates a window in which every node that dials during it
burns that target for an hour.** The operator's fix propagates suppression to
everyone else.

#### A methodology error worth recording

At 48 of 60 attempts this experiment read **0 failures, max 29.6 s**, and was
nearly written up as "the timeout is comfortable". The completed run says 13.3 %
failure with a p85 of 78 s.

**Fast attempts finish first.** Reading a latency experiment while it is still
running samples the head of its own distribution, and the incompleteness is
*correlated with the quantity being measured*. That is the same defect class as
the rest of this arc — a check sharing a fate with its subject — reached this
time by reading results that were still being produced.

**The bias is structural, not bad luck**: *any* partial read of a duration
experiment reads fast. The countermeasure is the one already in
`read_anon_histogram.sh` — **refuse to report below the expected count** — which
is now the fourth time refuse-don't-clamp has been the answer in this arc.

### 11.9 Every missing link was a burn, and they all expired on schedule

**The six-host ring was sampled every ~3 minutes for an hour.** The result is the
strongest confirmation available, because the prediction was made in advance
from a constant read at source.

| sample (UTC) | total links | `use` inbound |
| --- | --- | --- |
| 02:21:52 – 02:34:49 | 21–23 of 30 | **1** |
| **02:38:05 onward** | **30 of 30** | **5** |

Seven links were missing at 02:34:49. **Seven timeouts appear in the six nodes'
logs**, every one of them at daemon start:

| dialer → target | burned | expires |
| --- | --- | --- |
| jp → use | 01:35:38 | 02:35:38 |
| eu → use | 01:35:39 | 02:35:39 |
| usw → brz | 01:35:40 | 02:35:40 |
| brz → aus | 01:35:43 | 02:35:43 |
| aus → use | 01:35:44 | 02:35:44 |
| aus → brz | 01:36:40 | 02:36:40 |
| brz → use | 01:37:06 | 02:37:06 |

**All seven expire inside an 88-second window, and the very next sample reads a
complete mesh.** The correspondence is exact: 7 burns, 7 missing links, 30/30
once they aged out.

**So the plateau was never churn, and it was never discovery.** Discovery had
finished long before; the graph was being held incomplete by the failure cache
alone. An earlier reading of this data as "a band of 21–23, not a decline" was
the **third** premature conclusion of the session — and the per-node series is
what refutes it, because every node's count is monotone and then flat, which no
oscillating process produces.

**Which settles a measurement requirement for the arms.** A fleet total hides
this completely: a node steady at 20 and a node oscillating across 12 are
indistinguishable in a sum, and at `A = 60` the floor is **per node**. The arms
record **per-node time series**, not a total with a spread.

#### Steady-state churn, over the full hour — and the contrast that matters

21 samples. After the burns expired the ring held **30 of 30 for the remaining
50 minutes**, with a single `29` at 03:23:27 recovered by the next sample.

**So genuine churn exists and is small — and it recovers in minutes.** That is
the contrast worth keeping: an ordinary link loss re-establishes inside one
three-minute sample, while a *burned* one is gone for an hour. The two are the
same observation in a total and completely different in a time series, which is
the second reason the arms need per-node series rather than a fleet sum.

### 11.10 Publication freshness dominates the failure rate — 55 % against 12.7 %

The same 60-service rig, probed with **no publication settle** instead of 180 s:

| | settled 180 s | probed immediately |
| --- | --- | --- |
| failure rate | **13.3 %** | **55.0 %** |
| median success | 7.9 s | 18.4 s |
| dials exceeding 45 s | 15.0 % | **61.7 %** |

**A freshly published service is four times more likely to be undialable**, and
this is the mechanism behind §11.5's finding rather than a separate one.

#### The restart loop — the remedy causes the symptom that prompts it

Compose the measurements and a self-reinforcing cycle falls out, with every step
observed rather than supposed:

1. A node's hidden service **fails to publish** on first start — **1 in 5**
   (§11.5, two trials).
2. The operator applies the documented remedy: **restart tor**.
3. The restart republishes with **new introduction points**, and for a window
   afterwards dials against it fail at **55 %** (§11.10) while clients may still
   hold the old descriptor.
4. Every node that dials during that window **burns the onion for an hour**, so
   the node's inbound collapses and it looks broken.
5. The operator restarts again.

**The fix for not publishing is what keeps the node unreachable.** This is
Q12-D6a's spiral reached from a direction the design was not watching: not *no
outgoing connection ⇒ no self-announcement ⇒ no inbound*, but *the repair
sustains the failure*.

**The dress rehearsal reproduced it at n = 1 and it was written up as residue.**
`use` — the node whose tor was restarted 3.6 minutes before the daemons started
— took **four of the ring's seven burns** and sat at `anon_in = 1` for the full
hour. Failures cluster on **targets**, not dialers.

#### Settled: failures do NOT correlate through the dialer

The rig was extended to record each attempt's **start** time, which the first
version omitted — without it every failure ran to the cap and so was the last
*completion* by construction, carrying no timing information at all.

**Four settled rounds, 240 attempts, 30 failures**, Wald–Wolfowitz runs test per
round on the start-ordered sequence:

| round | failures | runs | expected | z |
| --- | --- | --- | --- | --- |
| 3 | 3/60 | 7 | 6.7 | +0.45 |
| 5 | 9/60 | 18 | 16.3 | +0.88 |
| 6 | 5/60 | 9 | 10.2 | −1.04 |
| 7 | 13/60 | 22 | 21.4 | +0.24 |
| **combined (Stouffer)** | | | | **+0.27, `p` = 0.79** |

**No clustering.** Failures are dispersed in start time, which is what
independent per-dial failure looks like — so the binomial in §11.7 is the right
model rather than the optimistic one, and the `p³` compounding that justifies
three retries holds.

**The test carries its own positive control.** Run on the *unsettled* condition
it returns **z = −5.30, `p` < 0.001** — strongly clustered — because publication
progress at the targets makes the failure rate decline monotonically across a
run (94 % → 83 % → 14 % by start-time third). So the instrument detects
clustering when clustering exists, and finds none once the trend is removed.

**That confound was self-inflicted and worth recording.** The unsettled condition
was chosen *because* it produces enough failures to have power, and doing so
imported the very time trend the test was meant to detect. **A powered test of
the wrong quantity is worse than an underpowered one**, because it yields a
confident number: reported alone, `z = −5.30, p < 0.001` would have read as the
session's strongest result and been an artifact of the condition chosen to
measure it.

### 11.11 Two constraints on the retry design that the derivation missed

**Dialing is serial and blocking.** `make_expected_connections_count` makes **one**
attempt per call ([`net_node.inl`](../../src/p2p/net_node.inl), the
`make_new_connection_from_peerlist` branch) and `connections_maker` loops on its
boolean result. Each failure therefore costs up to the full 45 s **in sequence**,
so one pass over twelve candidates at a 23 % failure rate already spends minutes
on failures alone, and three attempts per candidate puts the worst case at the
order of half an hour.

**Time-to-floor is therefore a constraint in its own right**, and the retry count
must be derived against it rather than against `p^n` alone. It also composes with
§12's live check: a node below the floor is out of the anonymity zone for that
entire window.

**Escalation must reset on a successful handshake.** Doubling toward the
public-zone value is right for a service that is genuinely gone. But a
transiently flaky peer — fails, succeeds, fails — would otherwise ratchet up to
3600 s and arrive at the same defect by a slower road. **The fix decays into the
thing it replaces unless the counter is cleared on success.**

### 11.12 The first-failure window, measured

**20 hidden services, published and verified dialable, then their tor restarted
with the same keys** — the documented remedy of §11.5, which is exactly the
event a dialer walks into. A fresh client polled all 20 until each answered:

```
20 20 20 21 21 22 25 80 96 96 103 136 136 137 138 139 222 239 259 262   (seconds)
recovered 20/20   min 20 s   p50 96 s   p90 239 s   max 262 s
(nearest-rank quantiles, n = 20 — the same estimator the constant is set from)
```

**Every service came back.** Nothing was permanently broken by the restart — the
peers were up and correct the whole time, and undialable for between 20 seconds
and four and a half minutes. Against `P2P_FAILED_ADDR_FORGET_SECONDS = 3600`,
the daemon answers a four-minute condition with an hour of blindness.

#### Provisioned at the TAIL, not the median

| candidate first window | first retry succeeds | three attempts cost |
| --- | --- | --- |
| 120 s | 55 % | 2460 s |
| 180 s | 80 % | 2880 s |
| **240 s (p90 = 239 s)** | **90 %** | **3300 s** |
| 300 s (covers max) | 100 % | 3720 s — **exceeds the hour** |

**Ruled: `P2P_ANON_FAILED_ADDR_FORGET_SECONDS = 240`, the p90 of measured
post-restart recovery.**

**The asymmetry is one-sided, which is what forces a quantile.** A window that is
too short retries *into the same dead interval*: it fails, escalates the
counter, and pushes the next attempt further out. Under-estimating therefore
**compounds** rather than degrades, while over-estimating costs only a slightly
slower first retry. An earlier draft of this section argued the opposite — that
a short first window is "self-correcting" because escalation absorbs it. **That
was wrong, and wrong in a recognisable way**: the escalation ladder exists for a
peer that is *genuinely gone*, and using it to absorb a mis-provisioned first
value is machinery defending a wrong number.

This is `F`'s provisioning shape and `hop`'s missing one: a distribution whose
tail is more than twice its median (96 s against 262 s) cannot be summarised by
its centre when the cost of being under is the failure being fixed.

**p90 is also the largest quantile the retry budget admits.** Provisioning at the
observed maximum would put three attempts at 3720 s — *more than the hour this
constant exists to avoid spending*. The tail requirement and the time-to-floor
bound meet at p90 rather than merely coexisting there.

**The quantile is stated at the constant itself**, in `cryptonote_config.h`, so
the next reader knows the value is a tail figure and does not "correct" it
toward a central one.

#### Time-to-floor, checked rather than assumed

Dials are serial and blocking (§11.11), so the retry count has a wall-clock cost:

| attempt | window | + 12 serial dials at 45 s | cumulative |
| --- | --- | --- | --- |
| 1 | 240 s | 540 s | 780 s |
| 2 | 480 s | 540 s | 1800 s |
| 3 | 960 s | 540 s | **3300 s** |

**Three full attempts at every one of twelve candidates costs less than the hour
the unfixed code spends on a single failure.** That bound is asserted in
`tests/unit_tests/node_server.cpp` rather than left in prose, so a future
re-derivation of either constant has to keep it true.

#### Two rates, not one range

These are **different quantities** and folding them together hides the thing the
fix is for:

| quantity | what it is | measured |
| --- | --- | --- |
| **steady-state dial failure** | a dial against a settled, healthy service | 13.3 % (rig), 15 / 25 / 20 % (three restart baselines), ~23 % (the six-host ring) |
| **post-restart dial failure** | a dial *inside the window the operator just created* | **55 %** |

The first sets the reachability arithmetic in §11.7. **The second is the
restart-loop's magnitude**, and it is the one that makes the documented remedy
actively harmful: a *majority* of dials fail during exactly the interval the
operator opened by applying the fix, and each of them costs an hour under the
unpatched constant. Reported as a range, the 55 % reads as an outlier in a
noisy measurement rather than as the mechanism.

### 11.13 The launch condition, stated plainly

Composing §11.7's reachability with §12's below-floor rule: below the floor a
node does not stem on the anonymity zone. At `p ≈ 0.15–0.23` the floor is
unreachable up to roughly `A ≈ 19`.

**So under the current constants, on a young network, no Shekyl node anywhere
stems over Tor** — and the operator sees a working Tor connection, peers,
traffic, and no indication that the stem is not running.

That is the launch condition, and it is now a number rather than a concern. It is
also the reason the pairing fix is **pre-genesis**: the constant that makes Tor
stemming work at launch cannot be one we intend to change after launch.

---

## 12. Q12-D9 — the below-floor rule, settled before the run

> **Amended by Q12-R13 (§11.6), 2026-08-11 — the ruling stands, its cost
> estimate does not.** `x = 0` was chosen because the operator's exposure is
> *bounded by recovery*. A node that fell below the floor through failed dials
> has those peers suppressed for an hour and cannot promptly climb back, so the
> below-floor state is stickier than §12.1 priced. The alternatives are worse
> under stickiness, not better; what changes is the size of the accepted cost
> and what the live check in §12.2 must expect to see.

**Ruled 2026-08-11, and deliberately before the arms.** The below-floor rule is
**not an input to the run — it is the mechanism the run observes.** At `A ≤ 12`
every node is below the floor by arithmetic (Q12-R11), so the below-floor branch
is the *only* behaviour exhibited. Running with it undecided means the fleet
measures whatever the code happens to do, and the decision is then read off the
run — deriving a rule from an implementation accident, which is the failure
Q12-D8 names. §12.11 already made this mistake once: thresholds deliberately
unset, mechanism live, semantics pinned only afterwards.

### 12.1 The answer follows from the floor's own justification

F-8b's floor is not a quality preference. `hop` and `F` were provisioned at
**`OutboundOnly@12`**, so the floor is *the condition under which the derived
constants are valid*. A node with 4 anonymity connections is not running the topology
the embargo was derived for: its fluff return is slower, so `F` is
under-provisioned **in the privacy-losing direction**, and its own transactions
carry an embargo too short for the graph they traverse.

| candidate | verdict |
| --- | --- |
| **stem anyway** | **rejected** — ships a known-invalid provisioning to the operator who chose Tor, invisibly. §75's shape: the failure has no feedback channel. |
| **hold** | **rejected** — at `A ≤ 12` this is not a transient stall but *every* Tor node holding indefinitely on a young network. A liveness failure dressed as caution. |
| **don't stem (`x = 0`)** | ~~**chosen**~~ **OVERTURNED 2026-08-15** — chosen here, measured in §17, re-ruled in §18: the node **stems anyway**, and the check becomes a local diagnostic. This row is kept as written because the reasoning above it was sound on the premise it had; the premise is what §17.6 removed. |

The trade is a real cost against an invisible one: an invalid embargo is a
**stranger's** cost and unobservable, where `x = 0`'s exposure is the
**operator's own and bounded**.

### 12.2 Two implementation constraints that are part of the ruling

**Refused in advance (§16.5): D9's check is a self-provisioning check, not a
sybil defense.** Distinctness on an anonymity zone is structurally unobtainable
— the identifier that would supply it is an eclipse-completion oracle worth more
to an attacker than to a victim — so this check can never be more than a check
on the node's **own** configuration and churn. Any future proposal to "harden
the floor against sybils" is proposing to reintroduce a linkable identifier, and
is refused on that ground rather than re-argued. The input is an
**outbound-connection count**, and §16.6 requires it be a named type that says
so.


- **The check must be live, not once at startup.** Peers churn, and a node above
  the floor can fall below it. This is exactly F-8b's gap: it floors the
  *configured cap*, never the *achieved count*, so a startup-only check would
  re-create the defect Q12-D6a exists to observe.
- **Refuse, don't clamp.** If the anonymity zone cannot satisfy the condition
  its constants were derived under, it is not used — a **state the code
  represents**, not a threshold it approximates. Same device as the depth table.
  *(Superseded as a runtime rule, 2026-08-15: "is not used" was `x = 0`, which
  §17 overturned. The bullet survives at the **configuration** surface — the
  parser/startup refusal — per §18.3's operator-controls/adversary-influences
  split.)*

### 12.3 What it makes the run

The question sharpens from *"does the graph form"* to **"at what `A` do nodes
cross the floor and the anonymity zone become usable at all?"** — a threshold
measurement. **This rehabilitates the `A = 15` arm**, which Q12-R11 had narrowed
to near-complete-connectivity: it is now the arm *nearest the crossing*, and so
the most informative rather than the least.

It also makes the launch condition honest and stateable: **below ~13
Tor-capable nodes the anonymity stem does not engage**, and Tor delivers
IP-hiding at the transport layer without the stem. A degradation with a floor,
not a silent regression.

### 12.4 ~~RESOLVED~~ SUPERSEDED — `x = 0` keeps the zone and drops only the stem (reading (b))

> **Superseded 2026-08-15.** The mechanics below are correct as mechanics and
> are kept for the record; the ruling they implement was overturned by
> measurement (§17) and re-ruled (§18). Nothing implements reading (b) or any
> other `x = 0` variant.

**The ruling says the node "routes clearnet, which exposes its IP as a relay
source". For *relayed* traffic that is right and costless — its home was always
clearnet. For the node's *own* transactions it contradicts a decision already in
the tree**, so it is flagged rather than implemented either way.

`send_txs` splits exactly here
([`net_node.inl:2293-2306`](../../src/p2p/net_node.inl#L2293-L2306)):

> *ORIGINATED traffic (false) takes the zone regardless and **fails closed**:
> falling back to clearnet would put our own transaction on the public network,
> which is the first-spy case this arc exists to prevent (§30.5). **Better to
> send nothing.*** … *RELAYED traffic diverted by R-1's roll (true) must NOT
> fail closed.*

So the arc has already ruled that a node's own transaction never falls back to
clearnet. Two readings of `x = 0` follow, and they differ in exactly the
protected direction:

| reading | own transactions | consistent with `:2296`? |
| --- | --- | --- |
| **(a) abandon the anonymity zone** — all traffic clearnet | IP exposed as origin | **no** — reverses the fail-closed rule |
| **(b) stop *stemming*, keep the zone** — fluff on the anonymity zone | IP still hidden by Tor; stem privacy lost, transport privacy kept | **yes** |

Reading (b) preserves both halves of the ruling's own logic: the invalid
embargo is avoided (no stem ⇒ no stem timer derived at `OutboundOnly@12`), *and*
the operator who configured Tor to avoid IP exposure still gets it. Reading (a)
buys nothing extra and pays the operator's IP for it.

**The distinction is not academic**: under (a), a node's IP appears on clearnet
as a transaction origin the moment the anonymity population dips below 13 — the
exact exposure Q12-D4a check 2 flagged as *"the operator's own cost, not a
stranger's"* but which `:2296` had already refused to impose automatically.

**Ruled 2026-08-11: (b).** The original phrasing reasoned about the *relayed*
case — where the cost is small and the home was always clearnet — and then let
it stand for originated traffic, where the cost is entirely different and
`send_txs` had already ruled against exactly that.

**The floor argument only supports (b).** The floor is a condition *on the
stem*: below 12 anonymity connections the graph is not what `hop` and `F` were derived
at, so the embargo is invalid. That is an argument about **arming a stem
timer**. It says nothing about which transport carries the bytes. Reading (a)
converts *"the stem constants are invalid here"* into *"this zone is
unusable"* — a broader conclusion than the premise supports, and it is the
broadening that costs the operator's IP. Reading (b) takes exactly the premise:
no stem ⇒ no stem timer ⇒ no invalid provisioning, while the zone still carries
the traffic and still hides the IP.

**The two privacy properties are separable**, which is this arc's own grid once
more: transport privacy (the IP) is a **wire-observer** property; stem privacy
(source ambiguity) is a **peer-observer** property. Orthogonal — losing one is
not a reason to discard the other.

| posture | transport privacy | stem privacy |
| --- | --- | --- |
| clearnet node | no | no |
| below-floor node under **(b)** | **yes** | no |
| below-floor node under (a) | no | no |

A below-floor node under (b) is therefore **strictly better off than a clearnet
node**. Under (a) it has neither property, having surrendered transport privacy
to avoid a stem problem the zone was not causing.

#### 12.4.1 The consequence, named so a future reader is not misled

Under (b) a below-floor node **fluffs on the anonymity zone with no stem** —
which is exactly the posture §63 documented and §89 set out to correct.
Verified at source: [`DAEMON_RELAY_PRIVACY.md:8335`](DAEMON_RELAY_PRIVACY.md)
records *"C. Tor / I2P … diffusion — no stem (corrected per §63)"*, and
`:10403` *"the anonymity zone has no stem"*.

**That is fine here, and the record has to say why**, or a future reader finds
the old behaviour alive in a branch and cannot tell whether it is a leftover or
a decision:

| | pre-§89 | below-floor under (b) |
| --- | --- | --- |
| scope | **every** anonymity transaction | a bounded fallback |
| trigger | none — it was the default | achieved anonymity connections `< 12`, checked live |
| known? | **no** — §63 discovered it | stated, with its cost |
| recovery | none defined | automatic once the floor is met |

The difference is not the behaviour; it is that this one has a **stated
trigger, a stated cost, and a stated recovery condition**, where the original
was an unexamined default nobody had noticed.

**Q12-U2 is unblocked.**

### 12.5 Q12-D9 stands. The retraction that was owed was mine, and it was wrong

> **Scope note, 2026-08-15:** what this section defends — that the live
> below-floor check *exists* and its quantity is real — survives §17/§18
> intact. What changed is the check's **consequence**: it no longer gates
> stemming (§18.4).

**2026-08-13.** A conclusion had been carried since the A = 15 arm that §12.2's
*live* below-floor check should be **dropped**, on the ground that *"no
per-node form of the floor condition exists"*. **That is retracted. The check
stands as ruled.**

**The error was the axis, not the arithmetic.** The measurement behind the
dropped-check conclusion asked whether one below-floor node moves *network*
first passage. It does not, materially. But §12.1 does not justify the floor on
the network's behalf — it justifies it on the node's own:

> *"its fluff return is slower, so `F` is under-provisioned in the
> privacy-losing direction, and **its own** transactions carry an embargo too
> short for the graph they traverse."*

So the rule is per-node **and self-regarding**, and a network-axis reading
cannot settle it. Measuring the wrong axis and concluding about the rule is the
same defect class as "assert on the axis where the defect lives": the number
was real, and it answered a question nobody had asked.

**Re-measured on both axes, and the placement is the whole variable**
(`tests/d9_floor_locality.rs`, 60 nodes, 400 trials, 8 seeds, `OutboundOnly`,
degree 10 against a floor of 12):

| arm | mean first passage | vs. baseline |
| --- | --- | --- |
| baseline — every node at the floor | 1613 ms | — |
| **SELF — the below-floor node is the source** | **1736 ms** | **+7.63 %** |
| NETWORK — one below-floor node, elsewhere | 1634 ms | +1.30 % |
| control — every node below the floor | 2095 ms | +29.83 % |

**A single below-floor node slows its own transaction's propagation by roughly
six times what it costs the network.** A per-node form of the condition exists,
it is exactly the form §12.1 argues for, and the live check is the mechanism
that acts on it.

**What the numbers are and are not.** They are a seed-averaged reading of this
instrument at these parameters, reported so the direction and the ~6× ratio
rest on running code rather than on a remembered figure (Q12-D8). They are
**not** a provisioning target: the test asserts only that the instrument
discriminates (whole-network degradation must move the number) and that the two
axes are distinguishable. Pinning a percentage would pin a seed-dependent draw,
which is the defect the `fluff_return_ms` sweep already caught once.

**Why this was worth rebuilding rather than quoting.** The original simulation
did not survive its session, so the conclusion rested on a number nothing could
re-run — and re-running it is what showed the axis was wrong. A design rule
about to be deleted on the strength of an unreproducible measurement is exactly
what Q12-D8's test is for.

#### 12.5.1 The quantity exists at the decision site and is destroyed on the line that reads it

**Verified at source, `eb1fd6d4e`.** The anchor for D9 is **not** in
`net_node.inl`. It is `levin_notify.cpp`, `notify::get_status()`:

```cpp
bool has_outgoing = zone_->p2p->get_out_connections_count();
```

That is the per-zone **achieved** outbound count — D9's quantity exactly —
assigned to a `bool`, so it is truncated to *nonzero*. `select_anonymity()`
accepts on `network->second.m_connect && status.has_outgoing`, so **one live
outbound peer is sufficient**: the zone stems at degree 1 against an embargo
derived at degree 12.

**The configured-axis gates are a different quantity that shares a numeral.**
`set_max_out_peers` refuses a configured cap; `change_max_out_public_peers`
clamps one. `MIN_PROVISIONED_OUT_PEERS = 12` equals `P2P_DEFAULT_OUT_PEERS = 12`,
so **every default operator satisfies the startup gate by construction**, while
the A = 15 fleet measured the condition it stands for as false ~30 % of the
time.

**And the anonymity zone has no runtime path at all.** `set_max_out_peers` has
exactly two callers — `net_node.inl:588` (public, `--out-peers`) and `:625`
(anonymity, `--tx-proxy`) — both inside `handle_command_line`.
`change_max_out_public_peers` has exactly one caller
(`core_rpc_server.cpp:2797`) and resolves `zone::public_` only. So the
anonymity zone's cap is written once, at `:625`, and never again by any path in
the tree. The one function holding `get_out_connections_count()` spends it
*shedding* connections down to a cap — the count is in hand and used to move
away from the floor.

**§12.2 is therefore building a mechanism, not tightening one:** no live check,
and no live path to put one on.

#### 12.5.2 D9 and §30.5 do not collide — the bands are disjoint

They read as rival answers only if both are taken as *zone* verbs. They are not.
`send_txs` decides **which zone** and has no vocabulary for stem-or-fluff — it
forwards `tx_relay` unchanged. The stem-or-fluff decision is one layer down, at
`levin_notify.cpp`'s `dandelionpp_notify` dispatch (*"this will change a local
tx to stem or fluff"*). So a node that rolls anon while below the floor executes
both in sequence without conflict: `send_txs` puts it on the zone,
`dandelionpp_notify` fluffs it there instead of stemming.

The predicates nest rather than overlap:

| achieved anon out-degree | behaviour | ruling |
| --- | --- | --- |
| `0` | zone unusable → send nothing | §30.5 fail-closed |
| `0 < d < 12` | usable, below floor → **fluff in zone, do not stem** | D9 `x = 0`, reading (b) |
| `d >= 12` | stem normally | — |

Disjoint, total, ordered. "Below the floor" covering both the first and second
band is what made one condition look like two answers.

**Placement, pinned before §12.2 is drafted.** The check is **scoped to
origination**, **tested at the stem/fluff decision**, and **never in
`select_anonymity()` or any arm of `send_txs`**. The third clause is the
load-bearing one: refusing the zone there is reading (a) — the §30.5 reversal —
and `select_anonymity()` is the function whose entire comment block explains
why originated traffic fails closed rather than falling to clearnet.

Two consequences follow from the placement. `dandelionpp_notify` is also
reached by **relayed** traffic through the coherence arm, so a check placed on
the shared stem path would change relay behaviour on a **network-axis** warrant
that §12.5's own table prices at roughly a sixth of the self-axis one. And it
would catch the local pool re-relay and the missed submit nudge, which reach
`anonymity_fail_closed` from three different producers.

**Shelved, blocked on the mechanism (rule 7):** what a below-floor node should
do at achieved degree 1, where its fluff has out-degree one. `x = 0` is right
against the embargo argument, but whether a degree-1 *fluff* beats a degree-1
*stem* is a quantitative question about a path that does not run. The
instrument that could answer it now exists and is named:
`simulate_fluff_return_mixed`, which takes a per-node degree vector. Settling it
in §12.2's prose instead would be the failure Q12-D8 names.

---

## 13. The `A = 60` arm — RUN 2026-08-14, and the graph forms

**Status: RUN. The arm's readout is in
[`data/q12-d6a-a60-2026-08-14/series.tsv`](data/q12-d6a-a60-2026-08-14/series.tsv),
committed with this section.** Every previous number in this document came from
a dress rehearsal or a rig; this is the first arm.

### 13.1 What was stood up

| | |
| --- | --- |
| anon population `A` | **60** |
| clearnet detector | **15** (fixed, Q12-R3) |
| hosts / regions / providers | 9 / 9 / 3 |
| binary | one artifact, `sha256 18984a08…`, on all nine hosts |
| bootstrap | 5 seeds cross-peered; **every other node got exactly ONE seed onion** |

The one-seed bootstrap is the discriminator §11.2 (Q12-R5) specifies: *"If
gossip works it reaches 12. If only seeds matter it reaches 1 and stops."*

### 13.2 The result

Twelve samples at ~4-minute intervals, 720 node-samples. Sample 1 is the
settling sample and is excluded from the per-node statistics; it is kept in the
series because excluding it silently is how a settling artifact becomes a
result.

| sample | min | at-or-above floor |
| --- | --- | --- |
| 04:26:24 | **1** | 49 |
| 04:30:26 | 10 | 55 |
| 04:34:28 | 11 | 52 |
| 04:38:30 | 11 | 49 |
| 04:42:33 | 11 | 54 |
| 04:46:35 | 9 | 56 |
| 04:50:37 | 11 | 54 |
| 04:54:39 | 11 | 50 |
| 04:58:42 | 10 | 49 |
| 05:02:44 | 10 | 47 |
| 05:06:47 | 8 | 50 |
| 05:10:50 | 11 | 46 |

**Per node, over the eleven settled samples:**

| | nodes |
| --- | --- |
| always at or above the floor | 10 |
| dips below and recovers | 50 |
| **never reaches the floor** | **0** |

Observation-level, 562 of 660 node-samples (**85.2 %**) at or above 12, and
**every node's maximum is 12 or 13** — there is no node the floor is out of
reach for.

#### "Always above the floor" is not a sample-count-stable statistic

An interim read of this same run at **eight** samples reported *26* nodes
always above the floor and 88.1 % of observations; at **twelve** it is *10* and
85.2 %. The observation rate barely moved. The "always" count more than
halved — and it must, because it is a conjunction over samples: every added
sample is another chance for a node to dip, so the count **decreases
monotonically in sample count** and is not comparable between runs of different
length.

Recorded because the interim figure was written down before the run finished,
which is the same defect as reading a constant off one seed. The statistics to
compare across arms are the **observation-level rate** and **"never reaches the
floor"**; the "always" column is descriptive of this run's length only.

#### An unresolved downward drift

At-floor counts run 55, 52, 49, 54, 56, 54, 50, 49, 47, 50, **46** — the last
third sits lower than the first. Over 40 minutes that is either slow
degradation or the low end of ordinary churn, and **eleven samples cannot
separate them**. §11.9 settled the analogous question on the six-host ring only
by running a full hour and matching every missing link to a specific burn with
a specific expiry.

**Not asserted either way here.** The claim this arm supports is the one the
drift does not touch: no node is structurally below the floor, and every node
reaches it. Whether the settled level is flat at ~50 or slowly falling needs a
longer arm, and that is left owed in §13.7 rather than resolved by picking the
reading that suits.

**The single node reading `1` in the first sample is the finding, not noise.**
That is the bootstrap-only state the control was designed to detect — one
`add-peer`, nothing gossiped yet — and it left that state by the next sample.
Every node reached the out-peer target. **Gossip carries the anonymity graph at
`A = 60`; the seeds are not doing the work.**

### 13.3 What the number is NOT

**12 is the configured target, not merely the floor.** `tx-proxy=…,12` caps
outbound anonymity links at 12, so the ~52 nodes sitting at 12 are *saturated*,
not comfortably clear of the floor. The two nodes reading 13 are inbound-side
artifacts of the same cap. A reader must not take "88 % at or above the floor"
as headroom — the arm shows the floor is **reachable**, not that it is
**exceeded**.

**The dips are churn, and the per-node view is what says so.** A fleet total
cannot distinguish 34 nodes each dipping once from 5 nodes permanently at 11 —
§11.9's requirement, and it earns its keep here: the aggregate oscillates
between 49 and 56 while **no node is ever structurally below**. Every dip
recovers within one sample, which is §11.9's contrast between an ordinary link
loss and a burned onion.

### 13.4 The isolation control passed

All 15 clearnet detector nodes read **0 anonymity links** (`END 15 0`). The
anonymity graph did not leak into the detector set, so Q12-R10's confound —
fleet nodes discovering each other by a route that is not the one under test —
is excluded by measurement rather than by assumption.

### 13.5 Consequence for §11.13's launch condition

§11.13 composed §11.7's reachability with the below-floor rule and concluded
that *"at `p ≈ 0.15–0.23` the floor is unreachable up to roughly `A ≈ 19`"*,
and that on a young network **no Shekyl node anywhere stems over Tor**.

**That bound is not contradicted, and this arm does not test it.** `A = 60` is
far above 19, and the arm measures the regime where the floor *should* be
reachable — it confirms the upper half of §11.13's own claim. The launch
condition concerns small `A`, and the arm that would settle it is `A = 15`,
which is still unrun.

**What this arm does settle** is that the mechanism works when the population
supports it: the graph is not held below the floor by discovery, by the failure
cache, or by hub dependence. A failure at small `A` is therefore a population
effect and not a broken gossip path — which is what makes the `A = 15` arm worth
running rather than a formality.

### 13.6 Three harness findings, all of which would have produced a wrong reading

**Q12-R14 — startup peak is ~2× steady state, and simultaneous starts OOM.** A
fleet instance settles at ~**274 MB** `RssAnon`, but the kernel killed one at
**520 MB** during genesis processing. Sizing a host on steady state and starting
every instance at once killed **exactly one daemon on each 8 GB host** at 15
concurrent starts, and none at 11. A silently-lost instance reduces `A` — the
independent variable — and the arm would report the smaller population's result
under the larger population's label. Instances are now started with a stagger
(`run_arm.sh`), and the phase verifies `alive == want` before continuing.

**Q12-R7 reproduced, from the other direction.** The first build of this arm
defaulted to `ARCH=native` on the dev box and emitted AVX-512; six of the nine
hosts lack it. §9.1 records this exact failure, and the default reintroduced it
the moment a build was made outside the recorded recipe. A rule written in prose
did not survive contact with `cmake -B build`; the portable flags now live in
the container recipe beside the binary they produce.

**The tor expert bundle carries its own libraries.** `tor` ships beside
`libevent-2.1.so.7`, `libssl.so.3` and `libcrypto.so.3` and will not start
without `LD_LIBRARY_PATH` pointing into the bundle — and the bundle sits at
`/home/shekyl/...` on some hosts and `/opt/shekyl/...` on others. Resolved on
the host rather than assumed.

### 13.7 Still owed (as of §13; §§14–15 close two of these)

- **A longer `A = 60` arm** — 11 settled samples cannot separate the observed
  downward drift (55 → 46 at-floor) from ordinary churn; §11.9 needed a full
  hour and per-burn attribution to settle the analogous question.
  **Classification: a true shelf.** Nothing waits on it — the arm's
  distribution is degree-at-target, so it raises `F′` by nothing and 3500 ms
  stands however the drift resolves (§13.7 below, `DAEMON_RELAY_PRIVACY.md`
  §90.3). Its blocker is **fleet provisioning**, i.e. a fresh spend, not an
  unanswered question. Contrast §16.4, which is a **gate**: filing both the
  same way would put the item that is cheap to unblock and the item that is
  blocking at the same priority in whatever reads this list next.
- ~~**Q12-R5's late-joiner control**, both variants.~~ **RUN — see §15.2**
  (seed 56 s, ordinary node 247 s; both reach the floor, so discovery is not
  hub-dependent). Struck rather than deleted: this section was written when the
  control was owed, and the list is read by people skimming for remaining work,
  so an item that quietly vanishes is indistinguishable from one that was
  dropped.
- **A degree distribution for `fluff_return_ms`.** This arm's series is a
  distribution at `A = 60`, but it is degree-at-target (the cap binds), so it
  raises `F′` by nothing: `DAEMON_RELAY_PRIVACY.md` §90.3 shows the conservative
  topology is uniform-at-the-floor, and a population sitting at the cap is
  exactly that. **3500 ms stands as the lower bound, now with a measured
  population behind the assumption it rested on.**

---

## 14. The `A = 15` arm — and §11.13's prediction is too strong

**Status: RUN 2026-08-14**, immediately after §13 on the same fleet, reduced to
15 anon nodes. Readouts in
[`data/q12-d6a-a15-2026-08-14/`](data/q12-d6a-a15-2026-08-14/) — **both** the
clean series and the contaminated one, because the contaminated run is a
finding rather than an embarrassment.

### 14.1 What changed, and what deliberately did not

The 15 were chosen **spread across all nine hosts**, not as indices 0–14, which
would have concentrated the arm on two machines and confounded population with
locality. Clearnet stayed at 15 — it is fixed across arms by design (Q12-R3),
so it is the one thing that must not scale with `A`.

Seeds dropped 5 → 2. Holding 5 would make the seed set a **third** of the
population, which is §7's own distortion warning ("at `A = 15` four well-known
hubs are a quarter of the population") applied to our harness. 2/15 = 13.3 %
against 5/60 = 8.3 % is the closest a cross-peerable seed set gets.

### 14.2 The result

| arm | at-or-above floor | per-node max | `stored` |
| --- | --- | --- | --- |
| `A = 60` (§13) | 85.2 % | 12–13 | — |
| `A = 15`, **contaminated** | **0.0 %** (0/180) | 4–8 | **60** |
| **`A = 15`, clean** | **52.1 %** (86/165 settled) | **12, all 15 nodes** | **14–15** |

**Every one of the 15 nodes reaches the floor; none sustains it.** Per-node
means run 10.25–11.67 against a floor of 12 and a ceiling of 14.

### 14.3 §11.13's prediction is directionally right and too strong

§11.13 concluded that at `p ≈ 0.15–0.23` **"the floor is unreachable up to
roughly `A ≈ 19`"**, and therefore that on a young network *no Shekyl node
anywhere stems over Tor*.

**Measured at `A = 15`: the floor is reachable — every node touches 12 — but
held only about half the time.** So the strong form is wrong. The *useful* form
survives and is now quantified: crossing 12 is a **coin-flip per sample** at
`A = 15` against a near-certainty at `A = 60`, so a below-floor rule that
suppresses stemming will fire on roughly half of a small network's samples
rather than on all of them.

That is a materially different launch condition from "no node stems", and it is
the difference between a network that cannot stem and one that stems
intermittently — which the arm can distinguish and the arithmetic could not.

### 14.4 The contaminated run, kept deliberately

The first `A = 15` attempt read **0.0 % at floor and 4–8 links**, and it was
wrong. Reducing `A = 60` → 15 left every surviving node holding a **60-address
peerlist**, two-thirds of it now dead hosts, so nodes spent their dial budget on
corpses and burned each into the failure cache.

**The `stored` column is what caught it** — 60 stored candidates in a 15-node
population is arithmetically impossible for a clean run. That column exists for
exactly this ("a node at 11 links with a full white list is churn, the same node
with every candidate burned is the failure"), and it earned its place: nothing
in the *achieved-links* series looked anomalous. A 4–8 plateau is entirely
plausible as a small-population result, and would have been reported as one.

**A second attempt was still not clean**, at 45–60 stored: the wipe raced the
shutdown. Killing the daemon, sleeping 6 s and removing the data directory lets
a daemon still flushing `p2pstate.bin` write the old list back out *after* the
removal, and one surviving node re-gossips it to the whole arm. The third
attempt waits for actual process exit, removes, **verifies removal**, and only
then starts — `stored` reads 14–15, and the result moves from 0.0 % to 52.1 %.

**Recorded as a standing requirement: an arm that changes `A` must start from
verified-empty peerlists, and `stored ≤ A` is the check that it did.**

### 14.5 A caveat the arm surfaced about the floor itself

Raised here because the arm made it concrete: an anonymity peerlist can be
deduped only **by address**, so the floor counts connections rather than
distinct hosts.

**Scoped and settled in §16**, which corrects this section's first framing on
two counts — the sentinel did not *cause* the property, and clearnet has the
same one.

---

## 15. The sweep closes — `A = 30`, and Q12-R5's late-joiner control

**Status: RUN 2026-08-14.** With §13 and §14 this completes the `{15, 30, 60}`
sweep and the bootstrap control. Readouts in
[`data/q12-d6a-a30-2026-08-14/`](data/q12-d6a-a30-2026-08-14/) and
[`data/q12-r5-late-joiner-2026-08-14/`](data/q12-r5-late-joiner-2026-08-14/).

`A = 30` ran on the six permanent seed hosts alone — no VMs were provisioned,
because 30 anon + 15 clearnet fits inside 24.8 GB once the startup peak is
staggered (Q12-R14). Three seeds, 10 % of the population, bracketing 8.3 % at
`A = 60` and 13.3 % at `A = 15`. **`stored ≤ A` was checked at the second
sample** (29–30 in a 30-node population) before any of this was believed —
§14.4's standing requirement, on its first use.

### 15.1 The sweep

| `A` | at-or-above floor (settled) | never reaches it | min after settling |
| --- | --- | --- | --- |
| 15 | 52.1 % | 0/15 | 11 |
| **30** | **84.2 %** | **0/30** | 11 |
| 60 | 85.2 % | 0/60 | 11 |

**The transition is between 15 and 30, and it is saturated by 30.** Going from
30 to 60 buys 1.1 points; going from 15 to 30 buys 32. In all three arms **no
node is ever structurally below the floor** — every node reaches 12 — so what
`A` changes is how *reliably* the floor is held, not whether it is attainable.

**This is the number §11.13's launch condition actually needs.** The concern was
that a young network cannot stem over Tor. Measured: at 15 anon nodes the
below-floor rule fires on about half of samples; by 30 it fires on one in six;
past 30 it stops improving. The operational reading is **~30 anonymity-capable
nodes**, not the `A ≈ 19` the arithmetic implied and not "unreachable".

### 15.2 Q12-R5 — the late joiner, both variants

One new node, **exactly one `--add-peer`**, joining the converged `A = 30`
network from a verified-empty peerlist. Run sequentially, not together: run
concurrently they could peer with each other, which is neither variant.

| variant | its one peer | time to floor |
| --- | --- | --- |
| **seed** | a cross-peered hub | **56 s** |
| **ordinary** | an ordinary fleet node | **247 s** |

**Both reach the floor, so discovery is not hub-dependent** — the thing Q12-R5
existed to test. A node that knows one ordinary peer converges on its own.

**The difference is ~4.4×, and that is the price of hub mediation.** It is not
in peerlist acquisition: both variants held ~30 candidates within 30 seconds,
because the handshake hands over a peerlist immediately either way. It is in
*link establishment* — the seed variant went 2 → 9 → 12, while the ordinary
variant climbed 0 → 2 → 5 → 6 → 6 → 9 → 9 → 10 → 11 → 12 with visible plateaus,
the shape of dial failures and retries against a 240 s window.

**Why the plateaus differ is NOT isolated by this rig** and is not claimed. Both
variants had the same candidate set within 30 s, so the gap is in which
candidates were tried and how many dials failed, and the rig records neither
per-dial outcome. Stated as an observation with its mechanism open.

### 15.3 A measurement error worth recording

The first late-joiner run reported **`anon_out = 0` for 21 minutes** while
`stored` climbed 1 → 31 — a node that learned the whole network and connected to
none of it. That would have been a striking finding. **It was wrong**: the
validated reader put the same node at **12**.

The cause was a hand-rolled `get_connections` filter written inline for the
poll loop, sitting beside `read_anon_histogram.sh` — the instrument with a test
suite, written because *"a consumer that regexes the human format is a defect
waiting to happen"* after an earlier extractor "reported nine values for six
nodes". The same mistake, in the same run, against the same warning.

**Recorded because the failure mode is seductive**: the bad number was
*interesting*. A late joiner that learns 31 peers and links to none is a better
story than one that reaches the floor in 56 seconds, and it survived twenty-one
minutes of polling without once looking implausible. The rule the arc keeps
re-learning is that a second instrument must be validated against the first
before its disagreement is treated as a result rather than a bug.

---

## 16. The floor counts connections — on every zone, and always has

**Maintainer analysis, 2026-08-14, verified at source.** §14.5 raised this as a
Tor-specific consequence of the `peer_id` sentinel. **Both halves of that
framing were wrong**, and the corrected version changes where it files and how
severe it is.

### 16.1 `peer_id` was never a distinctness mechanism, on any zone

Every `peer_id` comparison in `net_node.inl` is one of exactly two things:

- **self-connection detection** — [`:1110`](../../src/p2p/net_node.inl#L1110),
  [`:1209`](../../src/p2p/net_node.inl#L1209),
  [`:1234`](../../src/p2p/net_node.inl#L1234),
  [`:2655`](../../src/p2p/net_node.inl#L2655) — every one guarded by
  `is_public` / `azone == zone::public_`, and the two that inspect live
  connections ([`:1215`](../../src/p2p/net_node.inl#L1215),
  [`:1240`](../../src/p2p/net_node.inl#L1240)) additionally conjoin
  `peer.adr.is_same_host(cntxt.m_remote_address)`;
- **peerlist keying** — `set_peer_just_seen`, our own entry, the announce.

**Nothing counts peers by `peer_id`.** Not on the anonymity zone, not on
clearnet. So the sentinel did not remove a distinctness mechanism; there was
none to remove, and §8.1's decision remains correct on its own terms.

### 16.2 Clearnet has no diversity limit either

`ipv4_network_subnet` appears only in the manual-ban machinery — the blocked
map at [`:209`](../../src/p2p/net_node.inl#L209),
[`block_subnet`](../../src/p2p/net_node.inl#L348) and
[`unblock_subnet`](../../src/p2p/net_node.inl#L399). **There is no netgroup
bucketing, no per-`/16` outbound cap, no stripe diversity in peer selection.**

Clearnet's floor counts connections too. It merely *looks* better because IPv4
is mildly scarce and `.onion` is free.

**So the finding restates:** F-8b and D9 count **connections**, on every zone,
and always have. The sentinel made that legible on Tor rather than causing it.

**Which fixes where it files.** Against the below-floor rule's threat model is
half right — it belongs equally against **F-8b's startup refusal**, which counts
the same way and has been shipping since it landed.

### 16.3 The exploitable direction is the opposite of the one first assumed

Price the adversary's position both ways. An adversary holding `k` of a
victim's twelve anonymity connections:

| the floor reads | what the victim does | what the adversary gets |
| --- | --- | --- |
| **twelve** | stems | the epoch's stem successor is one connection of twelve, so with probability `k/12` it is the adversary — who then sees every origination and forward from that victim, **but ambiguous between origin and relay**, which is the ambiguity D++ is built on |
| **low** | D9(b) fires, fluffs at origin | the adversary holding **any** connection sees the victim as the fluff source: deterministic, every origination, every epoch, **precision ≈ 1** |

**The second is strictly better for the adversary.** So an adversary who can
move the reading wants it **low** — and moving it low costs nothing. No onions,
no sybils: occupy outbound slots, be unreachable at the right moment, or simply
wait, because §15.1's own sweep says the network sits below the floor **47.9 %**
of the time at `A = 15` and **15.8 %** at `A = 30`.

**Therefore the address-counting property makes the floor read too HIGH, and
too high is the direction that denies the adversary the better outcome.** The
twelve-onions eclipse costs a VPS and buys the adversary the *worse* branch.
That is not nothing — under full eclipse the adversary has precision 1 whichever
branch fires, so the floor check changes nothing there at all — but it is not
the severity §14.5 implied.

### 16.4 GATE on §12.2 — the α measurement, pre-registered

**Not a shelf. A gate**, and the distinction is the point: a shelf is something
the queue walks past, and this is something §12.2 walks *into*. Drafting D9's
live check without this answer would settle the question by picking a
semantics, which is the quiet form of the failure shelving exists to prevent.

**Reopening criterion (rule 21): §12.2 cannot be drafted until this runs.**
**DISCHARGED 2026-08-14 — the gate ran; see §17.**
That is the trigger, stated so the queue can see a dependency rather than a
parking space.

#### The question, and why it is quantitative rather than a sign check

§12.1's counter is real: a below-floor node that stems anyway carries an embargo
too short for its own graph, so the embargo expires and it fluffs at origin
**late** — after the stem already leaked to its successor. On that reading
D9(b) does not create fluff-at-origin, it makes it prompt and deliberate
instead of late and additionally leaky.

Write the two branches out and the comparison stops being one-sided. Let `L` be
the cost of losing origin ambiguity and `E` the cost of the extra
stem-successor leak, and let **α** be the probability a below-floor node's stem
completes before any node's embargo fires:

| branch | expected cost |
| --- | --- |
| **D9(b) fires** | `L` — ambiguity lost with certainty, no extra leak |
| **D9(b) does not** | `α·R + (1 − α)(L + E)` — with probability α the stem completes; otherwise the late fluff costs `L` *and* `E` |

`R` is **not zero**, and an earlier draft of this table set it to zero. §16.3
prices it: a stem that completes still hands the epoch's successor to an
adversary holding `k` of 12 connections with probability `k/12`, ambiguously
between origin and relay. Omitting `R` understates the no-D9(b) branch and so
moves `α*` **down**, biasing the comparison toward the very ruling this
section pre-registers as likely — which is exactly the lean a pre-registration
exists to prevent.

So **D9(b) is better iff `L < α·R + (1 − α)(L + E)`**, i.e. iff

> **α · (L + E − R) < E**,  equivalently  **α < α\* = E / (L + E − R)**

`R < L` (ambiguous attribution is worth less to an attacker than certain
attribution), so `α*` is *larger* than the zero-`R` form — D9(b) is favoured
somewhat more than the naive comparison suggests. That can still go either way
on α, which is why it is measured rather than argued.

**Unit for `L`, `E` and `R`: adversary precision**, the same quantity §16.3
uses — `≈ 1` for fluff-at-origin seen by any attacker link, `k/12` per epoch
with origin/relay ambiguity for a completed stem. Naming the unit here is what
keeps the middle band below executable rather than an IOU.

#### What α is, exactly — and why it is not `EMBARGO_FULL_TRAVEL_PROBABILITY`

`EMBARGO_FULL_TRAVEL_PROBABILITY = 0.90` is a **design input**: the shipped
190 s embargo is *solved* so that full travel completes with probability 0.90
**at the provisioning degree of 12**. A below-floor node runs a slower graph, so
its true `F′` exceeds the one the embargo was derived from and its *achieved*
α falls below 0.90. The measurement is that shortfall.

**No new instrument is needed — this is a composition of two that already
ship:**

1. `conformance::converged_fluff_return_mixed` → converged `F′(d)` at a given
   degree distribution, refusing rather than reporting an unconverged draw;
2. `derive::full_travel_probability(&DandelionParams, mean_ticks, tick_millis)`
   → α, with `fluff_return_ms` set to `F′(d)` and `mean_ticks` taken from the
   **shipped** 190 s embargo, not re-solved.

Feeding the degraded `F′` to the *unchanged* embargo is what makes the output
the achieved α rather than a redesign. `fluff_return_ms` enters
`full_travel_probability` through the timer-survival exponent —
`slack_ticks = ceil((h·hop + F′) / τ)` — so a larger `F′` inflates the exponent
and depresses α, which is the mechanism the measurement needs.

**Non-vacuity control, run FIRST and required to pass:** two calls differing
only in `fluff_return_ms` (3250 against 4750) must return different α. If they
do not, `F′` does not reach the computation, the sweep would return ≈ 0.90 at
every degree, and it would "confirm" the `α > 0.5` row on the exact axis the
measurement exists to vary — the `hop_sensitivity` failure (vacuous by input,
hard-coded on the axis its name advertised) repeated one arc later. A sweep
whose control has not run is not evidence.

#### The degrees are taken from the readouts, not chosen

Below-floor is **not** a broad spread over degrees 5–11. Counting below-floor
node-samples in the committed series (`data/q12-d6a-a{15,30,60}-2026-08-14/`):

| `A` | 6 | 8 | 9 | 10 | 11 | share at 11 |
| --- | --- | --- | --- | --- | --- | --- |
| 15 | 1 | 2 | 2 | 7 | 67 | **85 %** |
| 30 | — | — | 1 | 2 | 49 | **94 %** |
| 60 | — | 1 | 2 | 3 | 92 | **94 %** |

**The realized below-floor state is one connection short of the floor**, in
85–94 % of cases, with a thin tail that reaches 6 exactly once across 229
observations. So the headline is **α(11)**, weighted by that distribution;
degrees 6–10 are reported as a tail and are not the decision driver. Sweeping
5–11 uniformly would let the harness author pick the answer by choosing where
to look.

#### Pre-registered decision rule (rule 11) — written before the run

`α*` depends on pricing `E` against `L`, which is a threat-model judgement and
not a measurement. So the rule is stated over the regions where the ruling is
**robust to that pricing**, with the boundaries fixed here in advance:

| measured α(11) | ruling | why it is robust |
| --- | --- | --- |
| **α > 0.5** | **D9(b) does not fire on the provisioning floor.** The branch needs a different threshold or a different mechanism, and §12.2 is drafted against that. | `α* ≤ 0.5` for any `E + R ≤ L` *(corrected post-run — see the amendment note below)*; D9(b) would have to be justified by claiming the extra leak plus the residual successor exposure together outweigh losing origin ambiguity outright. |
| **α < 0.1** | **D9(b) as ruled, threshold = the floor.** §12.2 proceeds as §12.1 specifies. | `α* ≥ 0.1` unless `E < (L − R)/9` *(corrected post-run: the original said "unless `E > 9L`", which is the inequality inverted even in the zero-`R` form)*; outside that corner, D9(b) wins for any defensible pricing. |
| **0.1 ≤ α ≤ 0.5** | **The slice does NOT proceed to §12.2 on the measurement alone.** `E` and `L` are priced on the record first, and the ruling follows from the priced `α*`. | The regions overlap only where the answer genuinely turns on the threat model, and that is a decision, not a reading. |

**Post-run amendment, 2026-08-15 — recorded rather than rewritten, because this
table was frozen before the run.** Review caught that the robustness column
mixed two derivations: this section's own formula is `α* = E/(L + E − R)` with
`R > 0`, and under it `E ≤ L` does **not** give `α* ≤ 0.5` (take `E = L`, any
`R > 0`). The condition for `α* ≤ 0.5` is **`E + R ≤ L`**. The **boundary the
test enforces is unchanged at 0.5**; what the amendment changes is the stated
pricing region over which 0.5 is the supremum — a *narrower* region, so the
claim is weakened rather than strengthened, which is the only direction a
frozen rule may be amended after its run. The `α < 0.1` row's algebra is also
corrected (inequality inverted in the original). The measured result clears the
corrected rule with margin: `α(11) = 0.884 > α*` for every pricing with
`E < 7.6 · (L − R)`, so the ruling survives even well outside the `E + R ≤ L`
region.

**Stated consequence, so this cannot be graded after the fact:** the
`α > 0.5` row is the outcome the arc's own numbers make likely, because degree
11 against a floor of 12 is a small perturbation of the graph the embargo was
derived for. **If that is what the instrument returns, D9's don't-stem ruling
survives as a ruling but its implementation via prompt fluff-at-origin does
not**, and §12.2 must be written against an adversary who *wants* the check to
fire (§16.3) rather than one who trips it by accident.

#### The primary output is the CURVE, not the band

Because that outcome is near-certain at degree 11, "which band does α(11) land
in" is close to a foregone conclusion and would not be a finding. **The
decision-relevant output is `α(d)` as a curve over `d`, and the degree at which
it crosses `α*`** — because that is what §12.2 actually needs: *at what
threshold would this check fire only where it helps?* The floor is 12 by
provisioning, and nothing says the useful trigger for D9(b) is the same number.

This also carries the sharper failure mode, which the bands alone cannot
express:

- **α crosses `α*` at some `d < 12`** → the ruling stands and **the threshold
  is wrong**; §12.2 specifies D9(b) at the crossing degree, not at the floor.
- **α stays above `α*` all the way down to `d = 1`** → **no threshold makes
  D9(b) beneficial**, and the finding is that *the mechanism* is wrong rather
  than its number. §12.2 is then a different section than §12.1 anticipated.

Distinguishing those two is the thing §12.2 turns on, so the curve is
mandatory and the band table is the coarse summary of it.

#### One sequencing constraint

This measurement and the `fluff_return_ms` landing decision (`DAEMON_RELAY_PRIVACY.md`
§90.4) move numbers derived from the **same degree assumption**, and §90.4
records that landing 3500 carries the 190 s embargo, the 874 s wallet timeout
and the §44 pins with it. If D9's threshold turns out not to be 12, the two
changes touch the same conformance vectors. **They must not be concurrent.**

### 16.5 CLOSED — distinctness on an anonymity zone is structurally unobtainable

Not a filed item with an open threat model. **Closed, with a reason**, and it
would remain closed even if the counting problem were more severe than §16.3
finds it.

**A distinctness oracle and a linkability oracle are the same predicate.** *"Can
I tell these twelve addresses are one host?"* and *"can I tell these two
addresses are one host?"* are one question. Any identifier that lets a node
detect twelve onions behind one daemon lets everyone else detect that two of an
operator's addresses are the same operator. That is not a cost trade; it is the
same knob.

**Shekyl already spent that knob.** `shekyl-p-transport::derive_socks_user`
([`lib.rs:134`](../../rust/shekyl-p-transport/src/lib.rs#L134)) gives
per-persona SOCKS stream isolation precisely so a node's personas do not share
a circuit fate, and §10.9 pins one-P-per-wallet-on-wire. A stable per-zone
`peer_id` announced to every peer would hand back, at the p2p layer, the linkage
the transport layer is built to deny.

#### And the oracle is worth more to the attacker — measured by direction, not preference

The symmetry argument alone leaves the trade open: perhaps the defender's use is
worth more. **It is not, and the asymmetry is structural.**

The direction of announcement hands the oracle to the wrong party. Inbound
anonymity connections carry **no client identity** — every hidden-service
listener's `default_remote` is `net::tor_address::unknown()`
([`net_node.cpp:336`](../../src/p2p/net_node.cpp#L336),
default-constructed at [`tor_address.h:71`](../../src/net/tor_address.h#L71)) —
so an attacker accepting N inbound streams sees N identical remotes. But
`get_local_node_data` fills `node_data.peer_id` on the **dialer** side
([`net_node.inl:2153`](../../src/p2p/net_node.inl#L2153)) and the acceptor reads
it into `context.peer_id`
([`:2672`](../../src/p2p/net_node.inl#L2672)). **The victim filling its outbound
slots announces to every attacker onion it dials; the attacker announces nothing
back that matters.**

Eclipse is three steps: get onions into the victim's peerlist (cheap — gossip
does it), get the victim to dial them (probabilistic), and **know it worked**.
Step three has no cheap solution today: grouping must be inferred from
correlated handshake timing, matching sync heights and correlated peerlist
responses — noisy, slow and confounded, because twelve streams from one victim
look much like twelve streams from twelve victims. A distinct `peer_id`
collapses step three to a **field read at handshake, before any traffic**.

That converts eclipse from an open-loop gamble into a closed-loop operation with
a completion signal, and the signal is worth as much as the position: at 9/12 the
attacker knows to publish more onions; at 12/12 it knows **every subsequent
observation is sound** rather than possibly explained by an honest link. The
oracle tells the attacker when its inference is valid, not merely when its
position is complete. A third use needs no eclipse at all — run one onion, accept
inbound, count distinct ids over time, and read out a **census of the anonymity
network**, which is currently unobtainable and bears directly on the `A ≈ 30`
launch condition §15.1 just established.

| | defender's use | attacker's use |
| --- | --- | --- |
| timing | **retrospective** — learns it is eclipsed after it already is | **prospective** — learns when to push and when to start |
| remedy | stop stemming → D9(b) fluff-at-origin, **the branch §16.3 shows the attacker prefers** | publish more onions, **near-zero cost** |

**Same oracle, strictly more valuable to the attacker.** So the sentinel is not a
reluctant trade in which distinctness is surrendered to preserve unlinkability:
**the distinctness it would buy is negative-valued on its own terms**, before the
linkability cost is counted at all.

And it would not work regardless. `peer_id` is self-asserted and free to mint —
an adversary running twelve daemons on one VPS announces twelve distinct ids at
the same cost as twelve onions. A per-zone random value catches the *accidental*
case and nothing adversarial, which is **worse than no mechanism, because it
would read as a defense** in the code and in the doc.

#### The one mechanism with real scarcity, refused

The only scarce resource in the tree that could supply peer-distinctness on Tor
is the archival serving identity — `OnionIdentity::from_hs_id_seed`
([`onion_identity.rs:124`](../../rust/shekyl-tor/src/onion_identity.rs#L124)),
under the `StakeEngine`'s custody since #464. Binding relay peering to it would
make p2p membership **paid**, give every relay peer a **persistent identity**,
and **correlate a node's relay position with its archival service** across two
subsystems that are deliberately separate — a privacy regression wearing a
sybil-resistance argument, the same shape as the "typical hardware" proposal
already ruled against.

### 16.6 What follows, in the code and in the record

**No code change is required by this finding**, and no behaviour changes here.
Three consequences:

1. **The prose stops saying "peers."** Twelve outbound *connections* is what is
   checked, on every zone, and the number does not certify twelve distinct
   hosts. Corrected at three sites in §12.
2. **`ANON_ZONE_SENTINEL_PEER_ID`'s comment now carries the same-zone
   argument.** It previously named only the cross-zone attack — connect to the
   hidden service, read `peer_id`, scan clearnet for a match — and that argument
   **is defeated** by the obvious counter-proposal of a per-zone independently
   random value. A future reader weighing *"can we relax this for sybil
   resistance?"* would have found the objection inapplicable and relaxed it. The
   eclipse-completion argument survives that counter-proposal, so it belongs
   beside it; the invariant now names its own consequence, which is what the
   startup refusal enforces and what its comment previously under-justified.
3. **§12.2's D9 input must be a named type** — an outbound-connection count that
   says what it counts, not a bare `usize`. The substitution is not
   hypothetical: `shekyl_relay_zone_plan_relay_with_refresh` takes
   `(outbound: *const u8, n: usize)` and binds `read_ids(outbound, n)` to a
   local named **`peers`**
   ([`relay_zone_ffi/mod.rs:816`](../../rust/shekyl-ffi/src/relay_zone_ffi/mod.rs#L816))
   while holding connection ids. An earlier estimate that this site "already
   receives the number" is **retracted** — it receives the wrong quantity.

**Refused in advance, in the shape of the Pi-4 ruling:** because distinctness is
structurally unavailable on an anonymity zone, D9's check can never be more than
a check on **the node's own configuration and churn**, and any future proposal to
*"harden the floor against sybils"* is proposing to reintroduce a linkable
identifier. That is a named privacy regression wearing a robustness argument, and
it is refused here rather than re-litigated later.

### 16.7 Lineage — Dandelion++ never had this check

Worth recording so the gap is not read as inherited breakage. §3.1 of
[1805.11060v1](https://arxiv.org/abs/1805.11060) models the adversary as a
fraction `p` of corrupt nodes, states its goal as **mass** deanonymization rather
than targeted attacks, and explicitly places ISP-level adversaries who can
eclipse a node **outside scope**, noting that routing-based defenses cannot
guarantee anything for a targeted node under those conditions.

So `p` is a **free parameter of the analysis**, not a quantity the protocol
bounds. Every result is conditional on it — Fig. 3's precision curves, Theorem
1's bound, §5.3.1's `q = 0.2`. Nothing in Dandelion++ makes sybils expensive and
the paper does not claim otherwise; §4.1.1's 4-regular graph is about robustness
to graph-learning, and even assumes adversarial nodes have the same degree as
honest ones. The CryptoNote line inherits that posture wholesale: address-only
dedupe on non-public zones, and no netgroup bucketing on clearnet either.
Bitcoin has the netgroup/ASN diversity machinery; this lineage never did.

**So Dandelion++ never had this check, and therefore never had this gap.** We
introduced it by deriving a constant from a graph-degree assumption and then
writing a check that reads a number the assumption does not cover — which is the
ordinary way this happens, and is a reason to name the check's limit rather than
to treat it as a defect.

---

## 17. §16.4's gate — RUN, and the ruling is that the mechanism is wrong

**Run 2026-08-14, against the decision rule committed in §16.4 before the
instrument existed** (`a5804d9c7`). Instrument:
`rust/shekyl-relay-privacy/tests/d9_alpha.rs`.

### 17.1 The non-vacuity control passed, and it validates the composition

| `F′` | α |
| --- | --- |
| 3250 ms (shipped, measured at degree 12) | **0.900281** |
| 4750 ms (§90.3's third-below-floor reading) | **0.869051** |

**The control is the two assertions, not the 0.90 reproduction — stated so a
future reader leans on the right one.** The first row is a round trip:
`derive_embargo` binary-searches `mean_ticks` for the smallest value whose
`full_travel_probability` meets the 0.90 target at `F′ = 3250`, so feeding that
pair back through the same function returns the search's own `achieved` field
by construction. It could not have come back anything else, and a modeling
error *inside* `full_travel_probability` moves the derivation and the check
together — it prints 0.900281 either way. What the row does buy: the test
hard-codes 190 s rather than re-deriving it, so the pair is pinned and an edit
to `full_travel_probability` drifts the printed value off 0.90 — a regression
canary on one pinned pair, and proof the harness calls the production
derivation rather than a mirror.

The evidence that the pipeline responds on the axis under test is the pair of
**assertions**: α at `F′ = 3250` and `F′ = 4750` must differ, and the slower
return must produce the *lower* α, with the mechanism named (a longer return
inflates the timer-survival exponent). What rules out the sweep printing 0.90
at every degree is the **sweep's own variation** — 0.884 at 11, ≥ 0.68 across
the measurable range, refusals at 1–2 — which the curve test now asserts
rather than reports (the pre-registered 0.5 boundary at every answering
degree, and the refusals as refusals). A modeling error common to every row —
a wrong slack exponent, a mis-placed RD-4 correction — passes both and is
bounded instead by the analytic/empirical pairing the crate uses elsewhere
(`marginal_preemption_profile` against `simulate_preemption_profile`,
`derive.rs:490`); `full_travel_probability` has no such partner yet, and that
empirical-α companion is the named follow-up, one degree's worth of work.

**The one unarmed premise, recorded beside it because it is the same shape:
`E + R ≤ L` is argued, not measured.** The armed 0.5 boundary is the supremum
of `α* = E/(L + E − R)` over the admissible pricing region — a derivation with
the pricing quantified out, not a threshold picked for tidiness. *(Amended
post-run: an earlier draft stated the region as `E ≤ L` against the zero-`R`
form `E/(E+L)`; with `R > 0` that region does not bound `α*` by 0.5 — the
condition that does is `E + R ≤ L`.)* Its admissibility argument is the capped
unit: adversary precision tops out at 1, D9(b)'s own branch already delivers
≈ 1, so `E` — the increment on an attribution already held — is close to zero
in that unit, and `R`, the *ambiguous* `k/12` exposure, is strictly below `L`,
the *certain* attribution. `E + R ≤ L` follows from both together. Sound, and
nothing in the file covers it: **if `E + R ≤ L` ever fails, the assertion stays
green while the ruling stops following from it.** Both residues are premises
the gate rests on and cannot see.

### 17.2 The curve

| degree | `F′(d)` ms | α(d) | shortfall vs design 0.90 |
| --- | --- | --- | --- |
| 1, 2 | **REFUSED** — stranded | — | — |
| 4 | 16250 | 0.681111 | −0.218889 |
| 6 | 9000 | 0.790112 | −0.109888 |
| 8 | 6250 | 0.839674 | −0.060326 |
| 9 | 5250 | 0.859061 | −0.040939 |
| 10 | 4750 | 0.869051 | −0.030949 |
| **11** | 4000 | **0.884424** | −0.015576 |
| 12 — provisioning reference | 3500 | 0.894940 | −0.005060 |

Monotonicity is asserted, not eyeballed. Degrees 1–2 are a **refusal, and the
refusal is a reading**: the flood strands more than 10 % of nodes, so the
question is ill-posed there rather than answerable with a finite-looking number.

α(12) reads 0.8949 rather than 0.9003 because the sweep uses the **converged**
`F′ = 3500` from #472 rather than the shipped 3250 — the half-point of α is the
cost of the low draw that PR corrected.

### 17.3 The ruling, taken from the frozen rule

§16.4 pre-registered: **α > 0.5 ⇒ D9(b) does not fire on the provisioning
floor**, robust for any pricing with `E + R ≤ L` (as amended — §16.4's
post-run note).

**Measured α(11) = 0.884.** Not marginal, and not sensitive to where in the
observed distribution one looks: α ≥ 0.68 at *every* degree the instrument will
answer for, and the realized below-floor state — 85–94 % of it — sits at 11,
where α is within 1.6 points of the design target.

**And the sharper mode fires too.** §16.4 pre-registered that if α stays above
`α*` all the way down, the finding is that *the mechanism* is wrong rather than
its threshold. The curve does not approach 0.5 anywhere it can be measured, so
**there is no threshold in the measurable range at which D9(b) becomes
beneficial.**

`α* = E/(L + E − R)` seals it in the unit §16.4 named. Adversary precision is
capped at 1, and D9(b)'s own branch already delivers ≈ 1 — so `E`, the
*increment* from the successor leak on top of an attribution the adversary
already has, is small against `L`. Small `E` drives `α*` low, and the measured
α is high. The two are not close.

### 17.4 What this does and does not overturn

**D9's ruling stands. Its implementation does not.**

§12.1's reasoning is untouched: a below-floor node *is* running a topology its
constants were not derived for, and shipping that invisibly to an operator who
chose Tor is still the wrong answer. What the measurement removes is the
**premise of §12.1's counter** — that such a node fluffs at origin anyway when
its embargo expires. At degree 11 it does so **11.6 % of the time**, not
usually. So D9(b) does not convert a late leak into a prompt one; it **creates**
a leak that would not otherwise have happened in 88 % of originations, and it
does so on the branch §16.3 shows an adversary can force for free.

Composed with §16.3, D9(b) as specified is an adversary-triggerable downgrade
from `k/12`-with-ambiguity to precision ≈ 1, on a condition the attacker can
induce by occupying slots or simply waiting — and §15.1 says the network
supplies that condition unaided 47.9 % of the time at `A = 15` and 15.8 % at
`A = 30`.

### 17.5 Consequence for §12.2, which can now be drafted

The gate is discharged, so the dependency §16.4 recorded is released — but not
to the section §12.1 anticipated. **Drafted: §18 (2026-08-15).** The
constraints below are the ones it was drafted under:

1. **`x = 0` is not the remedy for below-floor.** It buys an invalid-embargo
   argument at the price of certain origin attribution, against a measured 88 %
   chance the stem would have completed.
2. **The remaining candidates are the two §12.1 rejected — and they are NOT
   equally reopened.** *Stem anyway* was rejected on *"ships a known-invalid
   provisioning invisibly"*, which is precisely the premise §17.6 just
   weakened to a ~0.4-point shortfall; its rejection rests on a measurement
   that has now moved. *Hold* was rejected on liveness — *"at `A ≤ 12` this is
   not a transient stall but every Tor node holding indefinitely"* — and both
   findings since then push the same way: R13's stickiness makes the
   below-floor state longer-lived, and the sweep puts the network in it 47.9 %
   / 15.8 % / 14.8 % of the time. **`x = 0` falling is not a general licence
   to revisit**: the re-ranking reopens *stem anyway* on its merits and must
   treat *hold*'s rejection as strengthened, not lapsed.
3. **Whatever §12.2 specifies must be evaluated against an adversary who wants
   it to fire** (§16.3), not one who trips it by accident.

**This does not reopen the floor itself.** F-8b's startup refusal is a
provisioning check on the operator's own configuration and is unaffected; what
is overturned is only the *runtime* below-floor branch. §16.5's refusal stands
unchanged, and so does the sequencing constraint: this and the `fluff_return_ms`
landing touch the same conformance vectors and must not be concurrent.

### 17.6 CORRECTION — what the curve measured, and the sharper route to the same ruling

**§17.2's curve is a whole-network reading, and §17.3 mislabelled it.** The
sweep passes `vec![degree; NODES]`, so *every* node runs at degree `d` and both
in- and out-degree move together. Calling α(11) "the realized below-floor
state" was wrong: the realized state is **one** node short of the floor among
healthy peers, which is a different and *milder* configuration.

**The quantity D9 turns on is narrower still, and the floor does not gate it.**
Under `OutboundOnly`, a node's own fluff return — the thing its embargo is set
against — arrives over links *someone else* initiated, so it is governed by
**in-degree**. The floor gates **out-degree**. In `build_adjacency_from_degrees`
every node draws its targets uniformly and never consults the target's degree,
so lowering a node's out-degree does not thin the edges pointed at it and does
not slow its own return at all. §12.1's sentence — *"its fluff return is
slower"* — is an `EveryPeer` intuition applied to an `OutboundOnly` rule, where
the two degrees collapse into one and the reasoning would be sound.

**The rescue clause is measurable, and it fails.** In-degree and out-degree
could be correlated on a real network — a node that cannot dial out may be one
others cannot reach (unpublished descriptor, R13 burn state, a slow guard) — in
which case the simulator's independence would be the artifact. The fleet
recorded both, so this is a reading rather than an argument. Over 1155 settled
node-samples across all three arms:

| | pooled |
| --- | --- |
| `r(out-degree, in-degree)` | **+0.050** |
| mean in-degree, out-degree < 12 | 11.53 (sd 3.60, n = 229) |
| mean in-degree, out-degree ≥ 12 | 11.83 (sd 4.36, n = 926) |
| **deficit attributable to being below floor** | **−0.30 links** |

Per-arm: `r` = +0.172 (A=15), +0.048 (A=30), +0.026 (A=60). **The simulator's
independence is faithful to the measured fleet.**

**So the ruling survives and strengthens, by a shorter route than §17.3's.** A
below-floor node's own fluff return corresponds to in-degree ≈ 11.53 against
11.83 — interpolating §17.2, α ≈ 0.889 against 0.893, a shortfall of about
**0.4 percentage points**. §17.3 refused D9(b) because α was far above `α*`;
the corrected figure is *higher* still and the margin *wider*. More directly:
**§12.1's premise is very nearly false.** A below-floor node's embargo is not
meaningfully under-provisioned, so there is no invalid-provisioning cost for
D9(b) to buy, and the trade §16.4 priced does not arise.

**What this does not change.** §17.3's arithmetic stands on its own inputs, and
§17.4–17.5 are unaffected: D9's ruling still stands, `x = 0` is still not the
remedy, and §12.2 must still be written against an adversary who wants the
check to fire. What changes is that the case against D9(b) no longer rests on
a close quantitative trade — it rests on the premise not holding.

**One thing this does NOT license.** The result says the *fluff-return* half of
§12.1 fails. It says nothing about whether a below-floor node is otherwise
worse off — its own transactions still spread over fewer out-edges, which is a
real effect on quantity (b) and is what §17.2's curve legitimately measures.
§12.2 may still find a reason to act on out-degree; it may not use *"its
embargo is under-provisioned"* as that reason.

---

## 18. Q12-D9 re-ruled — stem anyway, and the check loses its wire effect

**Drafted 2026-08-15, discharging §17.5's obligation.** This is the §12.2 the
measurement permits, and it is not the section §12.1 anticipated. The
constraints it is drafted under are the ones already on the record: `x = 0` is
overturned (§17), the two rejected candidates reopen **asymmetrically** (§17.5),
the design is evaluated against an adversary who *wants* the check to fire
(§16.3), and the floor is a self-provisioning check, never a sybil defense
(§16.5–16.6).

### 18.1 The re-ranking

| candidate | verdict, with what changed since §12.1 |
| --- | --- |
| **`x = 0`** (don't stem → fluff at origin) | **OVERTURNED** (§17). Creates a leak that would not otherwise happen in ~88 % of originations, on a branch an adversary can force for free. |
| **hold** | **Rejection STRENGTHENED, on three grounds.** (a) §12.1's original liveness ground stands. (b) Below-floor is *modal*, not exceptional — 47.9 % / 15.8 % / 14.8 % of settled samples at `A = 15/30/60` (§15.1), so "hold until healthy" is "originate rarely" on a young network. (c) **New, from §16.3's adversary model: hold is adversary-triggerable censorship.** An adversary who occupies outbound slots, or simply waits, converts the victim into a node that cannot transact — at zero cost, with a timing tell on top (withheld transactions burst on recovery). A remedy the adversary can invoke against the operator is not a remedy. |
| **stem anyway** | **ADOPTED.** Reopened on its merits (§17.5) and now ruled in, on the dominance argument below plus the measured margins. |

### 18.2 Why *stem anyway* — dominance, not preference

The two costs §12.1 priced against it, re-priced by the measurements:

**The embargo cost is near-zero.** *"Its own transactions carry an embargo too
short for the graph they traverse"* was the load-bearing sentence, and §17.6
killed it: a node's own fluff return is governed by its **in-degree**, which its
own out-degree does not touch, and the fleet-measured below-floor in-degree
deficit is **0.30 links** — an α shortfall of ~0.4 points, not a cliff.

**The attribution cost is real and still dominated.** Falling out-degree `d`
raises the chance the epoch's stem successor is adversarial (`k/d` rather than
`k/12`) — at `d = 1`, interception is certain if the sole link is hostile. But
**origin/relay ambiguity survives interception**: a successor seeing a stem
cannot tell origination from relay, which is the ambiguity Dandelion++ is built
on. Fluff-at-origin surrenders exactly that, to *every* attacker link, at
precision ≈ 1. So on the attribution axis, **stemming weakly dominates
fluff-at-origin at every out-degree `d ≥ 1`** — interception probability
degrades gracefully; attribution certainty is a cliff the node never needs to
step off.

**Honesty about the range.** The α instrument refuses at `d ∈ {1, 2}`
(whole-network stranding, §17.2), so the measured margins cover degrees 4–12.
The ruling at 1–2 rests on the two structural legs alone — in-degree governs
the embargo, ambiguity survives interception — both of which are
degree-independent. Ruled by dominance, with α as the margin where it exists.

**The real cost of low degree, recorded rather than hidden.** At `d = 1` the
sole successor accumulates the victim's **entire origination timeline** across
epochs — the guard-node shape (the SP-T3 finding: one guard sees the node's
whole emission timeline). Per-transaction ambiguity survives; longitudinal
volume and timing analysis strengthens. This argues for **provisioning** —
the configured floor, more peers, the R13 retry fixes — and not for refusing
to stem, because the alternative on offer hands the same adversary *more*.

### 18.3 The design principle this generalizes to

> **Gate on what the operator controls; only observe what the adversary can
> influence.**

§16.3's lesson, stated as a rule the next check can be tested against. The
*configured* cap is the operator's own act: an adversary cannot set
`--tx-proxy`'s count, so **F-8b's parser/startup refusal stands unchanged** —
refuse-don't-clamp at the configuration surface, exactly as shipped. The
*achieved* count is adversary-influenceable — occupy slots, be unreachable,
wait — so **it must never select wire-visible behavior**: any branch it picks
is an oracle the adversary fires at will, which is the entire §16.3 → §17
arc in one sentence.

**The one accepted exception, named so the principle does not read as having
an unexamined counterexample in production: achieved degree 0.** At `d = 0`,
`select_anonymity()` refuses on `m_connect && status.has_outgoing`
(`net_node.inl:2340`) and the transaction lands in `anonymity_fail_closed` —
send nothing. That *is* hold, selected by the achieved count, invocable by an
adversary who drives the victim to zero. It is a **forced residual, not a
counterexample**: at `d = 0` there is no wire action available, and the only
alternative — clearnet fallback — is the §30.5 forbidden path, first-spy from
the origin's own IP. The count is not selecting *between* behaviors; there is
one behavior. This is also why §18.1's ruling reads **"every achieved degree
≥ 1"** and not "always": `d = 0` is the one place the adversary's censorship
is unavoidable and accepted — which is the strongest form of the statement
that the floor's remedy is *provisioning*, not a wire branch.

This also resolves §12.2's two bullets without discarding either:
*"live, not once at startup"* survives — the live quantity feeds the
diagnostic below; *"refuse, don't clamp"* survives **at the configuration
surface only** — as a runtime rule it was `x = 0`, and it is overturned.

### 18.4 What D9's check becomes — a local diagnostic, exactly

The check §12.5 defended still exists; what changed is its **consequence**.

- **Reads** the achieved outbound anonymity-connection count, live (§12.2's
  surviving bullet).
- **Writes** operator-facing state only: a warn-level log line on the
  below-floor transition (and on recovery), and a field on the existing
  stem-tallies snapshot — which is already **admin-only by posture**
  (`core_rpc_server.h`: *"Must not be registered on the restricted (public)
  listener"*, with the Sharma probe-cost rationale). The diagnostic joins that
  surface under the same restriction. **It must never appear on the public
  RPC surface** — a remotely readable below-floor bit is a free targeting
  oracle (§16.3) and a census input (§16.5).
- **Changes no wire behavior.** Nothing in `select_anonymity()`, any arm of
  `send_txs`, the stem/fluff decision, or the embargo consults it — the pin
  recorded before this section was drafted, now satisfied structurally rather
  than by discipline: the count simply has no consumer on those paths.
- **Carries its name in its type, and the type is diagnostic-only.** When
  plumbed, the count crosses as a type that says what it counts — outbound
  **connections**, not peers (§16.6 item 3; the `read_ids(...)` → `peers`
  mislabel is the standing example) — and the type exposes **no `Ord`, no
  arithmetic, no comparison against the floor constant outside the logging
  path**. §18.4's "no consumer" claim is structural *today* only because
  nothing plumbs the count; the natural read site (`get_status()`, where
  `get_out_connections_count()` already sits) is the same object, on the same
  strand, that the stem/fluff dispatch consults — so once the diagnostic
  lands, "no consumer" decays to discipline unless the type forbids the
  branch. A diagnostic-only type makes a future wire consumer a **visible
  edit to a type that says why it exists**, which converts §18.5's second
  bullet from a request in prose into a rule the compiler reads.

### 18.5 Refused in advance

- **Degree-adaptive embargo** — scaling the embargo by the achieved count would
  let the adversary *write the victim's connection count onto the wire*:
  embargo length is measurable from fluff timing (the
  `zone_embargo_disclosure` instrument exists because of exactly this), and
  the achieved count is theirs to influence. Same shape as §16.5's sybil
  refusal: a robustness argument purchasing an oracle. Also unnecessary on the
  measurement — the under-provisioning it would correct is ~0.4 points.
- **Any future wire-visible consumer of the achieved count**, whatever its
  rationale, re-opens §16.3 and must be argued against this section, not past
  it.

### 18.6 Consequences outside this section

- **The `fluff_return_ms` sequencing constraint is discharged by
  construction.** §16.4 barred concurrency because D9's remedy might have
  moved the same conformance vectors as the 3500 ms landing. As ruled, this
  change moves **no derived number** — no embargo, no timeout, no pin — so the
  §90.4 landing decision is free to proceed on its own schedule.
- **What implementation owes** (registered per rule 94, Rust-owned per rule
  20): the diagnostic slice — transition logging, the admin-surface field, and
  the named count type at the boundary it crosses, **constructed
  diagnostic-only** (no `Ord`, no arithmetic, no floor comparison outside the
  logging path — §18.4). No consensus surface, no wire change, no C++ beyond
  the existing snapshot plumbing it rides.
