# Q12-D6a — the peer-discovery run

**Design, opened 2026-08-11.** The run specification for the measurement
registered as **Q12-D6a** in
[`Q12_FORWARD_DELAY_AND_ZONE_FIELD.md`](Q12_FORWARD_DELAY_AND_ZONE_FIELD.md):
*"the most expensive measurement the arc has proposed and the only one that
cannot be faked."*

**Status: DESIGN. Nothing provisioned, nothing built, no VM stood up.**
Ground findings below are verified at source and against the live estate on
2026-08-11 at pin [`14c2ee599`](https://github.com/Shekyl-Foundation/shekyl-core/commit/14c2ee599).
Identifiers `Q12-R1…R6` extend the already-registered `Q12-` family (rule 94 §1;
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
3. **No tor process on any host.** The SP-T3 spike's pinned Tor Expert Bundle
   is gone. **No onion service exists yet** — the addresses the run needs must
   be generated.
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
seeds matter it reaches 1 and stops. One run, clean isolation — and it is also
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
([`cryptonote_protocol_defs.h:50,88`](../../src/cryptonote_protocol/cryptonote_protocol_defs.h#L50)),
and `address_type` distinguishes i2p (3) from tor (4)
([`enums.h:39-46`](../../contrib/epee/include/net/enums.h#L39-L46)) — so outbound
anon peer count per node needs **no new instrument**.

**The four production seeds are in the graph but not in the histogram.** After
Q12-R-W2 they run anon zones on the same testnet, so they participate whether or
not this doc says so — and at `A = 15` four well-known hubs are a quarter of the
population, distorting exactly the arm where selection pressure matters most.
So: seeds serve as **bootstrap targets and gossip participants**, and the
reported distribution is over **fleet nodes only**. `A` counts fleet nodes.
(Q12-R5's late joiner answers *"did we measure the bootstrap?"*; this answers
*"what population is the histogram over?"* — two different confounds.)

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

## 6. The propagation arm, and why it is second

**What "isolation" means here.** Not a stem-graph partition — Q12-D5 retracted
that; coherence makes stem paths zone-uniform and the two graphs overlap. The
real failure mode is **propagation**: a transaction that fluffs on the anon zone
failing to reach clearnet-only nodes.

The bridge is R-1's `tx_relay` exit — an anon fluff reaches anon peers, who are
dual-stack, and they relay publicly at the next hop. That *should* work by
construction. But "should work by construction" is exactly what was said about
coherence, and coherence turned out to be dormant (§89.8). So it is measured.

**Measurement.** Originate on a Tor-capable node with the anon path forced;
measure arrival fraction and time-to-arrival at the clearnet-only set. The
failure signature is unambiguous: the transaction sits in every anon node's
pool and no clearnet node's. **Reverse arm**: originate clearnet-only and
confirm arrival at Tor-capable nodes — the easy direction, serving as the
control.

**Why second.** The testnet is at height 1 with difficulty 1: **no spendable
outputs exist.** The propagation arm needs mining (`skl-miner-test`), coinbase
maturity, and funded wallets. Discovery needs none of that — it is pure
peerlist gossip with zero chain activity. Sequencing discovery first keeps the
fleet off the critical path of a funding step.

---

## 7. Order

1. Q12-R-W1 — repo PR: Monero seed deletion. **Q12-R-W3 rides this PR** —
   independent of the run, but both touch `add_zone`'s neighbourhood, so they
   share a validation surface
   ([`19-validation-surface-discipline`](../../.cursor/rules/19-validation-surface-discipline.mdc)).
2. Q12-R-W2 — seed estate: rebuild, restart `seedusw`, tor + HS ×4,
   cross-`--add-peer`, **keys backed up**.
3. Ubuntu 24.04 build artifact; fleet image pinned to match.
4. **Discovery arms** — `A ∈ {15, 30, 60}`, 15 clearnet detectors, converge,
   record.
5. **Late joiner** (Q12-R5) — one node, exactly one `--add-peer`.
6. Teardown; verify no instance survives.
7. Land the compiled **testnet** tor seed list (deferred by Q12-R2).
8. **Propagation arm** — after mining and funding, per §6.

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
