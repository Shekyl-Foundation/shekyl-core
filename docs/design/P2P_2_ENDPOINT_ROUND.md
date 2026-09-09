# P2P-2 cluster E — the node's own endpoint

**Status:** RULED 2026-09-06 — every row signed by Rick (§5). The round opened
wider than it should have; PWD-E3/E4's mechanisms were already ruled on `dev`
and are retained as records-was. What this round contributes: the direction of
the nonce/address dependency, the dead `m_our_address` fact, PWD-E2's
enforcement requirement, and PWD-E5's requirement on the removal lane. See §0
before reading anything else. Rule 26 is cited explicitly
(`26-sub-pr-design-discipline.mdc`): this is a multi-round design surface with
untrusted-input and identity coupling, so A2 (audit-against-actual-code) and
A3 (threat-model framing) are load-bearing here, not optional.

**Decision authority:** this round rules; it does not implement. Every ruling
lands in [`SHEKYL_P2P_PROTOCOL.md`](SHEKYL_P2P_PROTOCOL.md) when signed. The
implementation belongs to `p2p/basic-node-data-address` (the wire half) and to
the Rust p2p node when it exists — **not to this document, and not to C++**
beyond what those lanes already scope (rule 20).

**Pinned sha:** `93e7860ba2755fbd61614f0fe5bbed66f83b920a` (`dev` tip,
`git ls-remote origin`-verified 2026-09-06). Every `file:line` below was read
at this sha.

---

## 0. Correction (2026-09-06) — this round opened too wide

**PWD-E3 and PWD-E4 were already ruled and are merged on `dev`.** They are
retained below as **RULED ELSEWHERE** rows, with pins, rather than deleted —
but they are not open, and nothing in this round re-decides them. The failure
was mine: I opened the round without reading its own family's deliverable,
[`SHEKYL_P2P_PROTOCOL.md`](SHEKYL_P2P_PROTOCOL.md), whose peer-identity section
already carries the adopted option at `:639` —

> *No identifier on the wire; nonce + same-host cap + local session-state flag,
> and the back-ping deleted outright* — **Adopted.**

**What that costs the round beyond two tables.** The deliverable enumerates
**four** jobs for `peer_id` (`:639`: "two are nonce-shaped, one is better
served by an address cap, one is *weakened* by the exposure"). §3 below found
**two**. The two-jobs framing was presented as this round's load-bearing
discovery; it is a **subset of a more complete table that already existed**,
and it should have been cited, not re-derived.

**What survives, and why the round stays open.**

- **PWD-E1 / PWD-E2 — endpoint determination — are genuinely open.** The
  deliverable rules what replaces `peer_id`; it does not rule how a node
  learns its own reachable endpoint. `p2p/basic-node-data-address`'s execution
  note defers to this round by name for exactly that.
- **§3's `m_our_address` fact is new and load-bearing.** The public zone's
  pre-dial self-check is **dead**, not merely weaker — assigned only inside
  the `--anonymous-inbound` block. `-43` reports this corrects what steering
  was told, and their note now records it credited here.
- **§4's finding stands as a record, not an open item.** It dies with
  `peerlist_entry.id`, which `-43`'s worktree already removes (verified: zero
  `peerid_type id` occurrences in their `p2p_protocol_defs.h`). It is kept
  because it is evidence *for* the adopted ruling.
- **PWD-E6** records Rick's `--p2p-external-port` ruling and is unaffected.

**The round's stated reason for existing is backwards (Rick, 2026-09-06).** §1
says job 1 cannot be replaced without the daemon knowing its own endpoint.
**That is false.** The nonce replaces job 1 completely and needs nothing about
our address: dial, send a per-connection value, and a handshake arriving with a
value we recently emitted is us. Endpoint determination is not a precondition
for it.

**The dependency in fact runs the other way, and E2(a) is that construction.**
If we dial X and our own nonce comes back, **X is us** — an external address
learned by our own socket, with no attestation trusted. So: nonce →
self-detection → endpoint determination → address comparison *as an
optimisation*. E2(a) already states this ("dial the candidate, recognise our own
nonce on accept"), so the construction is not new; **the correction is to §1's
framing, which had the arrow pointing the wrong way and used it to justify the
round's scope.**

**What that costs the round.** PWD-E1/E2 come **off PWD-I1's critical path**.
They stop being a blocker on removing `peer_id` and become a separate question
about `my_port` and NAT correctness — lower stakes, and `-43`'s lane. §6b's
chain is amended accordingly.

**Address comparison vs nonce is a cost difference, not a correctness gap —
and the cost has a named failure mode.** Comparison avoids the dial; the nonce
detects after it. On `public_` that is a wasted TCP connect. On an overlay it
is a wasted circuit build, **and the failed-address suppression turns it into
something stranger**: a self-dial that times out on a non-hairpinning NAT calls
`record_addr_failed` (`net_node.inl:1318`, `:1332`, `:1387`, `:1399`) **on our
own address**, and `is_addr_recently_failed` then gates candidate selection
(`:1454`, `:1713`) *and* the peerlist merge (`:2148`). **So the first failed
verification attempt suppresses the next one for the whole window** — E2(a)
throttles itself exactly on the nodes that need E2(b).

**RULED (Rick, 2026-09-06) — the nonce is its own field.** Per-connection,
minted fresh, never persisted, and **not** the transport IV or ephemeral
pubkey even once p2p encryption lands. Reusing key material would couple p2p
dedup to the crypto key schedule so a change to one silently changes the
other, and would make job 1 work only on encrypted links. Substrate check:
`basic_node_data` is `{network_id, my_port, peer_id, support_flags}` — no
nonce, no IV — and `net_node.inl:881` still passes
`e_ssl_support_disabled`, so there is no ephemeral key material to reuse today
regardless. The property that matters is that it is **not an identity**:
persistence across connections is what made `peer_id` a correlation surface.

**One consequence for PWD-E2, from the same line.** The adopted option deletes
the **back-ping outright**. E2(b) was written as a reuse of that machinery; it
is not available, so E2(b) must specify its own dial-back mechanism or be
withdrawn. **This is now E2's first open question.**

**Pin note (verified, not assumed).** `-43` builds on `dev` `66bcf1f0f`; this
round pins `93e7860ba`. The gap changes four files and **none under
`src/p2p/`**, so every `file:line` below is identical at both pins.

---

## 1. Why this round exists, and what it does not own

PWD-I1 removes `peer_id` from the wire. The lane that implements it
(`p2p/basic-node-data-address`, declared but not yet built) replaces it with a
`network_address` absorbing `my_port`. That lane owns the wire.

This round **opened** because `peer_id` has two jobs in `is_peer_used` and only
one of them had a replacement anywhere in the tree — the second read as needing
something the daemon does not have: knowledge of its own reachable endpoint.

> **That premise did not survive the round — see §0.** The nonce replaces job 1
> standing alone, needing nothing about our address, so endpoint determination
> never gated `peer_id`'s removal. The sentence above is kept as records-was
> because it is why the round was scoped as it was; **it is not a live claim.**

**What the round is worth, stated in the present tense.** Two things it
established do change the surrounding work: the public zone's pre-dial
self-check is **dead**, not merely weaker (§3), and the nonce/address
dependency runs the opposite way to how it was scoped (§0), which takes
PWD-E1/E2 off PWD-I1's critical path.

**Not owned here.** The wire encoding of the new field (`-43`'s lane). The
peerlist trust model — [PR #637](https://github.com/Shekyl-Foundation/shekyl-core/pull/637)
rules that white means *this process dialled it and it answered*, and this
round takes that as a standing input rather than reopening it. Anything about
overlay-zone identity, which PWD-I2 already closed.

---

## 2. Standing inputs

| Input | Source | Status |
|---|---|---|
| `peer_id` leaves the wire | PWD-I1 | RULED, unimplemented |
| Overlay zones announce a sentinel, never a per-node id | PWD-I2; `ANON_ZONE_SENTINEL_PEER_ID` at `src/p2p/net_node.h:180` | RULED |
| White means *this process dialled it and it answered* | PR #637 amendment | IN REVIEW |
| `--p2p-external-port` is kept | Rick, 2026-09-06: *"leave the external port specifier on there, because it really is user-configurable, even if it usually isn't"* | RULED — see PWD-E6 |
| An endpoint is not an identity | PW-19a | RULED |

---

## 3. Substrate (read at the pinned sha)

**`peer_id`'s two jobs.** `is_peer_used` (`src/p2p/net_node.inl:1207-1228`,
duplicated for anchors at `:1232-1253`) has a pre-loop self-check and a
per-connection loop:

- **Job 1 — self-dial avoidance** (`:1215`): `is_public && m_config.m_peer_id == peer.id`, *with no address comparison at all*.
- **Job 2 — cross-port duplicate avoidance** (`:1221`), disjunct 1: `is_public && cntxt.peer_id == peer.id && peer.adr.is_same_host(cntxt.m_remote_address)`. Disjunct 2 (`!cntxt.m_is_income && peer.adr == cntxt.m_remote_address`) is address-exact and outbound-only, so it cannot see the case disjunct 1 exists for.

**The case job 2 covers is every inbound peer.** On a successful inbound
handshake (`:2759-2785`) the live context holds *(their IP, ephemeral source
port)* while the peerlist entry written after pingback holds *(their IP,
`my_port`)* — same host, same instant, two ports, tied together only by
`peer_id`.

**Job 2 has a replacement in the tree; job 1 does not.**
`has_too_many_connections` (`:3115-3136`) already counts inbound connections by
`is_same_host`, default max 1 (`src/p2p/net_node.cpp:178`), consulted on the
accept path (`:240`) — an observed property, no minted field. It is simply not
consulted from the dial side. By contrast the address-based self-check at
`:1699` compares `zone.m_our_address`, which is assigned only from
`--anonymous-inbound` (`:674`; the field is commented "in anonymity networks",
`src/p2p/net_node.h:373`). **The public zone's `m_our_address` is never set, so
that check is empty exactly where job 1 is needed.**

**The daemon never asks for its own endpoint.**

| Available | Where | Used? |
|---|---|---|
| `UPNP_GetExternalIPAddress` | `external/miniupnp/miniupnpc/upnpcommands.h:77` | **zero occurrences in the tree** |
| `UPNP_AddAnyPortMapping` (returns `reservedPort`) | `upnpcommands.h:160` | unused |
| `UPNP_GetSpecificPortMappingEntry` | `upnpcommands.h:237` | unused |
| IGD `controlURL` + `servicetype` in scope | `net_node.inl:3228`, used at `:3239` | used only to add a mapping |
| `socket().local_endpoint()` | `contrib/epee/include/net/abstract_tcp_server2.inl:1098` | read, discarded into a log line |
| an `addr_you` echo field | — | `basic_node_data` is `network_id`, `my_port`, `peer_id`, `support_flags` only (`src/p2p/p2p_protocol_defs.h:141-153`) |
| `--p2p-external-ip` | — | does not exist; only `--p2p-external-port` (`net_node.cpp:151`) |

The announcement is `node_data.my_port = m_external_port ? m_external_port : m_listening_port` (`:2172`) — **a port announced for an address never determined.** `UPNP_AddPortMapping` is called with the same port string as both external and internal port (`:3239`), i.e. it *requests* equality and never reads back what it got; on failure it logs and continues (`:3240-3244`).

---

## 4. Finding — a gossiped `id` decides a dial

Recorded here because it is the sharpest instance of the defect class this
round exists to close, and because **PWD-I1 may or may not discharge it** (see
PWD-E5).

- **Adversary:** any peer that has completed one handshake. Our `peer_id` is in the handshake *response* (`:2799`, via `get_local_node_data`) and in `handle_ping`'s reply (`:2809`).
- **Access:** gossip. `sanitize_peerlist` filters address and pruning seed only (`:2090-2115`); the merge predicate is address-only (`:2147`). Nothing inspects `id`. On address collision the gray record is **replaced including its id** (`src/p2p/net_peerlist.h:420-424`), so any gray entry can be retargeted; white is protected (`:406-408`).
- **Delta:** gray housekeeping dials the address and handshakes successfully — reading the *real* peer id into `pi` at `:1393-1394` — then **discards it and promotes `pe.id`, the gossiped value** (`:3167`). The honest address enters white carrying our own id, and `is_peer_used`'s self-check then skips it at every selection (`:1445`, `:1703`, `:1769`). Correction requires that peer to dial us and complete pingback.

The observed value is in a local variable one line above the store of the
minted one.

---

## 5. Decisions — **RULED 2026-09-06 (Rick)**

| Id | Verdict |
|---|---|
| **PWD-E1** | **(c)** — sources propose, a verifier decides. (b)'s falsifier is *satisfiable today*: under CGNAT `local_endpoint()` reports a private address and nothing signals it. (a)'s cost falls on the E6 population — operators who configured a forward and silently never receive inbound. |
| **PWD-E2** | **(a) and (b) together**, with an enforcement requirement added below. |
| **PWD-E3** | **(c)** — and the nonce does not merely precede the address, it **removes the address's necessity for job 1 entirely**. Underlying mechanism already ruled on `dev`; this records the direction. |
| **PWD-E4** | **(a)**, with its adversarial limit moved into the concession column. Underlying mechanism already ruled on `dev`. |
| **PWD-E5** | Requirement, satisfied in `-43`'s lane. |
| **PWD-E6** | `--p2p-external-port` stays, as a verified candidate. |

### Ruling additions that are not in the tables below

**PWD-E2 — the precondition is stated but not enforced.** "A peer we dialled
outbound knows only the address we announced" is true of an **honest** peer and
false of an adversary that learned another endpoint from gossip. So dial-back's
discrimination must be **scoped to peers we dialled, in a session where we
announced exactly one candidate**, and *that scoping belongs in the mechanism,
not in the prose describing it*. A precondition documented but not enforced is
the gap between E2(b) working and E2(b) being believed to work.

**PWD-E3 — a constraint at the definition site.** The nonce is **per-connection
and never persisted**. Persistence across connections is what made `peer_id` a
correlation surface, so **a nonce reused for two dials is `peer_id` with a
shorter name**. It is also not the transport IV or ephemeral pubkey even once
p2p encryption lands (§0).

**PWD-E4 — the limit belongs in the concession column, not the overlay note.**
`has_too_many_connections` keys on **host**, and host is cheap to multiply on
**both** transports: a /24 gives 256 free hosts on `public_` as surely as a
keypair gives one on tor. So the cap **bounds honest duplicates and nothing
adversarial, in any zone**. Stated only as an overlay limitation, the row reads
as clearnet-effective and overlay-limited — which is exactly the framing this
concession retires (the overlay carve-out). Recorded on the §1 ladder in
[`SHEKYL_P2P_PROTOCOL.md`](SHEKYL_P2P_PROTOCOL.md) as of 2026-09-09.

> **Question routed to the deliverable, not asserted here — DISCHARGED
> 2026-09-09.**
>
> [`SHEKYL_P2P_PROTOCOL.md`](SHEKYL_P2P_PROTOCOL.md) §1's three-tier ladder —
> *worst: verify a claim; better: replace it with your own observation; best:
> bind it into the transcript* — carries the same-host cap as the **worked
> example of tier two**, not as a claim about its adversarial strength. As that
> example it is **correct**: nothing is claimed, so nothing can be forged.
>
> **The line needed no correction. What was missing was a fourth statement the
> ladder did not make:** tier two closes the **forgery** surface and is silent
> on the **multiplication** surface. An observed property can still be cheap to
> produce — a /24 gives 256 hosts, a keypair gives one onion — so "nothing to
> spoof" and "adversarially binding" are **independent**. Written into the
> ladder on 2026-09-09, immediately after the three rungs. The risk named
> here — that the ladder reads as a completeness ordering — is why the note
> sits on the framework, not on the cap.

## 5b. The decision tables



Each table: the options, the adversary and channel each answers, what it
concedes, and the falsifier that reopens it.

> **Implementation status for cluster E lives in the deliverable, not here.**
> [`SHEKYL_P2P_PROTOCOL.md`](SHEKYL_P2P_PROTOCOL.md) §0.5 carries a
> per-decision status with evidence for all 37 P2P-2 decisions, E1–E9
> included. One table, one owner: a second status here would be the
> restatement that goes stale (rule 94 §6).

### PWD-E1 — does a node determine its own reachable endpoint?

| Option | Adversary / channel | Concedes | Falsifier |
|---|---|---|---|
| (a) No — keep announcing `my_port` against an undetermined address | none addressed | operators behind non-1:1 forwards silently never receive inbound; job 1 has no basis | any measurement showing a non-trivial share of nodes announce an endpoint they are not reachable at |
| (b) Yes, from local sources only (IGD, `local_endpoint`, operator flag) | none — no remote input | wrong under CGNAT and double-NAT, with no signal | a node that verifies reachable while IGD reports a private address |
| (c) Yes, sources propose and a verifier decides | remote peers feeding a false address (gossip / handshake echo) | complexity; nodes that cannot verify do not advertise | a verifier that can be made to accept an endpoint the node is not reachable at |

**Proposed: (c).** (b) is (c) with the verifier removed, and the verifier is the
part that makes an operator's declaration and a router's claim safe to use.

### PWD-E2 — what verifies a candidate endpoint?

| Option | Adversary / channel | Concedes | Falsifier |
|---|---|---|---|
| (a) Hairpin self-dial: dial the candidate, recognise our own nonce on accept | trusts no remote | **false negatives on routers that do not hairpin** — common consumer gear | a NAT class where hairpin succeeds but the endpoint is not externally reachable |
| (b) Peer-assisted **dial-back**: ask a peer to dial the candidate; the port is read from **our own accepting socket**, never from anything the peer reports | a peer reporting a false port — inadmissible, because no reported value is read | proves reachability of *an* endpoint, not specifically the candidate (see below); proves no address either way | an attesting peer names a port our listener is not bound to and the mechanism accepts it |
| (c) Peer echo (`addr_you`) accepted directly | — | **reproduces §4 in address form**: an attacker echoes an honest node's address | — (rejected on its face) |
| (d) k-of-n echo corroboration | an attacker holding k of our connections | that is the eclipse precondition, not a defence against it | — |

**Proposed: (a) and (b) together, (c)/(d) as candidate sources only.** The two
verifiers are complementary in exactly the way the sources are: echo can give
an address but not a port; dial-back gives a port but not an address.

#### (b) is two mechanisms, and only one is admissible (amended 2026-09-06)

The round's own discriminator — **minted versus observed**, not overlay versus
clearnet — applies to (b) itself, and separates two things the first draft's
summary did not distinguish:

- **Peer observes our outbound connection and reports the port.** The port it
  sees is the **ephemeral source port** of an outbound socket, not our
  listener's, and it arrives as a value the peer chose to send. Minted by the
  attester, with extra steps. **Rejected.**
- **Peer dials back, and we read the port off our own accepting socket.**
  Observed locally; nothing the peer says is consulted. **Adopted.**

**The requirement this forces, stated so no implementation can drift into the
first variant: no port value is ever read from a field a peer sends.** The
peer's role is to cause a connection, never to describe one. Rick's falsifier
is the gate: an attesting peer names a port our listener is not bound to, and
the mechanism must reject it — if it cannot, the value is minted.

**And the adopted variant is weaker than the first draft claimed.** An arrival
proves that *some* endpoint of ours routed a connection, **not that the
candidate did** — with a single listener, every arrival lands identically
however it was reached. It discriminates between candidates only while the
attesting peer has **no other known route to our listener**. For a peer we
dialled outbound that precondition typically holds, since the only listener
address it has is the one we announced — but it is a precondition, not a
proof, and it fails against a peer that learned another endpoint of ours from
gossip. **State it as a conditional guarantee; do not cite (b) as
unconditional reachability proof.**

### PWD-E3 — self-dial avoidance once `peer_id` is gone — **RULED ELSEWHERE, NOT OPEN**

> **Ruled on `dev`:** zone-scoped handshake nonce, owner **PWD-T1**, with a
> **stem-width** falsifier because the failure mode is an undetected self-edge
> rather than a wasted dial ([`SHEKYL_P2P_PROTOCOL.md`](SHEKYL_P2P_PROTOCOL.md)
> `:602-628`, `:639`). The zone scoping is a *requirement*, not a detail: a
> naive nonce re-creates the cross-zone oracle `handle_handshake` already warns
> about. The table below is retained as records-was; it does not rule.

| Option | Adversary / channel | Concedes | Falsifier |
|---|---|---|---|
| (a) Address filter only, from a verified endpoint | gossip cannot forge it (verified, not asserted) | **nothing at all until an endpoint is verified**, including the whole startup window and every non-hairpinning node that also lacks (b) | a node that dials itself while holding a verified endpoint |
| (b) Fresh per-dial nonce: dialer sends `N`, our own acceptor drops an inbound bearing an outstanding `N` | groups nothing — per-connection, so the PWD-I2 eclipse-oracle argument does not bite | one field on the wire; the set must be bounded (entry removed on dial completion or timeout) or it is a memory sink | a replay that achieves more than making us drop the replayer's own inbound |
| (c) Both: nonce is detection, address filter is avoidance | — | two mechanisms | the nonce failing to catch a self-dial the filter missed |

**Proposed: (c).** The nonce is correctness and needs no address; the filter is
an optimisation that saves the wasted dial. Note the dependency direction:
**the nonce is what makes PWD-E2(a) possible at all**, so it is upstream of the
address, not replaced by it.

### PWD-E4 — cross-port duplicate avoidance (job 2) — **RULED ELSEWHERE, NOT OPEN**

> **Ruled on `dev`:** address-based same-host outbound cap
> ([`SHEKYL_P2P_PROTOCOL.md`](SHEKYL_P2P_PROTOCOL.md) `:519`, `:639`), with the
> multi-node-host concession stated against the invariant rather than a number,
> and PWD-B9 owning the value. My proposed (a) — reuse
> `has_too_many_connections` — matches what `-43`'s unit reports it will do, so
> the pointer stands even though the decision was not mine to make. Retained as
> records-was.

| Option | Adversary / channel | Concedes | Falsifier |
|---|---|---|---|
| (a) Consult the existing inbound-by-host predicate from the dial side | minted values play no part | does nothing on overlay zones — no host to compare | an honest duplicate that survives the check on clearnet |
| (b) Accept the duplicate; drop the check with `peer_id` | — | an outbound slot spent on a peer already connected inbound; a stem edge may go to a node already observing us inbound | a measurement showing the duplicate rate is negligible |
| (c) Re-derive identity from the new address field | **reintroduces a minted value in a control decision** | — | — (rejected on its face) |

**Proposed: (a)** as a *direction* — host-keyed duplicate avoidance, no minted
value — and that is what shipped. The first draft's *wiring* was reuse of
`has_too_many_connections` from the dial side; `-43` built a dedicated
outbound helper instead (`outbound_connection_takes_host` /
`has_outbound_connection_to_host`): outbound-only, host-keyed, every zone.
The first draft's overlay concession ("does nothing on overlay zones — no host
to compare"; "overlay limitation is not a regression") is the framing the §5
concession retired. That no-op is a fact about the inbound cap (PWC-E11,
`net_node.inl:3029` returns false off `public_`), not about job 2. The
concession cell on (a) in the table above is records-was of the first draft;
do not cite it as current.

### PWD-E5 — is §4 discharged by PWD-I1?

| Option | Concedes | Falsifier |
|---|---|---|
| (a) Yes — no `id` field survives, so nothing gossiped decides a dial | assumes `PeerlistEntry.id` goes too, not only `basic_node_data.peer_id` | a surviving `id` on any gossiped structure |
| (b) No — the same shape recurs if the new address field is gossiped and then used to *skip* a dial | — | — |
| (c) **Neither — `id` becomes a dead wire field that every consumer still reads** | this is the likeliest outcome of the field set as currently scoped | — | a lane that strips `id` from the gossiped peerlist too |

**(c) is the state to design against, and it is not hypothetical.** `id` is a
field of `peerlist_entry_base` (`src/p2p/p2p_protocol_defs.h:62`), which is a
*separate* structure from `basic_node_data` (`:141-153`) — and
`p2p/basic-node-data-address`'s lane names `basic_node_data` only. In that
field set `peer_id` leaves the handshake while a gossiped `id` stays on every
peerlist entry, and `set_peer_just_seen(pe.id, …)` at `net_node.inl:3167` goes
on storing it. §4 would then be **undischarged and harder to see**, because the
field that carries it no longer has a producer anyone can point at.

**So E5 resolves to a requirement, not a question:** either the removal strips
`id` from the gossiped peerlist wire as well, or it deletes every `id` read
before landing. There is no third schedule — a field with no meaning and live
consumers is exactly the deferral rule 22 forbids.

The discriminator stays narrow: does any *gossiped* value reach a decision to
**not** dial an address? §4's delta came from a skip, not from a connect.

### PWD-E6 — `--p2p-external-port` (RULED, recorded)

Rick, 2026-09-06. The flag stays. It becomes an operator-supplied
**candidate**, verified by PWD-E2 like every other source — keeping the flag
and announcing it unverified are separable, and only the first was ruled.
**Consequence to carry:** if verification depends on hairpin alone, a correctly
configured operator behind a non-hairpinning router still would not advertise,
which would make the flag useless to exactly the people it exists for. This is
the strongest argument for PWD-E2(b).

---

## 5c. The check to run when the removal lane lands

> **CORRECTED 2026-09-07.** This section previously said the insert ordering
> *"is the whole of the bounded-set requirement"*. **It is not**, and the error
> is the kind that reads as coverage: it told a maintainer that the ordering
> test discharges boundedness, so they would not build erase coverage at all.
> The two properties are independent and are separated below.

**Ordering governs detection.** Recording the nonce **before the request is
written** is what makes a self-dial detectable: it closes the race in which our
own connection arrives and is checked against the set before the value is in
it. Nothing about this bounds the set's size.

**Boundedness rests on the termination guard alone.** A set that is never
erased from grows without limit however well the insert is ordered — but the
mechanism that bounds it is the *attempt scope guard*, not the erase leg taken
as a whole. Its declaration states the invariant and this section will not
paraphrase it a fourth time:

> *"Attempt-scoped by construction — bounded by in-flight outbound attempts, so
> there is no size limit to choose and no eviction policy to get wrong."*
> — `src/p2p/net_node.h:344-346`

The guard is unconditional RAII over a local (`net_node.inl:1074-1077`), so it
runs on success, failure and timeout alike. **Erase-on-match is not a second
boundedness requirement**: remove it and the guard still removes the nonce. What
it *does* buy is **single-fire / anti-replay** semantics — a nonce cannot fire
twice, so a peer that learned it by being dialled cannot replay it — plus
shorter residency. Those are correctness properties of detection, not of the
set's size.

**Status in the removal lane.** Both properties are now discharged, and by
different means.

> **This section carries its own pin, and must.** The symbols below **did not
> exist** at the document's pin (`93e7860ba`) — they landed with PR #643. Every
> `file:line` in this section is read at **`1878e89d3f6e51f32056dee6f13500859640c407`**
> (#643's merge commit), not at the document pin and not at "`dev` after the
> merge", which is a moving target that would stop resolving at the next merge.

- **Ordering is enforced by construction, and a test pins the construction.**
  `mint_recorded_handshake_nonce`
  generates the value, records it into the zone's set, and only *then* returns
  it (`net_node.inl:1209-1215`), so a request cannot be built from an
  unrecorded nonce. `node_server.handshake_nonce_is_recorded_before_it_can_be_written`
  pins it — **the test's job is to red when the construction is dismantled, not
  to catch a race**, which is the distinction that makes it sound: a real
  self-dial's detection is a race the acceptor usually wins, so an
  insert-after-write regression would have made such a test **flaky**, and a
  falsifier that fails to fail is exactly the defect §5c exists to prevent.
  Stronger than the falsifier this section originally asked for, and correctly
  so.
- **Both erase *implementations* are pinned by test — but they are pinned for
  different guarantees.** `erase_outbound_handshake_nonce` (`:1228`) is the
  boundedness mechanism, because the scope guard calls it on every exit path;
  erase-on-match inside `detect_self_handshake`, which returns
  `erase(nonce) > 0` (`:1248-1257`) so detection and removal are the same act,
  pins **single-fire behaviour and prompt removal**, not a second size bound.
  Each is exercised by count as well as by detection, with
  `inflight_handshake_nonce_count` (`:1238`) as the observable.
  **What no test observes** is that `do_handshake_with_peer` attaches the
  termination erase at all — RAII over a local — and the test states that
  boundary itself at `tests/unit_tests/node_server.cpp:1634-1638` rather than
  leaving it to be assumed. **Implementation coverage, not termination-path
  coverage.**

> **What this round got right and wrong — and the pattern in the wrongness.**
> Right: that the check needed writing, and that it should be authored against
> the unit rather than asserted about it. Wrong three times, each time by
> attributing a property to the wrong mechanism: first ordering ⇒ boundedness
> (#641), then the erase leg's *two exits* ⇒ boundedness (this PR's first
> pass), and finally erase-on-match credited with a size guarantee it does not
> carry. **The declaration at `net_node.h:344-346` stated the invariant
> correctly throughout.** Every error came from paraphrasing a contract instead
> of citing it — which is why the boundedness paragraph above now quotes the
> declaration rather than restating it.

Field placement — request-level on `COMMAND_HANDSHAKE` rather than inside
`basic_node_data` — is right for the layering reason in §0, independently of
whether p2p encryption ever lands.

## 6. Forward actions (rule 26 A5)

| # | Action | Target |
|---|---|---|
| F1 | Answer PWD-E5 against the built field set | `p2p/basic-node-data-address` |
| F2 | Whatever PWD-E3/E4 rule must land **with** the `peer_id` removal, not after it | same lane — removing job 1 and job 2 with no replacement is the regression this round exists to prevent |
| F3 | Rust shape (endpoint typestate `Candidate<Source>` → `Verified{at}` → `Stale`; `Zone` marker types with `type Dedup`/`type Announced`, distinct from `RelayZone`) | the Rust p2p node; rule-18 question of whether `RelayZone` derives from the transport zone is **not** settled here |
| F4 | Re-home PWD-I2's eclipse-completion-oracle argument when `ANON_ZONE_SENTINEL_PEER_ID` is deleted | the removal lane — the argument outlives its subject and is the standing reason not to reintroduce per-node identity |
| F5 | **DISCHARGED 2026-09-07.** §5c's check, corrected: ordering is enforced by construction (`mint_recorded_handshake_nonce`) with a test pinning the construction; **boundedness rests on the attempt scope guard alone** (`net_node.h:344-346` — attempt-scoped by construction), while erase-on-match pins single-fire/anti-replay rather than a second size bound. Both erase implementations are exercised by count and by detection; the termination *wiring* is RAII and deliberately unobserved — see §5c, which states the boundary rather than claiming path coverage | the removal lane, PR #643 |

## 6b. The chain, drawn (added 2026-09-06)

The ordering hazard is no longer a two-item sequence. `peer_id` leaving before
its replacements exist is now a property of a **four-link chain with an
unbuilt middle**:

```
  PR #637  ──►  p2p/basic-node-data-address  ──►  PWD-I1 complete
  (OPEN)        (declared, UNBUILT)               (ruled, unimplemented)
                        ▲
                        │  gated on BOTH:
                        ├── job 2 replacement  ── PWD-E4 (wiring exists, unconsulted)
                        └── job 1 replacement  ── PWD-E3
                                                    └── gated on endpoint
                                                        determination — PWD-E1/E2
                                                        (this round)
   and separately: B9 restores the honest-duplicate half I1 removes
```

**AMENDED 2026-09-06 — the chain is three links, not four.**

```
  PR #637  ──►  p2p/basic-node-data-address  ──►  PWD-I1 complete
  (OPEN)        (declared, UNBUILT)               (ruled)
                        ▲
                        └─ siblings, not a nested gate:
                           PWD-E4 same-host cap (wiring exists)
                           PWD-E3(b) nonce (a field + a bounded set)
```

**Why E1/E2 left it.** The nonce carries
job 1 by itself, so PWD-I1's removal does not wait on endpoint determination.
What remains gating I1 is the nonce (PWD-T1) and the same-host cap, both ruled;
E1/E2 are a parallel question about `my_port` and NAT, not a link in this
chain. The diagram above is retained as records-was.

**Why it was drawn.** Each link is individually reasonable and the chain
is not: the middle link is unbuilt, the link after it is ruled, and the two
gates on it live in a round that is still open. A lane that lands `peer_id`'s
removal because "I1 is ruled" would be reading one link, not the chain.
PWD-E5's requirement sits on the same middle link and makes it strictly larger
than its title suggests.

## 7. What would reopen this round

- PWD-E2(b) shown unsound — the port-proving claim is reasoning, not a verified result.
- A measurement showing endpoint determination is not needed because the announce-and-hope path already reaches the network reliably.
- `-43`'s lane landing a field set that makes PWD-E3/E4 moot.


### PWD-E7 — how a node obtains an **overlay** endpoint: two postures, ephemeral by default

**RULED by Rick, 2026-09-07.** PWD-E1/E2 answer the clearnet question — a
candidate endpoint proposed by NAT, IGD or an operator, and a verifier that
decides. **This row is the overlay case, and it is not the same question.**

| Posture | How the address exists | Requires | Ruling |
|---|---|---|---|
| **Daemon-held, ephemeral per boot** | the daemon mints a service key and publishes it; the address is the `ServiceID` tor returns from `ADD_ONION` | tor **control port** | **DEFAULT** |
| **Operator-provisioned, stable** | the operator runs a hidden service in `torrc`; the address is handed to the daemon as a string (`--anonymous-inbound`, `net_node.cpp:159`, parsed `:297`) | SOCKS + a `torrc` service | **SUPPORTED** |

**These are different privacy postures, not two custodies of one thing, and the
distinction is the ruling.** Rick, verbatim: *"the second isn't 'the same thing
with different custody.' It's a different privacy posture, chosen
deliberately."* An ephemeral address is **a route**; a stable one is **a durable
identifier the operator has knowingly accepted**. The stable posture exists for
seeds and deliberately-persistent infrastructure, where a fixed address is the
point.

> **State it wherever the flag is documented, because the failure mode is
> quiet:** someone reads "both supported" as "pick either, they're equivalent",
> copies a config example that uses `--anonymous-inbound`, and a
> default-posture node ends up with a permanent address it never chose. The
> flag is not a custody preference; taking it is opting into a durable address.

**The ephemeral default is what keeps the daemon secret-free.** `discard_pk:
true` (`onion_service.rs:243`) means tor retains no copy — so a *stable*
daemon-held key would have to be persisted by the daemon, giving it its first
long-lived on-disk secret and escalating the peerlist-store question from
privacy into integrity. Ephemeral-per-boot removes that entirely: **no
persisted secret, no durable join key, no store-encryption escalation.** The
key is minted at startup, lives in memory, and dies with the process.

**Behaviour at every seam, both postures** — required because both are
supported, so no seam may be defined in only one:

| Seam | Ephemeral (default) | Operator-provisioned |
|---|---|---|
| Where the address comes from | `ADD_ONION` reply `ServiceID`, read from our own control connection | the flag's parsed string |
| Verification | **none needed, and none admissible to add** — see below | none today; unchanged |
| Restart | new key, **new address** | same address, from `torrc` |
| tor control unavailable | no address ⇒ no overlay inbound; the node is outbound-only on that zone | unaffected — needs only SOCKS |
| First run vs later | identical; there is no "later" state | identical |

**Why the overlay case needs no verifier, stated as a property rather than an
exception.** PWD-E2's adversary is *a remote party proposing an address we
cannot check*. On the self-provisioned path there is no remote party in the
channel at all: the address is returned by the local process that just created
the service, over a local control connection, and `ServiceIdMismatch`
(`onion_service.rs:59,72`) already rejects a reply that does not match what we
asked for. **This is the one case where a node genuinely knows its own
address** — locally authoritative, not locally *asserted*. Adding a dial-back
here would verify reachability we have not claimed and cannot use.

**It also over-determines PWD-I1's exit.** The ruling that overlay inbound peers
are not gossip-bound on possession rested on *posture heterogeneity* — a
possession proof is unverifiable across a mixed network. Under ephemeral-by-
default there is now a **second, independent** reason: a boot-scoped address has
**nothing durable to bind to**. Two independent grounds is a better place for a
genesis-frozen ruling to sit than one.

**The forbidden direction is unchanged and this row does not touch it.** Owning
*our own* key is the precondition for having an address; it asserts nothing
about anyone. Using a key to decide who a **remote** peer is, or to carry a
claim across reconnects, stays forbidden. Same fact, opposite consequence,
depending on whose address it is. Every mechanism added under this row must
answer *does this let anything conclude that two observations involve the same
party?* — and if yes, stop.

**UPDATE 2026-09-09: IMPLEMENTED, both postures.** The ephemeral default is
`DaemonTorControl` (`rust/shekyl-tor-control-daemon`) wired into
`node_server::add_ephemeral_tor_zone` (`src/p2p/net_node.inl`) over the
`shekyl_daemon_tor_*` FFI; the operator-provisioned posture is the unchanged
`--anonymous-inbound` path, which the default yields to when configured. The
durable-address warning ruled above is now stated in the flag's own descriptor
(`src/p2p/net_node.cpp`, `arg_anonymous_inbound`). Opt-out is
`--no-ephemeral-tor`. Every seam in the table above landed as ruled: no
verifier, no persisted key, restart mints a new address, a start failure
degrades to outbound-only on the zone rather than aborting the daemon.

### PWD-E8 — address volatility: the measurement PWD-E7 must ship **before** it can exist

**DEFERRED, with a real external blocker and a falsifier chain.** An earlier
revision of this row had the dependency **backwards** — it read "the measurement
owed before PWD-E7 is built". Rick, 2026-09-08: *"we need to stress the fleet to
get an actual read on T, so we need working code before we can come up with a
REAL T rather than conjecture."*

**`T` is the mean uptime between restarts of real nodes.** It cannot be derived,
assumed, or read off a constant. Without E7 shipped there is no fleet running
the thing whose volatility `T` describes, so **the measurement has no subject**.
Building E7 first is not a convenience justified by "the mechanism is identical
either way" — it is the only order that can produce `T` at all.

#### The half that IS derived, and may be stated as such

A gossiped overlay address enters **gray**. On a saturated node the only prober
is `gray_peerlist_housekeeping`, which draws **one random gray entry per zone
per 60 s** (`net_node.h:631`) from a pool capped at
`P2P_LOCAL_GRAY_PEERLIST_LIMIT = 5000`. A uniform draw with replacement gives an
expected wait of `N` cycles for any specific entry:

> `D = N × 60 s = 5000 × 60 s ≈ **3.5 days**` — derived from shipped constants,
> and statable as derived. It moves with the gray cap and the cadence, so
> changing either re-opens this row.

#### The half that is CONJECTURE until the fleet reports

The dead-on-probe fraction is `1 − e^(−D/T)`. **`T` is unmeasured, so every
number below is conjecture in Rick's own word — not a property of this network,
and not merely "conditional".**

| **assumed** `T` | model output **if `T` were that** |
|---|---|
| 30 days | ~11 % |
| 7 days | ~39 % |
| 1 day | ~97 % |

> **Quotation rule.** These may appear only in the form *"assuming `T` = 7 days,
> the model gives ~39 %"* — never as a property, and **never in a summary line
> where the assumption can be dropped in a restatement.** A figure that loses its
> qualifier reads as measured, which is worse than no figure.

#### The falsifier is a CHAIN, and every link is named

"Blocked on `T`" alone would leave a reader thinking a rig run produces it. It
does not: **Q12-D6a is the instrument, not the source.** The source is nodes
restarting in the wild under load.

> **E7 ships → nodes run it → the fleet is stressed → `T` is measured under
> those conditions → the threshold becomes Rick's.**

Each link is a real precondition: no ship, no fleet; no fleet, no restarts; no
stress, no admissible `T`; no `T`, no threshold.

#### What makes a `T` admissible — stated because this is where the number goes wrong

Restart behaviour **under load** is the thing being measured, and **a quiet fleet
reports a `T` that flatters the design**. An inadmissible `T` that gets quoted is
worse than no `T`, because it reads as measured. A `T` is admissible only with:

- **Duration** — long enough to observe restarts, not a brief run whose window
  is shorter than the restart interval it is trying to estimate.
- **Stressor** — the fleet under load, since load is what causes the restarts
  (OOM, operator intervention, upgrade cycles) that `T` is about.
- **Heterogeneity** — not a homogeneous set of well-behaved nodes. A fleet of
  identical healthy hosts measures the operator's discipline, not the network's.

Any `T` reported without all three is not the `T` this model needs, and the row
should reject it rather than absorb it.

#### Blocker (rule 22)

**Named external blocker: `T` cannot exist until E7 ships and a stressed,
heterogeneous fleet runs long enough to observe restarts.** Zero symbols; one
FOLLOWUPS row; lifts exactly when the chain above completes. The acceptable
threshold is **Rick's** to rule once `T` is in hand — it is a judgement about
whether overlay *discovery* converges, not about whether individual dials
succeed.

**Three non-fixes, named so they cannot look like progress:**

- **Do not shorten `D` by probing gray harder** — trades a measured quantity for
  unmeasured overlay dial volume, and PWD-B1's rate limiting has no derived
  parameters yet.
- **Do not infer an acceptable aggregate from the clean per-case failure** —
  that inference is exactly what makes this degrade quietly.
- **Do not substitute a convenient `T`.** An assumed value that survives one
  restatement becomes a measured one.

### PWD-E9 — PWD-E7's isolation boundary: what "the daemon gets its own path" forbids

**RULED by Rick (relayed 2026-09-08):** *"the daemon needs it's own path we DO NOT
want crossover between the daemon and archival-serving P."* The second clause is
the binding one — this is an **isolation requirement between two identities that
must not be linkable**, not a crate-layout preference.

#### Sharing code is not crossover. Sharing state is.

Reusing the control-protocol client, the `AddOnion` request type and the reply
evaluator is **library reuse**; duplicating them would be the deliberate-duplicate
error this program has ruled against repeatedly. What must not be shared is
anything that lets an observer, or a compromised component, place the daemon's
P2P onion and the archival-serving persona's onion **on the same host**.

#### The enumeration — a reviewer checks the diff against this table

| Shared-resource class | Shared? | Why |
|---|---|---|
| tor **process / instance** | **NO** | the root of every linkage below; one process is one guard set, one descriptor-publishing identity, one crash domain |
| **control connection** + authed session | **NO** | a single authenticated session that can `ADD_ONION` both services is a component that, once compromised, links them by construction |
| **supervisor** and its state | **NO** | `WalletTorControl` holds cross-incarnation state; a supervisor that knows both is a join |
| **vanguard / guard set** | **NO** | `vanguard_rotation` is explicitly *"supervisor-scoped state that outlives Tor incarnations"* — persisted and authoritative. Two services under one supervisor share the guard topology **by construction**, not by accident |
| **circuits**, SOCKS isolation credentials | **NO** | follows from the process split; per-`P` `IsolateSOCKSAuth` isolates within an instance, not across identity domains |
| **onion identity / service key** | **NO** | trivially — different services |
| **data directory** | **NO** | holds the control cookie and tor state; a shared directory re-links what the process split severed |
| control **cookie / auth file** | **NO** | consequence of the data directory and the control connection |
| control-protocol **client code** (types, parser, `AddOnion`, reply evaluation) | **YES** | library. No runtime state crosses; duplicating it is the ruled-against error |
| tor **binary discovery + hash pin** | **YES, as policy** | a verification *rule*, not a runtime handle. Both sides should verify the same binary against the same pin; that shares a decision, not a session |
| **listening ports** | **NO**, and must not collide | not shared state, but two instances need disjoint control/SOCKS ports — an allocation constraint the build must make explicit rather than discover |

**All three ambiguous classes are now RULED (Rick, 2026-09-08).** They were
named rather than decided quietly because an ambiguous class settled silently
is how crossover arrives later as a convenience.

- **Operator config file — SEPARATE FILES.** One `shekyl.conf` naming both tors
  would be a shared *file* and not shared runtime state, so nothing links the
  identities at runtime. It is nevertheless the single place an operator can
  mis-wire both onto one instance, and that failure would present as a config
  typo rather than a design breach. The convenience is small; the failure is
  exactly the crossover this row forbids.
- **Log sinks — SEPARATE SINKS.** Both sides already treat control-channel data
  as a forensic surface that must not be logged, so a shared sink does not link
  the identities *today*. It is where a future "just log the onion address for
  debugging" would link them in one line that looks harmless. Separate sinks
  mean that line cannot do damage even if someone writes it.
- **Managed-tor launch path — RULED: MANAGED.** Rick, 2026-09-08: *"yes,
  managed - the daemon can spawn it's own TOR."* The launch **code** is
  therefore shared between the two sides while the **instances** must not be,
  which is the sharpest remaining crossover risk in this row: reuse looks safe,
  and it is the most plausible route to one process serving both identities.
  **The mitigation is structural, not procedural** — the launch path moves into
  the neutral crate and takes the instance's identity (data directory, control
  port, service key) as a *parameter*, so a caller cannot obtain the other
  side's instance by reusing the function. Sharing the code cannot produce a
  shared instance, and an attempt to would be a compile-time argument error
  rather than a convention someone remembers to follow.

#### Build state — the neutral crate exists

The two `YES` rows and the MANAGED ruling's mitigation all name one thing: a
crate that belongs to neither side. It is **`rust/shekyl-tor-control-client`**, and the
control protocol (`control/`), the binary hash-pin gate (`binary.rs`) and the v3
onion identity encoding (`onion_identity.rs`) were lifted into it out of
`shekyl-tor-control-wallet` — a move with no behaviour change, so that nothing is built on the
old shape and then migrated.

`shekyl-tor-control-wallet` keeps exactly what the table marks **NO**: the `WalletTorControl`
supervisor and its cross-incarnation state, the vanguard rotation state machine
and the `VanguardsActive` witness, and the persona publish orchestration. It
depends on the client crate and does **not** re-export the launch path
(`TorControlClient`, `ManagedTor`, `AddOnion`), so a consumer that wants to
speak the protocol names the client crate. Types already on `WalletTorControl`'s
public surface (`OnionIdentity`, `EventSink`, `ControlError`) are re-exported
from the wallet crate, so wallet consumers do not take the launch crate just to
name a field.

The daemon sibling is `DaemonTorControl` in `shekyl-tor-control-daemon` (PWD-E7
piece 2). **UPDATE 2026-09-09: built and wired.** The crate owns the ephemeral
posture end-to-end (managed pinned tor via the neutral crate's parameterized
launch, in-memory v3 key, `ADD_ONION` `Flags=DiscardPK`, per-boot `ServiceID`,
bounded teardown) plus a blocking facade (`BlockingDaemonTor`) that owns its own
runtime so the FFI stays runtime-free. The daemon consumes it through
`shekyl_daemon_tor_probe`/`_start`/`_is_alive`/`_shutdown`
(`rust/shekyl-ffi/src/daemon_tor_ffi.rs`) from
`node_server::add_ephemeral_tor_zone` (`src/p2p/net_node.inl`): the default
posture engages when a pinned tor is installed, yields to operator-configured
`--anonymous-inbound`/`--tx-proxy`, and is disabled by `--no-ephemeral-tor`.
Per this row's table the crate depends only on `shekyl-tor-control-client` and
never names `shekyl-tor-control-wallet`; its tor's `DataDirectory` lives under
the daemon's config folder; it carries no vanguard state.

The isolation requirement is carried in the crate's own module doc rather than
left to this document: *no entry point here may default, infer, or discover which
Tor instance it is talking to.* That is the compile-time form of the MANAGED
mitigation above — every instance-identifying input is a parameter, so reusing a
function cannot yield the other side's instance.

One visibility change was forced by the move and is worth a reviewer's eye: the
SP-T0c pin gate's test bypass (`VerifiedTorBinary::unchecked_for_test`) was
`#[cfg(test)]`-private, and `cfg(test)` does not cross a crate boundary. It is now
`pub` behind the `unpinned-tor-for-tests` feature, which
`scripts/ci/check_test_only_features.py` holds to dev-dependency edges only. The
production gate is unchanged and is now *stronger*: `VerifiedTorBinary`'s field was
already private, and the type is now behind a crate wall as well, so the supervisor
cannot forge one even by accident.

#### The apparent contradiction with the accepted §7 residual, and why it is not one

A reviewer will find this and should find the answer here first.
`ARCHIVAL_BOND_2D2_SP_T0_TOR.md` and `..._TRANSPORT_PLAN.md` record a **ratified
residual**: `P` and the principal share one guard set, and the docs say
explicitly **"do not split instances to 'fix' it"** — because a non-default
config is itself a fingerprint to a guard observer, a weaker adversary than the
correlator a shared guard exposes.

**That ruling is about splitting ONE application's identities across two
instances. This ruling is about TWO applications not sharing one.** They are
different operations and the §7 reasoning does not transfer:

- The wallet's `P` and principal are both **wallet** identities inside one trust
  domain, and the residual was priced within it.
- The daemon's P2P onion is a **different domain**. Placing it on the wallet's
  tor would extend an accepted intra-wallet residual to a pairing nobody priced.
- Two applications each running their own tor is not a non-default config; it is
  two programs each doing the ordinary thing.

**And there is an asymmetry that makes the crossover strictly worse than the
residual it resembles.** Under PWD-E7 the daemon's onion is **ephemeral** — it
re-addresses every boot — while the serving persona's is **durable**. On one
instance, a guard observer watches a durable identity share its guard set with a
service that re-addresses repeatedly, which is a **repeated** correlation
opportunity against the durable identity. The §7 residual has no such generator:
both wallet identities are durable. So the accepted-residual argument does not
merely fail to transfer — it points the other way.

#### Crate shape (rule 25), proposed

The test the peer named is the right one: **neither crate's docs should have to
describe the other's posture.** `shekyl-tor-control-wallet` today opens *"Wallet-owned Tor
integration for the 2d-2 archival firewall (SP-T0)"*, so the daemon cannot
become a second consumer of that ownership without making that sentence false.

- **Lift** the protocol layer — control client, `AddOnion`/reply types, reply
  evaluation, binary verification — into a crate **neither side owns**.
- **`shekyl-tor-control-wallet` keeps the wallet supervisor**: vanguard rotation, serving
  posture, SP-T0 policy. Its doc sentence stays true.
- **A new daemon-side crate owns the ephemeral posture** (`shekyl-tor-control-daemon`,
  `DaemonTorControl`): mint, publish, read the `ServiceID`, tear down on shutdown.
  No vanguard state, because an ephemeral address has no tenure to protect.

**Not proposed: the daemon driving `WalletTorControl`.** It is a supervisor for a
long-lived managed tor with vanguard pinning and a retry policy — the wallet's
posture. Driving it from the daemon imports exactly the state this row forbids.

**All three ambiguous classes are now ruled; nothing in this row is owed before
code.** The launch-path ruling is the one that changed what gets built:

> **Managed.** The daemon spawns its own tor, so the default posture works
> without the operator configuring a control port first — a default nobody
> reaches is not a default. The cost accepted with it is that the launch code is
> shared, and the mitigation for that cost is **structural**: the launch path
> lives in the neutral crate and takes the instance's identity as a parameter,
> so a caller cannot reach the other side's instance by reusing the function.
> **The rule this row hands the implementation: no launch entry point may
> default, infer, or discover which instance it is starting.** Every one of data
> directory, control port and service key arrives from the caller. An
> implementation that adds a convenience overload without them re-opens exactly
> the crossover this row forbids, and the gate against it is that the overload
> would not compile without inventing the values.
