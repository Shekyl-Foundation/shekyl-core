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
as clearnet-effective and overlay-limited — which is exactly the framing the
§3.1c correction retired.

> **Question routed to the deliverable, not asserted here — and re-posed
> 2026-09-06 after reading the passage properly.**
>
> [`SHEKYL_P2P_PROTOCOL.md`](SHEKYL_P2P_PROTOCOL.md) `:142-150` is a **three-tier
> ladder** — *worst: verify a claim; better: replace it with your own
> observation; best: bind it into the transcript* — and the same-host cap
> appears as the **worked example of tier two**, not as a claim about its
> adversarial strength. As that example it is **correct**: nothing is claimed,
> so nothing can be forged.
>
> **So the line needs no correction. What is missing is a fourth statement the
> ladder does not make:** tier two closes the **forgery** surface and is silent
> on the **multiplication** surface. An observed property can still be cheap to
> produce — a /24 gives 256 hosts, a keypair gives one onion — so "nothing to
> spoof" and "adversarially binding" are **independent**. This is why `-43`
> could stop leaning on the justification without the line being wrong: they
> needed a property the ladder does not supply.
>
> **The risk is that the ladder reads as a completeness ordering.** A reader
> reaching tier two concludes they have arrived somewhere adequate, and tier
> three is stronger against a *different* problem.
>
> **The answerable question, therefore, is about the framework and not about
> any adopted option:** *does the ladder need a note that tier two is silent on
> cost-to-multiply — that a tier-two mechanism can be correct and still bound
> nothing an adversary cares about?* Posed as "is the cap's justification
> adequate?" it invites a defence of a line that is not wrong. Still that
> document's owner's call.

## 5b. The decision tables



Each table: the options, the adversary and channel each answers, what it
concedes, and the falsifier that reopens it.

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

**Proposed: (a).** `has_too_many_connections` (`:3115-3136`) already computes
the predicate; it is a sibling-site wiring, not new mechanism. Its overlay
limitation is not a regression — `peer_id` was a shared constant there
(PWD-I2), so the check never fired on those zones either.

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

`-43` reports the nonce is inserted into the zone's in-flight set **before the
request is written**, and erased on attempt termination or match. **That
ordering is the whole of the bounded-set requirement**: if it holds, the bound
is satisfied *by construction*; if the insert moves after the write, it is
satisfied only while someone remembers to keep it there.

> **Falsifier, to be written against that unit rather than asserted about it:**
> a test that goes red when the insert is moved after the request write. Not
> yet written — this round does not own that unit, and the claim is a report,
> not an audit. Recorded so the check is not re-derived.

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
| F5 | Write the in-flight-set ordering falsifier described in §5c — a test that reds when the nonce insert moves after the request write | the removal lane; this round does not own that unit |

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
