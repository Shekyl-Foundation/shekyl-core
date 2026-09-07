# P2P-2 cluster E — the node's own endpoint

**Status:** OPEN — design round, wargame pending. Rule 26 is cited explicitly
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

## 1. Why this round exists, and what it does not own

PWD-I1 removes `peer_id` from the wire. The lane that implements it
(`p2p/basic-node-data-address`, declared but not yet built) replaces it with a
`network_address` absorbing `my_port`. That lane owns the wire.

This round exists because **`peer_id` has two jobs in `is_peer_used`, and only
one of them has a replacement anywhere in the tree.** Removing the field
without ruling the second is a silent regression, and the second job needs
something the daemon does not currently have: knowledge of its own reachable
endpoint.

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

## 5. Open decisions

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

### PWD-E3 — self-dial avoidance once `peer_id` is gone

| Option | Adversary / channel | Concedes | Falsifier |
|---|---|---|---|
| (a) Address filter only, from a verified endpoint | gossip cannot forge it (verified, not asserted) | **nothing at all until an endpoint is verified**, including the whole startup window and every non-hairpinning node that also lacks (b) | a node that dials itself while holding a verified endpoint |
| (b) Fresh per-dial nonce: dialer sends `N`, our own acceptor drops an inbound bearing an outstanding `N` | groups nothing — per-connection, so the PWD-I2 eclipse-oracle argument does not bite | one field on the wire; the set must be bounded (entry removed on dial completion or timeout) or it is a memory sink | a replay that achieves more than making us drop the replayer's own inbound |
| (c) Both: nonce is detection, address filter is avoidance | — | two mechanisms | the nonce failing to catch a self-dial the filter missed |

**Proposed: (c).** The nonce is correctness and needs no address; the filter is
an optimisation that saves the wasted dial. Note the dependency direction:
**the nonce is what makes PWD-E2(a) possible at all**, so it is upstream of the
address, not replaced by it.

### PWD-E4 — cross-port duplicate avoidance (job 2)

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

## 6. Forward actions (rule 26 A5)

| # | Action | Target |
|---|---|---|
| F1 | Answer PWD-E5 against the built field set | `p2p/basic-node-data-address` |
| F2 | Whatever PWD-E3/E4 rule must land **with** the `peer_id` removal, not after it | same lane — removing job 1 and job 2 with no replacement is the regression this round exists to prevent |
| F3 | Rust shape (endpoint typestate `Candidate<Source>` → `Verified{at}` → `Stale`; `Zone` marker types with `type Dedup`/`type Announced`, distinct from `RelayZone`) | the Rust p2p node; rule-18 question of whether `RelayZone` derives from the transport zone is **not** settled here |
| F4 | Re-home PWD-I2's eclipse-completion-oracle argument when `ANON_ZONE_SENTINEL_PEER_ID` is deleted | the removal lane — the argument outlives its subject and is the standing reason not to reintroduce per-node identity |

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

**Why it must be drawn.** Each link is individually reasonable and the chain
is not: the middle link is unbuilt, the link after it is ruled, and the two
gates on it live in a round that is still open. A lane that lands `peer_id`'s
removal because "I1 is ruled" would be reading one link, not the chain.
PWD-E5's requirement sits on the same middle link and makes it strictly larger
than its title suggests.

## 7. What would reopen this round

- PWD-E2(b) shown unsound — the port-proving claim is reasoning, not a verified result.
- A measurement showing endpoint determination is not needed because the announce-and-hope path already reaches the network reliably.
- `-43`'s lane landing a field set that makes PWD-E3/E4 moot.
