# Tor cover posture — relay contribution, not a protocol carrier

**Status: LIVING CONTRACT.** RULED 2026-09-04, recorded 2026-09-12. Identifier
family `TRC-1…TRC-n` (index row registered at birth per rule 94 §1). Decision
authority: Rick. This document records a decision that was reached in design
conversation and never written; the ruling is not new, its record is.

That class — **ruled-but-unwritten** — is why the record exists. Ruled-and-
written is fine. Unruled-and-unwritten presents as open and gets decided.
Ruled-but-unwritten is the dangerous one: every surface says "open" while the
decision is real, so a grep finds nothing and the next pass re-derives, possibly
differently. Rule 23 cannot catch it; the four disposition classes all assume
the decision reached a document.

---

## 1. The ruling

**On the Tor zone, wire-observer resistance is obtained by operator posture —
running a non-exit Tor relay in the same Tor process the node uses as its
client, not by a protocol-level cover-traffic carrier.**

Cover comes from *volume on that process's OR connections*: a relay's uplink
already carries thousands of fixed-size, per-hop-encrypted cells per second,
and the node's own originated cells are indistinguishable among them **only
when they share those connections**. An 8 KiB stem is seventeen cells inside a
stream doing thousands. A second Tor for the daemon's SOCKS/onion — including
the default managed ephemeral instance — keeps originated cells on their own
OR connections; a wire observer can still separate that burst from relay
volume. The node stops emitting a constant-rate envelope of its own and stops
paying for one.

Three consequences follow immediately:

- **Stems go out over the ordinary connection, immediately.** No fixed slots, no
  waiting for the next cadence tick.
- **Every fixed-slot artifact stops having a subject on this zone** —
  fragmentation, `MAX_FRAGMENTS`, epoch-miss arithmetic, the in-flight
  remainder, the length leak, the empty-message wedge.
- **The anon embargo loses its largest inherited term.** The ~50-minute figure
  was an artifact of a cadence constant, not a derived requirement.

## 2. What is preserved

**The carrier mechanism is retained.** `shekyl-relay-privacy`, `params::carrier`,
the noise-slot machinery and its tests stay in the tree and stay maintained.

This ruling **narrows the carrier's scope**; it does not abandon it. The carrier
remains the cover mechanism for encrypted network layers other than Tor, where
no relay-volume equivalent exists and where substitution cover is the only
available construction. A future encrypted zone that ships without a
volume-cover story inherits the carrier as built.

Because the mechanism is retained,
[`COVER_TRAFFIC_RESTORATION.md`](COVER_TRAFFIC_RESTORATION.md) §1.6's
abandonment clause is **not** triggered by this ruling. The carrier's
do-not-delete argument stands, with its scope restated. What must change in that
document and its neighbours is the claim that the carrier is the Tor zone's
cover mechanism — see §10.

### 2.1 What this reopens — COVER_TRAFFIC §1.7 Axis 3

[`COVER_TRAFFIC_RESTORATION.md`](COVER_TRAFFIC_RESTORATION.md) §1.7 Axis 3
(**Ruled 2026-08-23**) said relay cover cannot substitute for the carrier at
any measured relay traffic level, because a guarantee that holds only for
operators who relay is **privacy as a setting**, which mission priority 2
forbids. That substitution foreclosure is **reopened for the Tor zone** by this
document.

The mission-2 objection is real. It is the cost named in §6, not a refutation
of Axis 3's reasoning. Axis 3's remaining standing rule — **no protocol
constant may be derived against an assumption of relay cover** — is
**preserved** (§5: not load-bearing on any protocol path). What is withdrawn
is only the claim that the carrier must therefore remain the Tor zone's cover
mechanism.

## 3. Why volume rather than substitution, on Tor specifically

Substitution cover — a constant-rate envelope the node emits whether or not
anything is happening — gives wire-observer recall of exactly zero. That is a
structural property, and it is strictly stronger in kind than what volume cover
provides. It is also, on Tor, the expensive way to buy a property the network
already sells.

Tor's cell format does the work substitution was simulating. Cells are 514
bytes, uniform, and encrypted per hop, and a relay carries its own client
circuits over the same OR connections it already holds to other relays. An
observer of **those** connections cannot separate relayed cells from originated
ones. That claim is false of a sidecar client Tor: originated circuits then
have their own OR connections, and the relay's volume is unused as cover. The
protocol does not need to manufacture the indistinguishability; it needs the
node's client circuits to ride the relay process. Operator form:
[`docs/TOR_RELAY.md`](../TOR_RELAY.md).

Against 3 KiB per 12.5 s of manufactured envelope, a modest relay's throughput
is not a close comparison. **That comparison is not the measurement §8 owes.**
Earlier figures (including a ~180 KiB/s burst-floor null result used as a
circuit-throughput stand-in) are not pins of sustained client-circuit
throughput and must not be quoted as such.

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

**Sizing is owed, not inherited.** Earlier consumption figures were derived for
a constant-rate carrier at a candidate cadence. That load profile no longer
applies: without the carrier, Tor consumption is bursty onion-service and fetch
traffic rather than a non-idling floor. The offset commitment is the durable
part; the number that satisfies it must be re-derived against the actual
profile before it is quoted anywhere. See §8.

**Path selection stays entirely Tor's.** Never route Shekyl traffic through
Shekyl-operated relays, and never prefer them (`COVER_TRAFFIC_RESTORATION.md`
§1.7 constraint 1, preserved). Otherwise an adversary running Shekyl nodes
acquires relay positions *on Shekyl circuits*, which is the worst outcome
available here.

## 5. Constraints on the relay posture

**Non-exit only.** Middle or guard relay, no exit policy. Stated explicitly
wherever this is recommended, because "run a relay" without the qualifier will
get an operator an exit relay and an abuse complaint. Exit operation carries
abuse-handling and legal exposure the project does not ask of its operators and
does not need for cover.

**Separate process from `shekyld`, same Tor process as the node's client.**
The relay must not share a process with the daemon. Relay throughput and
uptime are externally measurable by design — that is how bandwidth authorities
work — so a relay co-located in the daemon process turns the daemon's uptime
into a remotely probeable signal. The same principle applies to any other
externally measured relay property. The operator must be able to restart
`shekyld` without restarting the relay, and the reverse. **Separate from
`shekyld` is not a second Tor for Shekyl circuits.** Mixing is cells on the
relay process's OR connections; the daemon's SOCKS outbound and onion inbound
must be that process (operator `--tx-proxy` / `--anonymous-inbound` against
it, which yields the default ephemeral spawn). Putting the relay *inside* the
daemon-spawned managed Tor remains rejected (§9).

**Not load-bearing on any protocol path.** No consensus rule, no mechanism, and
no default behaviour may assume the node's operator runs a relay. The posture
improves an operator's position; it is never an input a protocol check reads.

**Never prefer Shekyl-operated relays.** Path selection stays Tor's (§4).

## 6. What this discharges, and for whom

Stated plainly because it is the cost of the ruling, not a caveat on it.

The carrier would have discharged the wire-observer objective **for every node
by default**. The relay posture discharges it **for operators who adopt it, and
not at all for those who do not**.

That is a real reduction in what the protocol guarantees, and it is the reason
this is a reclassification — cover moves from a *protocol mechanism* to an
*operator posture* — rather than a swap of one mechanism for a better one. Any
document that claims a default wire-observer property on the Tor zone must be
corrected rather than reinterpreted.

## 7. Accepted trades and residuals

**Structural becomes statistical.** Constant-rate cover made the observer's
question unanswerable. Relay cover makes it a question the observer can attempt:
"is this burst relayed or originated?" We expect to win that question at any
realistic relay volume, but it is a question we must keep winning rather than a
property we hold.

**The cover is not the node's to verify.** Nothing inside the daemon can
determine whether the uplink currently provides cover. A relay at 04:00 with low
consensus weight may be nearly idle. The node therefore cannot refuse to act
when uncovered, which a carrier-based design could have done.

**It ramps.** A new relay carries little for days while consensus weight builds,
so a fresh install has no cover precisely during the window in which it is most
identifiable as a new participant.

**It is Tor's decision, not ours.** Path-selection weights, flag assignment and
load are outside the project's control and can change without notice.

**Enumerability residual.** A relay IP in the consensus advertises "runs Tor,"
not "runs Shekyl," and the relay set is a poor candidate list. Emit-attribution
on the anon zone is structurally unavailable, so the onion↔IP adjacency is not
newly reachable by this posture. **Publishing overlay inbound from that same
listed process is the mixing topology for inbound, not a protocol
requirement** — inbound on a second Tor is uncovered inbound. The residual that
remains: if Shekyl operators adopt relaying disproportionately, the population
correlation strengthens over time. This is why the posture is documented as a
contribution and a recommendation and is never made a default or a
requirement.

## 8. Falsifiers and reopen criteria

**The measurement this ruling rests on has not been taken.** A Shekyl node
whose Tor **client is the same process as** a modest non-exit relay, and how
much traffic that process actually carries across hours and consensus weights.
A sidecar client Tor is not this measurement's subject — originated cells
would not be on the relay's OR connections. It is the one input that cannot
be reasoned to, and it decides whether the cover is real at the sizes an
ordinary operator runs.

Falsifier chain, in the [`PWD-E8`](P2P_2_ENDPOINT_ROUND.md) shape — the subject
must exist before the measurement can:

1. The posture is documented (`docs/TOR_RELAY.md`: shared-instance bind) and
   that operator topology is running.
2. Carried traffic is measured across hours and weights.
3. If measured cover at ordinary operator scale is insufficient to make
   originated cells indistinguishable, **this ruling reopens** and the carrier's
   scope re-expands to the Tor zone.

**Reciprocity falsifier.** Consumption is re-derived against the post-carrier
profile (§4) and Foundation relay capacity is sized above it. If measured
consumption exceeds contributed capacity for a sustained period, capacity is
added; the commitment is not satisfied by intent.

**Scope falsifier.** If an encrypted zone ships with its own volume-cover story,
the carrier's retention argument (§2) weakens for that zone and should be
re-examined there — not here.

## 9. Rejected alternatives

**Every node relays, as the protocol's cover mechanism.** Rejected. Making
relaying a default puts every node's IP in a public directory and creates
same-host correlation with a hidden service dialling peers. The escape hatch
closes: an unadvertised relay carries no traffic and provides no cover, so
advertised-and-listed is the only configuration that works.

**Exit relay.** Rejected. Abuse-handling and legal exposure the project does not
ask of operators, for no additional cover.

**Carrier on the Tor zone.** Rejected as the Tor-zone mechanism. Cover by
substitution forces fixed slots, which force fragmentation, which produced the
cadence, `MAX_FRAGMENTS`, epoch-miss, the discard-on-rebind defect, the length
leak, the empty-message wedge, and the inherited embargo. Retained for other
encrypted layers, where no volume alternative exists (§2).

**Relay co-located in the daemon process.** Rejected. Externally measurable
relay properties become a remote probe of daemon state (§5). The daemon-spawned
managed Tor stays client-only; do not add relay flags to it.

**A second Tor process for the daemon's SOCKS/onion, as cover.** Rejected as a
cover configuration. Originated cells then travel that client's own OR
connections. The default managed ephemeral Tor is that second process;
`--tx-proxy` / `--anonymous-inbound` against the operator relay yields it.
This is not a new ruling — it is the §3 mixing claim stated so "separate
process" cannot be read as a sidecar client Tor.

**Preferring Shekyl-operated relays for Shekyl circuits.** Rejected (§4). Path
selection stays Tor's.

## 10. Same-change doc tasks (rule 91)

Discharged in the 2026-09-12 recording change that landed this document.

- Register `TRC-1…TRC-n` in [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md)
  at birth (rule 94 §1), after the prefix uniqueness gate.
- [`COVER_TRAFFIC_RESTORATION.md`](COVER_TRAFFIC_RESTORATION.md): restate the
  carrier's scope as encrypted zones other than Tor. §1.6 is **not** triggered;
  the do-not-delete argument stands with narrowed scope. Correct any text
  presenting the carrier as the Tor zone's cover mechanism. §1.7 Axis 3 is
  SUPERSEDED for the Tor-zone substitution question; its no-constant-from-
  relay-cover standing rule is preserved.
- [`DAEMON_RELAY_PRIVACY.md`](DAEMON_RELAY_PRIVACY.md): correct any wire-observer
  claim that assumes a default carrier on the Tor zone; the property is now
  posture-conditional (§6).
- Operator documentation: [`docs/TOR_RELAY.md`](../TOR_RELAY.md) — the non-exit
  relay recommendation, with §5's constraints and §7's trades stated, so
  adoption is a choice rather than a default. **UPDATE 2026-09-12:** the
  operator form names the shared-instance bind (daemon SOCKS/onion on that
  same relay process). A sidecar client Tor is uncovered; this is the §3
  claim, not a new ruling.
- [`FOLLOWUPS.md`](../FOLLOWUPS.md): one pre-genesis row for the §8 measurement,
  blocker named as the falsifier chain's first link.
