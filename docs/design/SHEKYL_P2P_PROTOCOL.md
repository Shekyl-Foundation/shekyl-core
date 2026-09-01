# Shekyl P2P protocol — normative specification

**Status:** IN PROGRESS — **cluster I (identity and Sybil resistance) delivered
for ratification; clusters T, B and A not yet drafted.** Produced by the P2P-2
design round dispatched on
[`P2P_2_DISPATCH_BRIEF.md`](P2P_2_DISPATCH_BRIEF.md). Ratification is Rick's,
**per cluster**, on the relay-round convention; the umbrella chat reviews each
package first. **Nothing here is implemented — implementation is P2P-3.**

**Pinned:** `dev` @ `47bfa66c33000249b1402a4bb104ae20ab68b757`
(`git ls-remote origin dev`, 2026-09-01). Papers corpus at `shekyl-dev`
`4cabe8ef2`. Every claim below was read at these pins.

**Identifier family:** `PWD-` (P2P wire decision), registered at birth in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md).

---

## 0. How a decision is stated here

Every decision carries four things, and **a decision missing the fourth is not
ruled — it is a deferral with extra words**:

1. **Options** actually considered.
2. **The adversary and the channel** each option answers. Naming `T` and its
   channel is the threat-model bar; an option that answers no named adversary
   is decoration.
3. **What is conceded.**
4. **The falsifier.** For a value choice with no experiment to run, this is a
   **named reopening criterion** — a concrete future observation. The
   operational test: *a future reader must be able to recognise the trigger
   without re-deriving the decision.* "Reopen if p99 handshake latency at the
   Pi-4 floor exceeds X" passes; "reopen if this turns out wrong" does not.

---

## 1. Invariants — requirements in, not subjects

Restated from the brief §3 so no decision below reopens them.

1. **Ratified D++ / relay-privacy mechanisms are requirements-in** — the stem
   graph, `STEMS = 2`, the embargo backstop, the per-zone `hop`, and the
   arrival-is-stemmed rule (Q12-U2, landed).
2. **No authentication between unknown peers** (PW-19a), jointly entailed by
   three landed rulings. `XK`/`IK` are *inapplicable*, not declined: the `K`
   pre-message is the assumption that the parties are not strangers.
3. **Structural unlinkability.** Privacy is not a setting.
4. **PW-4/PW-5 are moot for gossip** (PW-7b) and carried as ground.
5. **The transport's adversary is the non-participant path observer.** The
   counterparty is conceded; arrival metadata is D++'s scope, taxed not
   eliminated.
6. **Clearnet gives confidentiality and integrity, not anonymity** (PW-3a).
   Anonymity is Tor's.

**The check that disposes of a whole family of proposals** (PW-19a, and it has
now killed four): *any mechanism that would let a node distinguish a legitimate
peer from a prober requires prior knowledge of that peer, and prior knowledge is
forbidden.* Test a proposal against that sentence **before** costing it.

---

## 2. Cluster I — identity and Sybil resistance

Delivered first because **PWD-I5's cross-document closure needs the relay
lane**, so it carries the longest external latency and should run in parallel
with the remaining clusters rather than after them. (The *disposition* load runs
the other way — cluster B carries ~20 bucket-4 rows to cluster I's 10 — so this
ordering is about latency, not volume.)

### PWD-I1 — session identity is fully ephemeral; no durable identifier on the wire

**RULED.** The transport carries **no durable peer identity**. `NN` has no
static keys, and nothing above the transport may reintroduce one.

At the tree, `peer_id` is already a per-process random `uint64` regenerated at
every start and **never persisted** (PWC-D4), with anonymity zones pinned to the
sentinel `1`. So the wire's *durability* is already nil; what this decision
settles is that it stays nil and that the remaining `peer_id` uses are justified
individually rather than inherited.

| Option | Adversary / channel it answers | Verdict |
| --- | --- | --- |
| **Keep per-process random `peer_id`** (status quo) | Self-connection detection and back-ping correlation, on the local node | **Adopted**, but each surviving use must be justified in cluster B — an identifier with no stated job is a linkage surface waiting for one |
| Durable node id | Would answer Sybil-resistance-by-identity | **Refused** — PW-19a; it is an enumeration key, and PW-20 records that `peer_id` was *never* a Sybil defence |
| No identifier at all | — | **Not adopted here**: self-detection (PWC-E14) and the back-ping (PWC-D11) currently consume it. Deleting it is a cluster-B question once those two have their own answers |

**Conceded.** Within a single session a peer is trivially correlatable across
its own connections — it dialled them. Session-scoped correlation is not the
asset; cross-session linkage is, and that is what ephemerality denies.

**Deliberately preserved:** self-connection detection is **public-zone only**
(PWC-E14), so a rejection cannot confirm a clearnet/Tor co-identity. Any
redesign must keep that asymmetry or it hands back the linkage PW-19a exists to
deny.

**Falsifier.** Name a mechanism the protocol requires that cannot work without
recognising a peer *across sessions* on the wire. If one exists, this decision
reopens; PW-19a would then have to be re-argued rather than assumed.

*This falsifier is a standing challenge by construction, and that is a
deliberate exception to §0's operational test rather than a lapse from it.* A
**removal** decision has no measurable quantity to trip on — the honest
reopening criterion for "X is not carried" is "show X was needed." It is not
open-ended: the two mechanisms that currently consume the identifier are named
in the row above (self-connection detection, the back-ping), both route to
cluster B, and **cluster B is where this challenge is first answered.** A reader
finding a third consumer there has met the trigger.

### PWD-I2 — peerlist disclosure is reduced, and the Shi et al. amplifiers are closed

**RULED.** Disclosure stays, bounded and anonymised, **with two changes**.

The current shape (all verified): up to 250 entries per message (PWC-D1),
disclosed on **both** handshake and timed-sync (PWC-B4), sampled over the whole
white list then shuffled and `last_seen`-zeroed (PWC-D2, an explicit defence
citing Cao et al.), refused wholesale if any entry is from another zone
(PWC-D10), with white/gray capped at 1000/5000 (PWC-D3).

| Option | Adversary / channel | Verdict |
| --- | --- | --- |
| Status quo | — | **Refused.** Shi et al. §III-A fills the 5000-entry FIFO graylist from *timed-sync responses* alone; §III-B cycles 1000 IPs through the white list |
| **Restrict peerlist disclosure to outbound-initiated exchanges** | The graylist-filling adversary, over inbound connections it opened | **Adopted** — the paper's own §VII-A countermeasure, and it removes the channel rather than rate-limiting it |
| **Cap records accepted per connection, not just per message** | The same adversary, amortising across many messages | **Adopted** — 250/message with no per-connection ceiling is a cap on the wrong quantity |
| Stop disclosing entirely | Topology mapping | **Refused** — peer discovery on an open gossip network needs it; and PW-3a records that discoverability is *structurally* incompatible with clearnet node anonymity anyway, so paying liveness for a property that cannot be bought is a bad trade |

**Conceded.** Topology mapping by a patient participant. PW-3a's discoverability
leg means an adversary can enumerate candidates regardless; these changes raise
the *cost and rate*, and do not claim to close it.

**Falsifier.** Restricting disclosure to outbound exchanges is expected to leave
peer discovery viable at the deployed out-degree. **Reopen if a fleet run shows
median time-to-`MIN_PROVISIONED_OUT_PEERS` on a cold node exceeding the current
figure by more than 2×** — the Q12-D6a rig is the instrument, and that is a
recognisable trigger rather than a judgement call.

### PWD-I3 — tenure is recognised by address, never serialized, and ordered by `first_seen`

**RULED**, and it ratifies what the tree already does rather than inventing a
mechanism.

- **Recognition key is the address.** Outbound continuity already matches on
  `peer.adr == cntxt.m_remote_address`, with `peer_id` only a secondary
  public-zone check (PWC-D6). The address family was ruled out as an *admission*
  basis (§6.10 — absent on Tor, lying on clearnet); it is **not** ruled out as
  *continuity bookkeeping*, and those are different jobs.
- **Nothing about tenure reaches the wire** (PW-18). The anchor list is
  persisted and its KV map is never sent (PWC-D5).
- **`first_seen` is an ordering input, not a log value** — it is the container's
  `by_time` index, and `get_and_empty_anchor_peerlist` drains through it while
  the dial loop stops at the first success, so it decides *which* anchors take
  the two slots.

**The constraint this decision must not lose (§39, F-8).** `forget`-on-close
resets tallies at **connection** granularity, so the convergence condition is
`warm-up ≪ mean outbound connection lifetime` — strictly stronger than the
process-uptime form, and it subsumes it. Its consequence is sharper still: *an
adversary clears its record by reconnecting rather than by minting an
identity*, and **"if anchors give a standing re-dial claim, reconnection is
nearly free and the defence is nearly nothing."** Any tenure scheme that pins on
address while leaving re-dial free is therefore self-defeating.

**Conceded.** The persistence double-edge (§7): a pinned honest peer is the
defence, a pinned adversary is durable. Pinning resists *active re-rolling*; it
does nothing structural against a patient peer that behaved well enough to get
pinned — the §6.9 concession, not a new caveat.

**Interaction the ruling acquires, and it belongs on the record.** Rick's
Tor-only default ruling composes badly with the re-entry-cost half of §12.10's
two bounds: §33.5 states that *"on an anonymity network key-minting is free, so
that wait is the entire cost"*, and F-8 shows the adversary reconnects rather
than mints. Defaulting the network onto Tor moves it onto the transport where
this bound is structurally weakest. **This is not an objection to the ruling** —
it is a named consequence that the eviction floor must be designed against, and
it is recorded here so PWD-I4's round inherits it rather than rediscovering it.

**Falsifier.** **Reopen if measured mean outbound connection lifetime falls
below the warm-up any admission mechanism requires** — F-8's own condition,
already stated as a comparison a measurement can settle.

### PWD-I4 — `ρ` / `g_max`: **DEFERRED to its own round, with the blocker named**

**NOT RULED.** Deferred under
[`22-no-lazy-deferral`](../../.cursor/rules/22-no-lazy-deferral.mdc), which
requires a named blocker rather than a decision postponed for convenience.

**The blocker is the owning document's own assessment, not this round's
reluctance.** §7 calls Q-10 *"a real blocker (its own grounding, likely its own
design round)"*, and the relay document's ledger calls it **"the single largest
blocker in this document"** — it gates `ρ`, §12.11's selection tier, the
cooldown/eviction threshold and `ε_explore`. §7 also hands this round the test
that decides the matter: ***"a bound that depends on a parameter owned further
down is not a bound — it is a lower bound wearing a costume"***, and warns the
seal may move again to address-manager behaviour or seed-node trust.

**Why deferring is cheap here, which is why it is honest rather than evasive.**
`g_max` is a **node-local selection-layer policy parameter** — not a wire
quantity, not consensus, **not genesis-frozen**. A node can change its
outbound-selection discipline without anyone's agreement, so this does not fork
the chain and carries no genesis deadline. That is a materially different
deferral from anything with a freeze date.

**What the sub-round inherits, so it does not restart cold:**

- **Its first task is a re-location, not a derivation.** §7 names the churn
  coupling as the non-obvious constraint and cites `dandelionpp.cpp:144,160` —
  **that file no longer exists**; the logic is in
  `rust/shekyl-relay-privacy/src/conformance/selection.rs`.
- **The load-bearing question, already answered numerically here:**
  `P2P_DEFAULT_OUT_PEERS = 12` against `ANCHOR_CONNECTIONS_COUNT = 2`, so **2
  of 12 outbound slots are anchor-backed and 10 are fresh-drawable**, with
  `connections_maker` refilling anchors first, then white, then gray.
- **Two documents describe complementary halves** — see PWD-I5.
- **The defence shape is pre-narrowed** (§6.10): behavioural floor plus
  guard-pinning; the address/subnet/ASN family is ruled out on both transports.
- **A design constraint, not a free property** (§6.10): the economic deterrent
  reaches the diffuse passive observer *only if stem-eligibility is gated on
  pinned tenure*.
- **The only `ρ` number in existence is disqualified** — a provisional `≈ 2 %`
  evaluated at `g = f`, which §13.5 calls *"a placeholder squared"*.
- **If persistence becomes a requirement, its bounding is part of the spec**
  (§33.6): bucketed counts rather than event logs, bounded retention, no peer
  identifiers at rest — specified *at the same time* as the requirement.
- **Two symbol collisions to pin before substituting numbers:** the D++ paper's
  `f` is the fraction supporting D++, not our adversary reach; its `d` is
  **total** degree, so `STEMS = 2` is `d = 4`.

**A second, independent reason the deferral is right — and one that did not
exist when it was taken.** If the eviction floor's re-entry-cost bound is
**transport-dependent** (§33.5: key-minting is free on an anonymity network;
F-8: the adversary reconnects rather than mints), then a `g_max` derived before
the default-transport question settles would be **derived against the wrong
transport**. The Tor-only default ruling landed after this deferral and
retroactively strengthens it.

**An obligation the sub-round inherits from that, to be argued rather than
assumed.** §6.10 deters *"the budget-constrained passive observer, by
economics"* and explicitly does **not** defend against the unconstrained one.
If Tor drives re-entry cost toward zero, **the economic deterrent is precisely
the thing that evaporates.** The sub-round must state plainly whether the
eviction floor retains *any* cost term on Tor, or whether it degrades to pure
behavioural exclusion with no whitewash penalty. §54.4(a)'s *"inert →
degraded"* softening is why that is survivable rather than fatal — but it is a
survivability argument that must be **made**, not inherited.

**Reopening criterion (this is the deferral's falsifier).** The sub-round opens
when the parameter-ownership question is settled — i.e. when it can be shown
that `g_max` does **not** depend on address-manager behaviour or seed-node
trust, or those are brought into scope. **If a later cluster produces a decision
that depends on a numeric `g_max`, that dependency is itself a finding and this
deferral is void.**

### PWD-I5 — Q-10 closure is written back into `DAEMON_RELAY_PRIVACY.md`

**RULED** as an obligation on whoever closes Q-10, discharging PW-26's
requirement that the document declaring a dependency records its discharge —
*"do not let this be a one-way read."*

**The closure must carry this reconciliation, because reading either source
alone specifies the wrong thing and both failures are silent:**

- **§12.10** reframes the deliverable *away* from a pool-share `g`: *"bounding
  pool-share `g` was bounding the wrong quantity"*, replacing it with two
  bounds — eviction responsiveness × re-entry cost, and eclipse-resistance as
  conscription cost.
- **§7** says Q-10 terminates on **one number**, `g_max` = the *sustained,
  churn-resilient* outbound-selection share, with the chain
  `ρ ← δ ← W3(g)+W3c(g) ← g_max`.

**They reconcile: §7's `g_max` is precisely §12.10's *full-eclipse* regime —
the one regime of three where pool-share survives.** Observation is out of
scope and partial disruption is backstop-dissolved. A round reading only §12.10
would decline to specify `g_max` at all; a round reading only §7 would specify a
pool-share `g` across all three regimes.

**Two further staleness hazards the closure must not step in:**

1. **§12.11's body is superseded in part.** The Exploit tier is D++ §4.5
   version-checking, which the paper **tests and rejects** — at low `β` it
   *"actually increases the likelihood of getting deanonymized."* The live
   mechanism is **uniform random selection over the non-cooled admissible set;
   reputation gates admission, it never orders the draw** (§54.1). Consequently
   **`ε` has disappeared as a parameter** and the ossification finding is *moot
   rather than mitigated* — a closure that derives `ε_explore` is deriving a
   parameter that no longer exists.
2. **`ρ` is not mentioned in §12.10 at all**; its canonical statement is §13.5.
   And §13.5's own scope narrowing applies: after §14, *"the only `δ` left to
   price is the W3 residual."*

**Falsifier.** **Reopen if the relay lane rules that §12.10's two bounds
replace `g_max` rather than containing it** — that would falsify the
reconciliation above, and it is a ruling a future reader can recognise.

### PWD-I6 — the Shi et al. graylist and whitelist sub-attacks are closed by PWD-I2

**RULED — absorbed, not separately specified.** The census established that
sub-attack ③'s two arms are already answered (private-transaction arm
structurally inapplicable since RT-9 removed `--public-node`; D++ arm refused
because a double-spend is a no-drop offense), while **sub-attacks ① and ②
remained unaddressed**. PWD-I2's two changes close both: restricting disclosure
to outbound-initiated exchanges removes the graylist-filling channel, and a
per-connection acceptance cap removes the amortisation the whitelist attack
needs.

**One residue is *not* closed and is recorded rather than absorbed.** The
double-spend no-drop guard is **inherited** — `f7fd209ed`, upstream Monero,
2024-03-07 — and carries the census's `inherited-defensive` class: it works, and
no Shekyl record has examined it. **A rewrite that re-derives the tx-ingest path
from the census would drop it silently.** Cluster B owns that as PWD-B7.

**Falsifier.** **Reopen if a fleet run reproduces graylist saturation under the
restricted-disclosure rule** — the paper's own attack is the test, and the
Q12-D6a rig can run it.

---

## 3. Cluster I disposition — the census rows this cluster accounts for

Ten bucket-4 `PWC-D` rows. **Ruled / absorbed / deferred must sum to 10.**

| Row | Disposition | Where |
| --- | --- | --- |
| PWC-D1 (250-entry disclosure) | **Absorbed** | PWD-I2 |
| PWC-D2 (anonymised head) | **Ruled** — kept; it is a real defence and survives the disclosure restriction | PWD-I2 |
| PWC-D3 (1000/5000 caps) | **Absorbed** | PWD-I2 (the per-connection cap is the fix; the list caps are not) |
| PWC-D4 (`peer_id` per-process random) | **Ruled** | PWD-I1 |
| PWC-D5 (anchor keys; `first_seen` ordering) | **Ruled** | PWD-I3 |
| PWC-D6 (address-keyed continuity) | **Ruled** | PWD-I3 |
| PWC-D8 (dual-stack field parity structurally tested only) | **Deferred — named blocker: LV-3.** It is a *test-coverage* gap on the Rust/C++ parity surface, not an identity commitment; it lands when the read side migrates | LV-3 |
| PWC-D9 (`sanitize_peerlist` IPv4-only port-0) | **Deferred — named blocker: tor port-0 semantics disputed** (`tor_address::unknown()` is port 0), named as such by #587 rather than invented here | cluster B |
| PWC-D10 (cross-zone peerlist refusal) | **Ruled** — kept unchanged | PWD-I2 |
| PWC-D11 (back-ping gate to white list) | **Absorbed** | PWD-I2 |

**Sum check: 5 ruled + 3 absorbed + 2 deferred = 10.** ✅

**PWC-D7** is bucket-2 (ratified by #587) and is excluded from the bucket-4
accounting, as are all `PWC-X` rows.

**Running total against the round's gate:** 10 of **46** bucket-4 rows
dispositioned. Clusters T (~16), B (~20) and A remain.

---

## 4. What cluster I does not decide

- **`ρ` / `g_max`** — PWD-I4, deferred with the blocker named.
- **Whether `peer_id` is deleted outright** — cluster B, once self-detection
  and the back-ping have their own answers (PWD-I1).
- **The inherited double-spend no-drop guard** — cluster B, PWD-B7.
- **Anything about the transport itself** — cluster T.

**Carried forward to cluster B, so it is inherited rather than re-derived.**
PWD-I2's per-connection cap turned on a defect class worth naming: *250 records
per message with no per-connection ceiling caps the wrong quantity*, because the
attack amortises across messages. **PWD-B1's rate limits face exactly that
question** — a limit that bounds per-message volume while the adversary's budget
is per-connection or per-epoch is a limit on the wrong variable, and it will
measure green while the attack runs. Check each proposed limit against the
quantity the adversary actually spends.

**Also carried forward: `network_config` is a dead struct, not one dead
constant** (PWC-F3 records the map; this is the fields). Enumerated at the pin,
**four of its eight fields are write-only** — their only occurrence outside the
struct definition is the assignment itself at `net_node.h:387-392`:
`handshake_interval`, `packet_max_size`, `config_id`, `send_peerlist_sz`. The
other four have real readers (`max_out_connection_count` 17,
`max_in_connection_count` 5, `ping_connection_timeout` 2, `connection_timeout`
2), so this is a **partial cleanup, not a whole-struct delete.**

Two things make it worse than ordinary dead weight, and both belong in the row:

- **Three of the five fields the KV map serializes are among the dead four**
  (`handshake_interval`, `packet_max_size`, `config_id`). The map that *looks
  like* a wire commitment is majority dead, which is exactly the review-cost
  hazard the census exists to price.
- **Two of the dead fields are dead *copies of live constants*, which makes
  them traps rather than merely inert.** The 60-second cadence is driven by
  `once_a_time_seconds<P2P_DEFAULT_HANDSHAKE_INTERVAL>` (`net_node.h:618`) — a
  **template argument from the constant**, not from the field — and
  `send_peerlist_sz`'s value is read directly from
  `P2P_DEFAULT_PEERS_IN_HANDSHAKE` at `net_node.inl:2655`. So an engineer who
  changed the cadence by editing `m_net_config.handshake_interval` would
  observe **no behavioural change and no compiler complaint**. A dead field
  holding a stale duplicate of a live value is worse than an empty one.

`config_id` is the provenance tell: an identifier for *which config set is in
force* only makes sense if configs are exchanged, and that machinery is not
wired here. What remains is the vocabulary of a negotiation that does not
happen.
