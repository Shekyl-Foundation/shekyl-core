# P2P-3 — the implementation round

**Status:** OPEN 2026-09-21. Pinned to `dev` `059aca264` (merge of #810);
every `file:line` below was read at that SHA. Rule 26 is cited explicitly
(`26-sub-pr-design-discipline.mdc`): this round splits a subsystem migration
across multiple short-lived PRs with design rounds before implementation cuts,
so A2 (audit-against-actual-code) and A3 (threat-model framing) are
load-bearing, not optional.

**This round mints no decisions.** `SHEKYL_P2P_PROTOCOL.md` §0.5 is the
per-decision status of record, and `PWD-` stays the decision vocabulary.
P2P-3 owns *implementation*, and is sliced by the §0.5 rows each slice flips.

---

## 0. Why this round exists, and why its absence was a defect

**P2P-1** was the wire census. **P2P-2** was the design round, deliverable
[`SHEKYL_P2P_PROTOCOL.md`](SHEKYL_P2P_PROTOCOL.md). **P2P-3 was nominated to
carry implementation and has never been opened** —
[`SHEKYL_P2P_PROTOCOL.md`](SHEKYL_P2P_PROTOCOL.md):51 says so in the
document's own words.

The work landed anyway, through ordinary lanes. §0.5 exists *because* of that:
the protocol document claimed nothing in it was implemented while **eight
merged PRs had already built parts of it**. PR #812 is the latest instance of
the same pattern — a finding, a row, and a forward cut arriving on a lane
rather than in the round nominated to carry them.

**A round that is never opened does not stop work; it stops work being
tracked.** That is the defect this opening closes, and it is why the opening
carries a citation sweep (§3) rather than a plan: forty-odd rows across eight
documents are waiting on a gate that nothing was holding.

---

## 1. Scope, and the boundary against the LV- family

**P2P-3's scope is implementation across clusters T / B / I / A / E.** Not
decisions — those are PWD-, and §0.5 records their status.

### 1.1 A family is not an owner

`LV-` is a **family**: work items in the Levin migration. **P2P-3 is a
round**: an owner. The distinction is the same discipline as *a cluster is not
an owner* — the recorded reason PWD-B11 was minted for PWC-D9 — and it is why
`LV-3` can sit in both sets without ambiguity:

| | `LV-` | P2P-3 |
| --- | --- | --- |
| **Kind** | family (work items) | round (owner) |
| **Records** | that LV-3 exists, and what it costs | that LV-3 is being done, and by whom |
| **LV-3's row** | the [`IMPLEMENTATION_INDEX`](IMPLEMENTATION_INDEX.md) `LV-` row, which **points at P2P-3** | slice 1 of the register in §4 |

The index's `LV-` row already records that **LV-3 "still gates on its own
design round"** — a round that did not exist. **P2P-3 is that round**, and
LV-3 is the handover point between the two sets.

### 1.2 P2P-3 mints no new identifier family

Deliberate, and the reason is the defect above. A parallel implementation-id
family (`P3-1`, `P3-2`, …) would create **a second place to look for the same
fact** — whether a decision is built — which is precisely how §0.5's document
spent months wrong about its own state.

So: **slices are named by the §0.5 rows they flip.** `PWD-` remains the
decision vocabulary, which is already true in practice — PWD-I7 and PWD-I8
were minted under `PWD-` on 2026-09-21 despite not being P2P-2 round
decisions.

**Falsifier for this choice (rule 21):** if a slice is ever needed that flips
*no* §0.5 row — pure refactor, no decision status changed — then the naming
scheme has a gap and a family is owed. Reopen here, not by minting one
silently.

---

## 2. The structural finding this round exists to fix

**Nothing in Rust owns a CONNECTION.**

| Crate | Owns | Does not own |
| --- | --- | --- |
| `shekyl-levin` | bytes — framing, caps, noise | who sent them |
| `shekyl-peer-policy` | **stateless verdicts** — `DropVerdict`, `BlockIngest`, `HostInboundCap` | the peer the verdict is about |

Every one of those verdicts is a function C++ calls **with values C++ walked
itself**. The connection lives in `net_node.inl`'s `foreach_connection` lambda
and in epee's context object.

**That is why the per-host cap became an address comparison inside a loop:
there was no object to hang a category on.** PWD-I8 is a missing **noun**, and
it is the same missing noun for:

- ~~**PWD-I8** — *what is this inbound connection to me?*~~ **STRUCK
  2026-09-21** by [`LV3_CONNECTION_OBJECT.md`](LV3_CONNECTION_OBJECT.md) §2.9.4:
  I8's remedy is a **deletion plus a measurement**, and neither reads a
  category. Retained struck rather than removed, because I8 is why this slice
  was cut first and the register must show that the reason changed.
- **PWD-E1/E2** — the endpoint a connection claims, and what verified it
- **PWD-B1** — the token bucket, which is per-peer state with no peer to live on
- **PWD-B2** — per-peer accounting, same
- **PWD-B7's score** — *"the tri-state verdict that makes that operational is
  owed to P2P-3"* ([`SHEKYL_P2P_PROTOCOL.md`](SHEKYL_P2P_PROTOCOL.md):4431)
- **PWC-E5** — idle kick and score floor, deferred with both inputs *"owed by
  rows this round did not close"*, same line
- **the failure-window row** — `record_addr_failed` takes an address and
  nothing else, so the failure *class* is discarded at the call site

**One missing noun, six consumers** — counted from the rows above with I8
struck, not carried from the prior figure. That is still the argument for LV-3
as slice 1: it is not the cheapest slice, it is the one the others are waiting
on. **What changed on 2026-09-21 is the object's identity, not the case for
building it** — see [`LV3_CONNECTION_OBJECT.md`](LV3_CONNECTION_OBJECT.md)
§2.9.8, where identity moves from I8's category to the endpoint's provenance
plus the per-peer state that has nowhere else to live.

---

## 3. Cleared-gate sweep — the citations this opening unblocks

**37 citations across 8 documents**, counted at `059aca264` by
`git grep -c 'P2P-3' -- docs/` rather than inherited. *(The dispatch brief that
opened this round carried a headline of 40; its own per-file breakdown sums to
37, and 37 is what the tree holds. Recorded because a composite figure that
disagrees with its own itemisation is the shape rule 94 §3 exists to catch.)*

| Document | Citations | Disposition |
| --- | --- | --- |
| [`SHEKYL_P2P_PROTOCOL.md`](SHEKYL_P2P_PROTOCOL.md) | 20 | §0.5 status rows and PWD bodies naming P2P-3 as the implementation carrier. **Land across slices**, each flipping the row that names it. PWD-B7's score and PWC-E5's inputs are **slice-1 dependents** (§2) |
| [`P2P_1_WIRE_CENSUS.md`](P2P_1_WIRE_CENSUS.md) | 4 | census rows routed to implementation. **Land in slices**; no retirement |
| [`P2P_2_REQUIREMENTS_REGISTER.md`](P2P_2_REQUIREMENTS_REGISTER.md) | 4 | requirements whose discharge is implementation. **Land in slices** |
| [`P2P_2_DISPATCH_BRIEF.md`](P2P_2_DISPATCH_BRIEF.md) | 3 | **Retire on read.** A closed round's dispatch brief is a record; its P2P-3 references are forward-looking prose from before this round existed and are superseded by §4's register |
| [`DAEMON_RELAY_PRIVACY.md`](DAEMON_RELAY_PRIVACY.md) | 2 | relay-side consumers of p2p implementation. **Land in slices**, sequencing TBD in-round |
| [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) | 2 | the `LV-` row and the P2P family row. **Updated by this opening** (§1.1) |
| [`FEE_LADDER_DERIVATION.md`](FEE_LADDER_DERIVATION.md) | 1 | a single forward reference. **Land in a slice**; verify at slice time whether it still applies |
| [`FOLLOWUPS.md`](../FOLLOWUPS.md) | 1 | the LV-2/LV-3 row at `:727`, a bare title. **Owned by this round** as of the opening |

**Not every citation is a gate.** Three of the eight documents are records of
closed rounds, and a forward reference inside a record is not a queue entry.
The sweep distinguishes them rather than treating a `grep` count as a work
list — *a sweep cannot tell a quotation from a reference.*

---

## 4. The slice register

Rule 26, not a plan. A register records **what a slice is and what it flips**;
it does not schedule slices that have not been designed.

| Slice | What | §0.5 rows it flips | Status |
| --- | --- | --- | --- |
| **1** | **LV-3 — the connection as a typed, owned Rust object.** Brief: [`LV3_CONNECTION_OBJECT.md`](LV3_CONNECTION_OBJECT.md) | unblocks B1, B2, B7's score, E1/E2, PWC-E5. **No longer flips I8** — see slice 2 | **DESIGN ROUND CLOSED 2026-09-21** (Rounds 1–3 answered) — no code. Identity amended by §2.9.8: the endpoint's provenance plus per-peer state, **not** I8's category |
| **2** | **I8's remedy — DELETE the per-host inbound cap, and give `--in-peers` a measured default.** Ruled [`LV3_CONNECTION_OBJECT.md`](LV3_CONNECTION_OBJECT.md) §2.9.4. **Two halves, one deletion and one measurement** — see §7.1 for the ripples, which are larger than the diff | **I8** OPEN → ruled-and-closed; **I7** PARTIAL → the row's mechanism is deleted, not completed | **DISPATCHABLE** — design complete, no blocker. Not yet cut |
| — | *candidates below are **not dispatched**; they are named so the register is not mistaken for a complete queue* | | |
| *(cand.)* | **E2 tier-1 self-classification.** A node with a published endpoint and zero inbound in `T` classifies itself unreachable, stops advertising, and tells the operator. **No wire change, no dial-back, no amplification surface** — and it builds the rule-82 surface PWD-I7 records as absent | E1/E2 (partial) | not dispatched |
| *(cand.)* | **The failure-class carry at `record_addr_failed`** — the class is known one line above the call and discarded crossing it | the failure-window FOLLOWUPS row | not dispatched; **blocked on a number that is not owed** (rule 76) |
| *(cand.)* | **Cluster T** — see §5, the sequencing question | T1–T4, T6, T8 | not dispatched |
| *(cand.)* | **The `pruning_seed` C++ RECEIVER** — `should_drop_connection` and the candidate filter at `net_node.inl:1832` both act on a claimed field ([`LV3_CONNECTION_OBJECT.md`](LV3_CONNECTION_OBJECT.md) §2.8.7) | none — it is `PDM-Q7`'s empty cell, not a `PWD-` row | not dispatched; **three arms in §7.2**, and the choice is steering's |
| *(cand.)* | **B1 / B2 / B12** — token bucket, per-peer accounting, fluff batch bound | B1, B2, B12 | not dispatched; B1/B2 depend on slice 1's noun |

---

## 5. The open sequencing question: does cluster T land through LV-3's seam or beside it?

**To be answered IN the round, not discovered during it.**

The facts, verified: **cluster T does not replace Levin framing.** T5 (8-byte
prefix) and T7 (compression) are both recorded **NO BUILD REQUIRED — "rules
the status quo"** in §0.5. Noise wraps Levin; it does not displace it. So
**LV-1 and LV-2 are not sunk cost**, and the question is not "which survives"
but "which seam does T's remaining work cross".

T and LV-3 touch the same seam. Answering this late means discovering a
conflict during implementation; answering it in-round means the slice
boundaries are drawn once.

---

## 5.5 Sequencing ruled 2026-09-21 — land, then design

**Ruled (Rick):** land PR #812 first, then run a **real design round (or
rounds)** and a comprehensive fix. **Changing the compiled default is refused
as a remedy — it hides the problem rather than fixing it**, and the estate's
`8` is recorded as a time-boxed deviation rather than a precedent (PWD-I7).

**Threat posture, ruled on the facts rather than assumed:** only **testnet** is
running, and the only things on it are the Foundation estate and the test rigs.
**So this is not an urgent privacy or security threat** — there is no
third-party operator whose peer diversity is being cut, and no value at risk.
That is a statement about *today's deployment*, not about the defect: the
partition is real, network-wide, and its masking **decays as the network
grows** (PWD-I7). **The urgency is schedule pressure, not incident pressure**,
and the two should not be confused in either direction — nobody should rush the
eclipse analysis, and nobody should conclude from a working testnet that the
round can be dropped.

## 6. What this round does not decide

Owed to the maintainer, and **not** to be decided inside a slice:

- Whether the PWD-I7 falsifier runs before the round proceeds.
- The refusal-class failure window value — a **new number needing its own
  derivation** (rule 76), not a reuse of either existing constant.
- Whether visible refusal is wanted. Argued against in PWD-I7: a reason code
  before the drop is a co-residency oracle over the whole NAT, plus a
  pre-handshake wire addition.
- Tor-by-default posture, and its dependency on
  `cryptonote_protocol_handler.inl:452` — **Tor cannot sync a chain today**, so
  that posture is a change to that line, not to a default.
- Q12-R1 (compiling the testnet seed onions into `get_seed_nodes`), held by
  Q12-R2 for experimental control, precondition in
  [`Q12_D6A_PEER_DISCOVERY_RUN.md`](Q12_D6A_PEER_DISCOVERY_RUN.md) §9.3.
- ~~**No cap number. No `--in-peers` number.** Both dissolved into design
  questions by PWD-I7's re-diagnosis and PWD-I8's routing.~~ **AMENDED
  2026-09-21 — neither is owed to the maintainer any more, and for two
  different reasons:** the **cap number is dissolved by deletion** (§2.9.4
  arm 1 — there is no constant left to pick), and the **`--in-peers` number is
  a MEASUREMENT at the rule-76 floor**, not a ruling (§2.9.4 arm 2). Recorded
  as an amendment rather than a rewrite because "owed to the maintainer" was
  the live status for the whole of Rounds 1–2.

---

## 7. The alpha.9 gate — re-ratification, not a schedule

**Added 2026-09-21 on steering's note:** alpha.9 cuts **as soon as the redb
conversion (`DRS-E*`) is done**, and p2p work "should be a part of it."

**Why this section is a re-ratification and not a plan.** The alpha.9 deferral
list in [`SHEKYL_P2P_PROTOCOL.md`](SHEKYL_P2P_PROTOCOL.md):117 — **B9's number,
E1, E2** — was ruled when **alpha.9 had no date**. "Defer to alpha.9" then meant
*later*; it now means *at a gate with a known trigger*. **A deferral ruled
against an undated release is not automatically a commitment against a dated
one**, so each candidate is re-stated with its readiness and its blocker rather
than inherited. New anchors in this section verified at `f9e000f76`.

### 7.1 The finding that reorders this: `DRS-E*` removes the EMITTER, not the RECEIVER

**This is the load-bearing correction, and it is easy to get backwards.**

`PDM-Q7` (RULED 2026-09-18) retires the `pruning_seed` wire slot in two halves:
a Rust daemon **sends `0`**, and **ignores** any non-zero it receives. The C++
engine "dies at `DRS-E*`". It is tempting to read that as *the cutover closes
this*, and to treat alpha.9 as self-cleaning.

**It does not, because `DRS-E*` is the STORE.**
[`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) contains **zero** references to
`net_node` or `src/p2p/`, and the `LV-` index row says so from the other
direction: *"the C++ path (`contrib/epee`, `levin_notify.cpp`, `src/p2p/`) stays
live"* until LV-3. So at the cutover:

| Half | Lives in | Survives `DRS-E*`? |
| --- | --- | --- |
| **The emitter** — `get_blockchain_pruning_seed()` feeding the handshake | the **store** | **No.** Dies with LMDB. We stop claiming a stripe |
| **The receiver** — `should_drop_connection`, the candidate filter at `net_node.inl:1832` | **p2p** | **YES.** Untouched by the store swap |

**Consequence:** after alpha.9 as currently gated, a Shekyl node **sends `0` and
still honours any non-zero it receives** — preferring the claimant at dial
([`net_node.inl:1834`](../../src/p2p/net_node.inl#L1834)) and protecting it from
eviction
([`cryptonote_protocol_handler.inl:1986`](../../src/cryptonote_protocol/cryptonote_protocol_handler.inl#L1986)).

**And Q7's ignore-half has no landing site at that gate**, because "a Rust
daemon ignores" presupposes a **Rust p2p receiver**, which `DRS-E*` does not
deliver — it delivers a Rust *store* behind C++ p2p. **This is a one-line
handover the pruning lane is owed**, since the sequencing looks self-closing
from inside `PDM-Q7` and is not.

### 7.2 Three arms for the receiver — the gate makes one cheap

1. **Delete the receiver branches in C++ before the cut** — the two live ones
   (`should_drop_connection`'s seed-`0` and stripe-match arms, and the candidate
   filter's `else if`); a third at `:1992` is gated on `--sync-pruned-blocks`,
   **already deleted under `PDM-Q5`**, so it goes with that ruling rather than
   this one. Smallest diff,
   and `PDM-Q-S0` does **not** govern it — S0 governs set-B discard and the
   engine row's *store* symbols, and neither `:1832` nor `should_drop_connection`
   is on that list. This is a rule-15/16 deletion question, not a sequencing one.
2. **Land LV-3's implementation before the cut, so the Rust connection object
   *is* the receiver.** This is the arm that discharges Q7's ignore-half as
   specified rather than by proxy — **the only arm that does** — and it is the
   expensive one.
3. **Cut with it, and date the exposure** in Q7's table so it is a known dated
   window rather than an empty cell.

**Not picked here.** Arm 1 is cheap and arm 2 is the one Q7 actually asked for;
which is right depends on §7.3's scope call, which is steering's.

### 7.3 The candidates, with readiness and blocker

| Candidate | Ready? | Blocker | What it flips |
| --- | --- | --- | --- |
| **Slice 2 — delete the per-host cap** | **YES** — ruled §2.9.4, three independent arms | none | I8 closed; I7's mechanism deleted |
| **`--in-peers` measured default** | **YES, mechanism-wise** — the ceiling exists and is checked; the default is the sentinel `-1` narrowed to `UINT32_MAX` | a **Pi 4 measurement** (rule 76 floor). Not a decision | creates §2.9.5's discharge trigger; no §0.5 row |
| **`pruning_seed` C++ receiver** | **YES** — §7.2 arm 1 is a two-branch deletion | none technical; it is a **scope call** | `PDM-Q7`'s empty cell |
| **B9's number** | **NO** | **PWD-I4**, deferred with parameter ownership unresolved. Unchanged by this round | B9 PARTIAL → done |
| **E1 — endpoint determination** | **DESIGN only** | no mechanism anywhere in `src/p2p/` or `shekyl-levin`; "largest of the nine by a distance". Rounds 1–2 produced the **claimed/observed split** and the §2.7.5 third-party-proposal candidate — **design, not mechanism** | E1 |
| **E2 — endpoint verification** | **DESIGN only** | with E1; **the amplifier warning stands** — *"rushing a dial-back mechanism into a release is how you get the ping-back-as-DoS-amplifier problem"* — and Round 2 **rejected** the reserve-capacity shortcut on mechanical grounds (§2.8.5) | E2 |
| **LV-3 implementation** | **DESIGN CLOSED** | reviewer bandwidth, and the object's identity only settled 2026-09-21 (§2.9.8) | unblocks six consumers; is §7.2 arm 2 |

### 7.4 The scope question, which is steering's

**"This should be a part of it" admits two readings, and they differ by a lot:**

- **Minimal** — slice 2's deletion, the `--in-peers` measurement, and §7.2
  arm 1. **All three are ready, none is blocked, and together they are a small
  diff with a large ripple** (§7.5). This removes a mechanism that defends
  nothing and gives a real ceiling a reachable value.
- **Full** — the above **plus** LV-3's implementation and E1/E2, which is the
  deferral list as originally written. This is the only reading that discharges
  `PDM-Q7`'s ignore-half as specified, and it is **much** larger: E1/E2 have no
  mechanism at all, and the amplifier warning that deferred them has not been
  answered by anything in Rounds 1–3.

**Recorded, not chosen.** The round's job was to make the two readings
separable and priced; picking between them is a release-scope decision.

### 7.5 The deletion's ripples — enumerated here, not discovered in the PR

Slice 2 is a small diff with a **larger** ripple than its size suggests:

- **[`SHEKYL_P2P_PROTOCOL.md`](SHEKYL_P2P_PROTOCOL.md) §0.5 I7** flips from
  PARTIAL, and *not* to IMPLEMENTED — the mechanism is **deleted**, which §0.5
  has no status for. **A status vocabulary that cannot express "the mechanism
  was removed as the fix" is itself a finding**; resolve it when the row flips.
- **I7's "the NUMBER is owed to the maintainer" dissolves.** There is no
  constant left to pick.
- **[`FOLLOWUPS.md`](../FOLLOWUPS.md) rows at `:756` and `:768`** both name
  **PWC-E11** as *the current inbound bound*. Both become false on deletion, and
  `:768`'s "anonymity zones have no inbound per-host cap at all" stops being an
  asymmetry to fix and becomes **the uniform state**.
- **A flag six production hosts pass — and the mechanism for retiring it
  already exists.** All six seeds carry `max-connections-per-ip=8` (verified
  2026-09-21). **Deleting the option would otherwise be a startup failure on
  every one of them**, and that is confirmed rather than assumed: an
  unregistered option in a config file raises `po::unknown_option`, which
  [`daemon/main.cpp:186-202`](../../src/daemon/main.cpp#L186) catches and exits
  `1` on. **But the same catch block first calls
  [`shekyl::cli::handle_removed_flag`](../../src/daemon/main.cpp#L191)** — a **retired-flag registry**
  (`REMOVED_FLAGS`, [`common/removed_flags.cpp:69`](../../src/common/removed_flags.cpp#L69),
  23 entries today, with a `TODO(v3.2)` sunset) that refuses a deleted flag **by
  name, with its reason**. So the ripple is **a registry row**, not a
  coordinated config change and not an invented deprecation window. **This is
  the rule-82 surface**, it is solved in this tree, and the only failure mode
  left is forgetting the row — which is why it is enumerated here rather than in
  the PR.
- **PR 812's surface becomes dead**: seven `node_server` tests, `HostInboundCap`
  / `InboundZone` in `rust/shekyl-peer-policy/src/host_inbound.rs`, and four
  `shekyl_host_inbound_*` FFI exports. **Deleting them is the correct outcome,
  not a regression** — PR 812 moved ownership into Rust so the mechanism could
  be reasoned about, and the reasoning concluded *delete*. Rule 15: the
  migration-shaped code goes with the thing it was migrating.
- **`--in-peers`' sentinel narrowing** (§2.9.4 arm 2) should be resolved in the
  same cut, since it is the identical defect one descriptor away and PR 812
  already built the Rust-side pattern for it.

---
