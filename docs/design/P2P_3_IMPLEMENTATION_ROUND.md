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

## 4. The slice register — RESTRUCTURED 2026-09-21

**Rule 26: a register records what a slice is and what it flips.** It does not
schedule slices that have not been designed. Every row carries **what it
inherits** and **a command that greens when it lands**, for the reason
[`LV3_CONNECTION_OBJECT.md`](LV3_CONNECTION_OBJECT.md) §6.1 records: this
round's own history is a nomination that decayed into intentions (§0).

### 4.1 WITHDRAWN: "LV-3 is slice 1"

**Ruled 2026-09-21 (steering): LV-3 is not a slice, it is nearly the whole
round, and it goes LAST.** Both halves of the original ordering were wrong, and
they were wrong for different reasons — recorded separately because only one of
them is a measurement error.

**Wrong boundary.** LV-3's scope was drawn **from a family name rather than from
the work**. `LV-` properly names the `levin_notify` / `net_node` seam — **the
socket layer and relay dispatch**. The **peerlist, admission policy, discovery
policy and handshake state machine are not Levin work at all**; they are P2P-3
slices in their own right. A "first slice" containing all of them is the round.

**Measured, because the size claim should not be asserted either.**
**Re-measured at `origin/dev` `fdf17b729`: 11,456 lines** — the stripe deletion
(PR #821) removed ~337 from the p2p and protocol-handler surface. The
itemisation below is the `f9e000f76` measurement it replaces, kept because the
*decomposition* is what the argument used and it did not change shape: `src/p2p/` 6,391
(`net_node.inl` 3,542 · `net_node.h` 797 · `net_peerlist.h` 550 ·
`net_node.cpp` 528 · `net_peerlist.cpp` 328 · `p2p_protocol_defs.h` 266 ·
`net_peerlist_boost_serialization.h` 234 · `net_node_common.h` 146),
`levin_notify.{h,cpp}` 2,189, `cryptonote_protocol_handler.{h,inl}` 3,213.
*(Steering's figure was 10,400. The two share no derivation, so this one is the
tree's and that one is theirs — not reconciled, because a composite figure that
disagrees with its own itemisation is the shape rule 94 §3 exists to catch.)*

**Wrong ordering, and this half is mine.** *"LV-3 must be slice 1"* rested on
§0's measurement — **85 lines of shipped C++ against 409 of Rust**, with the
residue being a `foreach_connection` walk that cannot move without a connection
object. **The measurement was real. Its scope was not**: it measured
**admission**, where `foreach_connection` is the blocker, and **one decision's
ceiling was generalised into the whole round's ordering.**

**Three independent facts invert it, and all three are checkable:**

1. **The peerlist has no such ceiling.** `net_peerlist.{h,cpp}` is **874 lines**
   of data structure (`f9e000f76`: 878; PR #821 removed the seed field).
   **Re-verified at `origin/dev` `fdf17b729`, not inherited:** it includes **no**
   socket header, **no** `net_node.h`, and **no** connection context, and
   `grep -cE 'foreach_connection|m_net_server|connection_context|socket|boost::asio|drop_connection|p2p_connection'`
   over both files returns **0**. The dependency runs the *other* way —
   `net_node` includes `net_peerlist`. It is independently compilable,
   differentially testable, and **gray/white already lives there**. **Nothing
   about it waits on the noun.**
2. **Round 3's deletion dissolves admission's dependency too.** `is_host_limit`
   ([`net_node.inl:232`](../../src/p2p/net_node.inl#L232)) does exactly two
   things: an atomic counter comparison, and `has_too_many_connections`
   ([`:241`](../../src/p2p/net_node.inl#L241)) — the per-host **walk**. §2.9.4
   arm 1 deletes the walk, leaving a comparison against
   `std::atomic<unsigned int> m_current_number_of_in_peers`
   ([`net_node.h:404`](../../src/p2p/net_node.h#L404)). **The 85/409 ceiling was
   a property of the per-host cap, not of admission** — so this round's own
   ruling removes the reason LV-3 looked like it had to be first.
3. **The eviction site's walk is GONE — this one has landed.**
   `should_drop_connection` was wholly stripe logic, and PR #821 removed it with
   its unconditional `for_each_connection` tally. **Verified at `fdf17b729`:
   `git grep -c should_drop_connection origin/dev -- src/` returns 0.** So **no
   policy decision walks connections** — stated as a present fact rather than a
   consequence of a pending cut, which is what it was on 2026-09-21.

**Better shape, and worth saying plainly:** the four policy slices establish the
patterns and the differential test harness first, and **the big-bang lands last,
where the cost and the irreversibility already are.**

### 4.2 The register

| # | Slice | Inherits | Flips | Greens when it lands |
| --- | --- | --- | --- | --- |
| **1** | **Peerlist** — `net_peerlist.{h,cpp}`, 878 lines, gray/white and the promotion boundary. Differentially testable against the C++ with no daemon | **the alpha.9 cut's ignore (§7.2 arm 1)**, because the peerlist has **three** received-seed sites of its own: the carry-forward guards at [`net_peerlist.h:367`](../../src/p2p/net_peerlist.h#L367) and [`:414`](../../src/p2p/net_peerlist.h#L414) (*"guard against older nodes not passing pruning info around"*), **and the persisted-peerlist load path, which never sanitizes — `sanitize` appears nowhere in `net_peerlist.cpp`.** `PDM-Q7`'s emitter-half clears none of them: they read what ARRIVES | I2's remaining acceptance rules; the white-list writer invariant | `rg -n 'pruning_seed' src/p2p/net_peerlist.*` returns **nothing** at open; a differential harness runs both implementations over one input sequence and agrees on gray/white membership |
| **2** | **Admission policy** — the ceiling, and nothing else after §2.9.4 | slice 1, and a **measured `--in-peers`** (§7.3) rather than `UINT32_MAX` | **I7** (mechanism deleted), **I8** (closed) | `rg -n 'has_too_many_connections' src/` returns nothing; `is_host_limit` is a counter comparison |
| **3** | **Discovery policy** — seed handling, the dial-candidate selection, `m_used_stripe_peers`' removal | slices 1–2, and the candidate filter's `else if` already gone (§7.2) | B9's mechanism half; PWC-E9's re-derivation | `rg -n 'm_used_stripe_peers\|next_needed_pruning_stripe' src/p2p/` returns nothing |
| **4** | **Handshake state machine** — the phases, and PWD-B1/B2's per-peer state, which have no landed mechanism and so land here first rather than migrating | slices 1–3 | **B1, B2**; B7's remainder and PWC-E5 | PWD-B1's four unguarded invoke handlers are guarded |
| **5** | **LV-3 — sockets and relay dispatch.** The `levin_notify` / `net_node` seam: 2,189 lines of dispatch plus `net_node.inl`'s connection registry. **The connection object lives here** | slices 1–4 — **the patterns and the harness**. Plus the walk-fed counter at [`net_node.inl:1112`](../../src/p2p/net_node.inl#L1112): a once-per-second `foreach_connection` recount feeding admission's atomic, which **a Rust connection registry should own its own count of** rather than inherit | the failure-window row; LV-3's own `IMPLEMENTATION_INDEX` cell | the C++ connection registry has no remaining policy caller; `:1112`'s recount thread is gone |
| *(open)* | **The fate of `cryptonote_protocol_handler`** — 3,213 lines, and **not yet a slice** | — | — | named so its absence is visible, per §0's defect |

**E1/E2 are deliberately not rows.** E1 tier-1's diagnostic half lands in
alpha.9 (§7.4); E2(b) is blocked on the amplifier analysis; E1's remainder and
E2(a) are cluster E's own work and are **consumers** of slice 5's provenance
type. *A register that absorbs its consumers is how a slice becomes a
subsystem* — the mistake §2.9.4 just finished unwinding for I8.

**What the restructure does to the `pruning_seed` sequencing.** LV-3 is now
**further away** than it looked — it is slice 5 of five, not slice 1 — while
**slices 1–4 can start much sooner** because none of them waits on the noun.
That strengthens the alpha.9 receiver deletion rather than weakening it: the
field must go in C++, because the Rust receiver that would ignore it is now four
slices out.

### 4.3 ~~The stripe scaffolding census~~ — SUPERSEDED 2026-09-22, the scaffolding is gone

**This section routed a ~311-site stripe removal across slices 1, 3, 5 and the
handler row. PR #821 removed all of it before any slice opened**, so the
routing is void and **no slice inherits a stripe-removal obligation.**

**Re-measured at `origin/dev` `fdf17b729`:** 4 sites, all comments. The
`m_used_stripe_peers` pure-virtual interface, `get_next_needed_pruning_stripe`,
`notify_new_stripe`, `should_drop_connection`, `block_queue`'s two extra
`reserve_span` parameters, the peerlist seed field and its unsanitized load
path — **all deleted**, with a store bump (v9 / boost v6) carrying the peerlist
format change.

**What this changes in the register (§4.2), recorded rather than silently
edited:**

| Row | Was | Now |
| --- | --- | --- |
| **1 — peerlist** | inherits the alpha.9 ignore; three received-seed sites to clear | **inheritance SATISFIED.** `git grep -n pruning_seed origin/dev -- src/p2p/net_peerlist.*` returns **one comment**. Slice 1 is unblocked on this axis |
| **3 — discovery** | inherits `m_used_stripe_peers` and the candidate filter's remainder | **nothing to inherit.** The stripe machinery it was to remove does not exist |
| **5 — LV-3** | inherits the connection-context field and `block_queue`'s signatures | **field and signatures already gone.** The `:1111` recount inheritance stands (below) |
| ***(open)*** — handler | inherits `should_drop_connection`, `notify_new_stripe`, the span block | **all three gone.** The row survives for the handler's *fate*, which was never about stripes |

**One inheritance is unaffected and re-anchored:** the admission counter is
still refreshed by a `foreach_connection` recount on a one-second sleep —
[`net_node.inl:1111`](../../src/p2p/net_node.inl#L1111) at `fdf17b729`
(*was `:1112`*). It remains slice 5's, and remains a rule-76 measurement input
for `--in-peers`.

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

1. ~~**IGNORE the claimed seed at every entry point.**~~ **DELIVERED
   2026-09-22 by PR #821 (`feat/pruning-seed-wire-deletion`), merged at
   `fdf17b729`** — and by the **stronger** act: the lane *removed* rather than
   ignored. This arm is a record now, not a plan.

   **Measured at `origin/dev` `fdf17b729`, not inherited:** the census that read
   **311 sites across 31 files** at `f9e000f76` now reads **4**, and all four
   are **comments recording the deletion**
   (`cryptonote_protocol_defs.h:179`, `net_peerlist.cpp:84`,
   `net_peerlist_boost_serialization.h:227`, `p2p_protocol_defs.h:56`). The
   Rust half went with it, and `PDM-Q7`'s two halves are both discharged: the
   wire field is gone from `CORE_SYNC_DATA` and `peerlist_entry`, and
   **the ignore lives in the codec** — `deleted_pruning_seed_never_written_still_readable`
   (`rust/shekyl-levin/tests/payload_kats.rs:148`) asserts a stale non-zero
   field is read and discarded. **That is the ignore-half, built and tested, at
   the layer this round argued it had to live at.**

   *(Anchors in the superseded revisions above — `should_drop_connection`,
   `:2112`, `:2116`, `:2199`, the entry-point table — are at `f9e000f76` and do
   not resolve in the current tree; the code is gone. The anchors in the
   paragraph below are at `fdf17b729` and do.)*

   **The analysis was independently confirmed by the landed diff, which is the
   part worth keeping.** This round predicted, by constant-folding the block at
   a seed of `0`, that a correct deletion must collapse
   `stripe_proceed_main → next_height_proceed`, `stripe_proceed_secondary →`
   constant `true` and therefore out, `proceed → queue_proceed`, and the
   `:2116`/`:2199` branches to unreachable. **The landed code is exactly that
   fold**, line for line: `next_height_proceed` at
   [`:1954`](../../src/cryptonote_protocol/cryptonote_protocol_handler.inl#L1954),
   `queue_proceed = (next_needed_height == bc_height) ? next_height_proceed : queue_proceed_init`
   at [`:1957`](../../src/cryptonote_protocol/cryptonote_protocol_handler.inl#L1957),
   `if (next_height_proceed && should_download_next_span(...))` at
   [`:1969`](../../src/cryptonote_protocol/cryptonote_protocol_handler.inl#L1969),
   `if (queue_proceed)` at
   [`:1977`](../../src/cryptonote_protocol/cryptonote_protocol_handler.inl#L1977).
   **Two independent derivations of the same fold agreeing is a semantic
   cross-check**, not a coincidence — it says the deletion was sound and not
   merely complete.

   **The transferable lesson survives the arm it was written for, and it is
   why this text is kept rather than cut:** *when a mechanism is degenerate on
   the honest path rather than absent from it, every intermediate deletion
   point is a half-deletion.* This arm was widened three times — two branches,
   then the function and its call sites, then every entry point where the data
   is stored — and **each widening was found by someone checking rather than by
   the previous scope failing.** The scope question for a degenerate mechanism
   is never *"which function?"* but *"where does the data stop entering?"*
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

### 7.4 SCOPE RULED 2026-09-21 (steering) — take four, respec one, defer two

**TAKE NOW — the alpha.9 cut:**

| # | Item | Why it qualifies |
| --- | --- | --- |
| 1 | **Delete the per-host inbound cap** | ruled §2.9.4, three independent arms, no blocker |
| 2 | **`--in-peers` measured default** | the ceiling exists and is checked; a **measurement** at the rule-76 floor, not a ruling. **One input the measurement must accept:** the counter it compares against is refreshed by a `foreach_connection` recount on a **one-second sleep** ([`net_node.inl:1112`](../../src/p2p/net_node.inl#L1112)), so the ceiling is enforced against a value up to a second stale. **That staleness is inert today and becomes load-bearing the moment the ceiling is reachable** — the Pi 4 run must price a second's worth of accepts at the floor, or the measured value is off by exactly that burst |
| 3 | ~~**The `pruning_seed` receiver**~~ **DELIVERED 2026-09-22, PR #821** — removed outright rather than ignored, both halves of `PDM-Q7` discharged | re-verified at `fdf17b729`: 4 sites remain, all comments |
| 4 | **E1 tier-1, diagnostic half** | *"no wire, no amplifier and no ruling owed,"* and it **closes the operator-diagnostic gap that started the lane** — the merit that earns it a place beside three ready items |

**Steering's framing, recorded because it is the reason item 4 is in and not
merely cheap:** *"Three ready plus one with no wire, no amplifier and no ruling
owed. Tier-1 still earns its place on merit."* **A cheap item that closes
nothing does not qualify**, which is the test items 1–3 also pass.

**RESPEC, rather than expand scope to satisfy:** `PDM-Q7`'s ignore-half
presupposes a receiver alpha.9 does not deliver, so **Q7 is re-specified against
the receiver that will exist** — §7.6. *That is the ruling that keeps item 3
from pulling LV-3's implementation into the cut behind it*, which is how a
scope grows by obligation rather than by decision.

**DEFER:**

- **LV-3's implementation** — the design round **closes with a slice register**
  as its deliverable ([`LV3_CONNECTION_OBJECT.md`](LV3_CONNECTION_OBJECT.md)
  §6), and **the first slice lands after the freeze.** The register is required
  to be *checkable* rather than a plan, for the reason §6.1 records: a round
  that closes on intentions is indistinguishable from a round that never
  closed, **which is this round's own history** (§0).
- **E2(b)** — stays blocked on the amplifier analysis. Unchanged, and Round 2's
  §2.8.5 rejection does not substitute for it.

**And the aside that shaped the deferral, kept because it is an argument and not
an aside:** if `pruning_seed` is gone before LV-3 starts, **that is a statement
about LV-3's distance**, not about `pruning_seed`. A far-off round owes a
deliverable that decays visibly. §6.3 gives the register three falsifiers that
are commands rather than judgements, and L1/L2's rows name what they **inherit
from this cut** — so if the cut does not land, the register goes red instead of
going quiet.

### 7.4.1 The gate is a named PR, not a policy — queue freeze WITHDRAWN

**Withdrawn 2026-09-21 (steering).** The standing *"confirm the PR-queue freeze
before opening anything"* constraint is withdrawn, and the honest disposition is
that **there is nothing to delete from a document.**

**Searched before saying so, because this is a negative claim.**
`grep -rniE "queue freeze|pr[- ]queue|freeze the (pr|queue)|open no (new )?pr|before opening (anything|a pr)" docs/`
returns **three hits, none of them the constraint** — a decision-log phrase
about *"this PR queue"*, a CHANGELOG entry, and a completed plan's *"Precursor
PR queued"*. **It was never in
[`P2P_2_DISPATCH_BRIEF.md`](P2P_2_DISPATCH_BRIEF.md), or anywhere else under
`docs/`.**

**That absence is the finding, not a tidy result.** The constraint existed only
in the relay stream, and **a constraint that is never written down cannot be
checked against anything** — which is precisely how it survived being cited
between two parties without either verifying it. Recorded here rather than
silently dropped, because the next such constraint should be written where a
`grep` can find it.

**What replaces it, and why it behaves differently:**

> **PR #818 — `DRS-E1 S-CURVE: typed curve-tree reads` — is the gate.** It is
> the redb lane the alpha.9 cut inherits from, and **it resolves by a merge
> rather than by someone deciding.** Resolution condition:
> `gh pr view 818 --json merged` reporting `true`.
>
> **RESOLVED 2026-09-22** — #818 merged at `e838bf801`, on `dev` at
> `fdf17b729`. **The gate did what a policy could not: it went green on its
> own, by an event, without anybody being asked.** That is the whole argument
> for naming a PR instead of asserting a freeze, and it took one day to
> demonstrate.

**A dependency on a named PR is checkable and expires; a policy is neither.**
The queue's *state* is a fact to read when it matters
(`gh pr list --state open`) — at `f9e000f76` it held #818, #819 and #820 — not
a precondition to assert.

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

---

## 7.6 ~~PROPOSED AMENDMENT to `PDM-Q7`~~ — OVERTAKEN 2026-09-22, kept as the record

**The pruning lane did not need the amendment: it deleted the receiver
outright** (PR #821, `fdf17b729`), updated `PDM-Q7`'s own rows, and landed the
ignore in the Rust codec as a KAT. **So the landing-site problem this section
existed to solve does not arise**, and the proposal below was never put.

**What it got right, and why the record is worth keeping:** that Q7's
ignore-half presupposed a Rust p2p receiver `DRS-E*` does not deliver (§7.1);
that **ignore and remove are separate acts** in Q7's own text; and that the
receiver's disposition was the empty cell in Q7's table. **The lane's answer
was the third option this section did not offer — delete the receiver in C++
now** — which is better than either arm it proposed, and available because
`PDM-Q-S0` never governed these sites (the note below, which stands).

**Also overtaken:** the "third note" below, warning that the peerlist carried
received-seed reads the emitter-half would not clear. **It did not need to be
carried — the same PR removed them**, and the peerlist is clean at `fdf17b729`.

**Superseded text follows, unedited. Its `file:line` anchors are at
`f9e000f76` and DO NOT resolve in the current tree** — most of the code they
name was deleted by PR #821, and where the file survives the line is now
unrelated. Kept as the record of what was read.

### 7.6.1 (superseded) PROPOSED AMENDMENT to `PDM-Q7` — for the pruning lane's ratification, not applied here

**Ruled 2026-09-21 (steering): respec Q7 rather than expand scope to satisfy
it.** This section is the proposed text. **It is deliberately not written into
[`ARCHIVAL_PRUNED_DAEMON_MODE.md`](ARCHIVAL_PRUNED_DAEMON_MODE.md)** — `PDM-Q7`
is the pruning lane's ruling, a `PWD-` round does not amend a `PDM-Q` one, and
an amendment applied by the lane that wants it is not a ratification.

### What is wrong with the row as written

`PDM-Q7`'s **P2P wire** row retires the slot in two halves: a Rust daemon
**sends `0`**, and **ignores** any non-zero it receives, *"the ignore becomes a
drop reason only after the C++ emitter is deleted."* The sequencing is sound and
**the landing site is not**: *"a Rust daemon ignores"* presupposes a **Rust p2p
receiver**, and `DRS-E*` delivers a Rust **store** behind **C++ p2p** (§7.1).
**So at the cutover the send-half lands and the ignore-half has nowhere to go.**

### The observation that makes the respec cheap rather than new work

**A receiver-side ignore already exists in the tree, as the zero path.** At
[`net_node.inl:1832`](../../src/p2p/net_node.inl#L1832) the first branch is
`next_needed_pruning_stripe == 0 || peer.pruning_seed == 0` → `push_back`: **a
zero seed already means *no preference*.** The non-zero handling is the
`else if` beneath it, and the matching retention in `should_drop_connection`.

**So deleting the non-zero branches does not build an ignore — it leaves the
ignore as the only remaining path.** That is the same semantics Q7 specified,
reached by subtraction in C++ rather than by construction in Rust.

### Proposed replacement for the P2P-wire row's disposition

> **Retired, two halves, each at the substrate that exists when it lands:**
> a daemon **sends `0`** — the C++ "unpruned" sentinel — so legacy peers read it
> correctly through the transition; and a daemon **ignores** any non-zero it
> receives. **The ignore lands in C++ at the alpha.9 cut, by refusing the input
> at all four entry points** — handshake ingest, `sanitize_peerlist`, the
> persisted-peerlist load, and the candidate filter's `else if` — **not by
> removing what reads it.** Everything downstream is degenerate at a seed of
> `0` and folds to the honest path at runtime, so the ignore is complete
> without touching the stripe scaffolding (§4.3 routes that removal across
> slices 1, 3, 5 and the handler row). The well-formedness check goes with it: a
> validity test on a discarded field is a gratuitous disconnect keyed on a
> claim. **Ignore and remove are separate in this ruling's own text**, and an
> earlier revision of this amendment conflated them. No wait for a Rust p2p
> receiver, which `DRS-E*` does not deliver. The Rust receiver's ignore then
> lands with **LV-3** and is **redundant on arrival**, which is the correct
> outcome for a retirement rather than a regression. The ignore becomes a
> *drop reason* only after the emitter is gone. No framing change.

**Two notes for the lane, both narrowing rather than widening the amendment:**

1. **A third branch at
   [`:1992`](../../src/cryptonote_protocol/cryptonote_protocol_handler.inl#L1992)
   also reads the seed but is gated on `m_sync_pruned_blocks`**, whose
   descriptor supplies no default
   ([`cryptonote_core.cpp:127`](../../src/cryptonote_core/cryptonote_core.cpp#L127)).
   It is dead unless `--sync-pruned-blocks` is passed, and **that flag is
   already deleted under `PDM-Q5`'s rejection** — so it goes with Q5, not with
   this amendment.
2. **`PDM-Q-S0` does not govern this.** S0 forbids a C++ landing for **set-B
   discard** and the engine row's **store** symbols; neither `:1832` nor
   `should_drop_connection` is on that list. This is a rule-15/16 deletion of a
   claimed read, so **no S0 reopening criterion has to be invoked** — which is
   what makes the respec available without a steering exception.

**A third note, widened on census:** the peerlist carries **three** received-seed
sites of its own — the two carry-forward guards below, **and a persisted-peerlist
load path that never sanitizes** (`sanitize` appears nowhere in
`net_peerlist.cpp`), so a stored peerlist carries its seeds straight into the
gray list. The guards are at
[`net_peerlist.h:367`](../../src/p2p/net_peerlist.h#L367) and
[`:414`](../../src/p2p/net_peerlist.h#L414) — the carry-forward guards *"against
older nodes not passing pruning info around."* **Q7's emitter-half does not
clear them**, because they read what arrives rather than what we send. They are
**not** part of this amendment (they are slice 1's inheritance, §4.2), but the
lane should know the field has a reader outside the two files Q7's row names.

### What the lane is owed alongside it

The **fleet answer**, already delivered: `get_blockchain_pruning_seed()` is `0`
on all six seeds, the `pruning_seed` property is absent from all ten LMDBs, and
no host passes `--prune-blockchain`
([`LV3_CONNECTION_OBJECT.md`](LV3_CONNECTION_OBJECT.md) §2.8.8). **The
random-stripe path is not live in production** — so the emitter half is already
satisfied in fact, and the amendment above is about the half that is not.

**Falsifier for this amendment (rule 21):** it is wrong, and Q7's original
sequencing is right, if **`DRS-E*`'s scope is shown to include `src/p2p/`** —
in which case a Rust receiver *does* arrive at the cutover and the ignore-half
has its specified landing site after all. Check:
`rg -n 'net_node|src/p2p' docs/design/DAEMON_REDB_STORE.md` returning a scope
row. **At `f9e000f76` it returns nothing**, which is the evidence this
amendment rests on.
