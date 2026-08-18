# COMPLETETREE_ACTIVATION.md

**Status:** Design closed (R0–R7, 2026-08-17). **Round complete — all code
slices merged**: slice 1 (PR #479 @ `4828d8dc`), slice 2 (#483 @ `f6aee5f3`),
slice 3 (#489 @ `84908135`), slice 4 Tasks 0–2 (#492 @ `3b108fb9`), slice 4b
Tasks 3–4 (#495 @ `c92f10ed`). This document is the round record; slice 5
lands it.
**Verified against:** `shekyl-core` `dev` @ `c92f10ed` (all claims anchored at
file:line against that tree unless a line explicitly dates itself earlier).
**Decision authority:** Rick. Rulings recorded inline with dates.
**Round record:** R0 (opening findings/decisions), R1 (source verification of
D-3 constraints), R2 (Q-1 closure, F-2 disposition, scope correction,
slicing), R3 (slice-1 review and merge; agent-synthesis rulings Q-3/Q-4/Q-5;
F-3 auto-resume gap and its slice-4 amendment), R4 (slice-2 review and merge;
RR-1/RR-2 absorbed; slice-3 brief rewritten), R5 (slice-3 review and merge;
AF-1/AF-2/AF-3 ruled; RR-3/RR-4 absorbed; **F-3 retracted**; slice-4 brief
rebuilt), R6 (#492 reviewed and merged; Task-3/Task-4 halts ruled with
verified shapes — AF-4/AF-5; execution order ruled: Tasks 3–4 as slice 4b,
then slice 5; rule-35 password-copy gap ruled a named follow-on cut
immediately after round close), R7 (#495 reviewed and merged — RR-5 absorbed;
slice 5 lands the record and sweeps the fossils).

---

## 1. Mission and scope

Activate the **CompleteTree serving posture**: as shards freeze, they are
added to the CompleteTree serve obligation and served. CompleteTree is the
posture for Foundation nodes and informed volunteers. It is:

- **Reachable through the CLI only** — by convention, not prohibition (ruled:
  D-2). Anyone may freely serve every shard; that is a welcome contribution.
  The gate exists solely so nobody arrives there **by mistake** or without a
  clear warning that this is **not a profitable staking configuration**.
- **Never the default.** The `first_stake` CompleteTree hardcode is deleted in
  this round.
- **Fully inside the penalty economy** (slash side live; ruled 2026-08-07,
  re-confirmed this round) and **fully outside the reward economy** (market
  exclusion by holdings shape, E-2).

**Explicitly out of scope (ruled, R2):** the shard assignment system for
market staking. This round's Market posture is a stub — a typed "no shards
available" refusal. Shard assignment is a named follow-on round (§10).

---

## 2. Verified current state

**Wire and consensus — already complete; this round touched neither**
(verified at `dev` @ `e0d9870` when the round opened; re-confirmed unchanged
at close):

- `Holdings::CompleteTree` exists; carries no shard list by wire rule
  (`BondPostError::CompleteTreeWithShardIds`); mapped at
  `bond_assembly.rs:461-466`.
- Market exclusion is a **shape rule**: `market_member_at_epoch` early-returns
  on the holdings-kind byte (E-2, `ARCHIVAL_CONSENSUS_STATE.md` §3.3).
  Identity is never read by the market gate
  (`FOUNDATION_GENESIS_IDENTITY_SET.md` §2 factored rule, RULING 2026-07-19).
- Slash side is live for CompleteTree — not exempt
  (`ARCHIVAL_CHALLENGE_MECHANISM.md` §6, closed 2026-08-07).
- A foundation record cannot `HoldingsUpdate` (`db_lmdb.cpp:5226`).
- Empty `ShardSetCompact` is **consensus-invalid** at JoinMarket
  (`bond_post.rs:516-518`; KATs `bond_post_tests.rs:44-51`,
  `rejects_floor_zero_via_empty_shards`). Floor scales per shard and is 0 for
  empty (`bond_floor.rs:28-37`) — deliberate zombie/floor-zero protection.
- CompleteTree bond floor = **one** `ARCHIVAL_BOND_FLOOR_ATOMIC`
  (`bond_floor.rs:29-31`): nominal bond, maximal obligation, by design.
- JoinMarket on an existing record is rejected (`RecordExists`,
  `bond_post.rs:540-541`).
- Challenge scheduler (`db_lmdb.cpp:6020-6120`): compact arm walks
  `held_shard_ids`; **CompleteTree arm walks the daemon's
  `archival_shard_segment` registry** — the chain's frozen universe at
  settlement time. Downstream of pair enumeration everything is uniform over
  `{P, shard}`. Growth is picked up automatically; no bond-time snapshot.
- Eligibility is as-of-fire-height (`db_lmdb.cpp:5270-5330`): CompleteTree ⇒
  held back to join.
- CompleteTree slash **demotes**: kind flips to compact, holdings cleared,
  atomically (`db_lmdb.cpp:5879-5884`); scheduler's CompleteTree arm breaks on
  first slashing shard.
- `holds_shard` returns true for **any** id under CompleteTree
  (`shekyl_types.h:1348-1358`) — safe only because the scheduler feeds
  registry-enumerated ids. Contract comment added in slice 1.

**Store:**

- Freeze is a **dense prefix cursor**: `maybe_freeze_segments` advances
  `META_NEXT_FREEZE_SEG` sequentially; the frozen set is always exactly
  `[0, k)`. Writers are exactly three: the freeze path, the truncate/rollback
  recompute, and the fresh-store insert-if-absent seed in `init_tables` (which
  can only establish the empty prefix, never move an established cursor). This
  fact drives the whole design: "the CompleteTree collection" is one growing
  `u64`, not a collection.
- `prune_frozen` has **no production caller** — the V3.0 client never prunes.
  The prune-disabled posture landed before the hazard exists (designed-in, not
  retrofit — same move as §9.1).

**The activation gap this round closed — exactly two named deferrals:**

- `EngineServeSetPinner::pin_serve_set` refused CompleteTree: "a shard-id
  serve-set cannot express" the whole corpus; whole-corpus pinning "would need
  a store enumeration that does not exist and an unbounded-growth policy."
  **Closed in slice 3** by the prefix arm.
- `start_serving_if_staker` carried the open question "should a host start at
  all for a CompleteTree persona". **Closed in slice 3** at the seam: it does,
  the construction site stays posture-blind, and the kind-aware decision lives
  with the pinner.

**Entry point (as the round opened):**

- `first_stake` hardcoded `HoldingsKind::CompleteTree` ("Genesis posture",
  `bond_orchestrator.rs:650-657`) — the named PR-4c deviation. Production
  callers: wallet-rpc `stake` and the regtest e2e `FixtureStake::FirstStake`,
  which drives the production entry exactly as the RPC does. **Deleted in
  slice 3** (D-3).
- No shard-assignment code exists anywhere in the tree (verified by search,
  R2; still true at close).

**Serving posture persistence and resume (verified, R3):**

- The **persisted bond record is the reboot-surviving posture marker**:
  `persist_bond_record` writes it durably at the W2 point. The record's
  holdings kind IS the posture; it changes only through consensus lifecycle
  (Unbond, slash-demotion) — never through a local setting. No pref exists or
  is wanted: a pref would be a second, locally-editable home for a fact the
  chain owns (the superseded serve-time pref's flaw).
- **F-3 — RETRACTED (R5).** The R3 finding claimed `start_serving_if_staker`
  had zero production callers; the claim was false, produced by a caller
  search mis-scoped to `shekyl-engine-core` when the wiring lives in
  `shekyl-wallet-rpc/src/lifecycle.rs` and pre-dates this round. Verified
  reality: **three call sites with deliberate, distinct semantics** — the open
  path (`lifecycle.rs:674`) is **fail-closed** (a staker whose serving path
  will not configure does not open; the already-spawned P-scan is shut down
  *and awaited*; the error surfaces in the open result — SH-2b-2, citing §9.6
  item 4); the first-stake intent reopen (`lifecycle.rs:1006`) is
  **best-effort** (a serving failure must not block the stake in progress;
  re-arms at next open); the failed-close restore (`lifecycle.rs:1070`) is
  **best-effort** (the wallet is staying open; refusing would leave no close
  path; a fresh launch standoff is drawn). Auto-resume already existed and is
  better-reasoned than the retracted brief demanded. One named residual, not
  this round's scope: on the two best-effort paths, bonded-but-not-serving is
  visible only in logs until the next open (§10 item 6).

---

## 3. Ratified decisions (with dates)

**D-1 — Serve-set representation: structural prefix (Option B).** *(Ratified
2026-08-15.)* `ServeSet` gains a prefix arm (`CompleteTreePrefix`). The store
gains a **prune-disabled posture flag**. No per-segment pins for CompleteTree:
the bad state (a foundation node pruning bytes it owes) is made
unrepresentable rather than pinned-against (rule 12). Membership on the
request path is `id < frozen_count`. Rejected alternative (materialize
`(0..k)` as a Vec through the existing machinery): O(D) pin writes per refresh
forever over a monotone D, a pin table permanently restating a structural
fact, and a freeze→pin race window that Option B removes entirely.

**D-2 — CLI-only is a convention, not a prohibition.** *(Ratified
2026-08-15.)* No server-start flag, no structural RPC gate beyond the
acknowledgment field (D-4). The informed volunteer serving the whole tree is a
donated full-node-equivalent and strictly good for the network. The gate
targets only the accidental path and the uninformed path.

**D-3 — One entry, mandatory posture enum; hardcode deleted; Market is a
stub.** *(Ratified 2026-08-15; scope corrected same day.)*
`first_stake(slot, posture)` with `StakePosture::{Market,
FoundationCompleteTree}` — **mandatory**, no default (a defaulted parameter is
exactly the §9.1 footgun; a mandatory enum forces every caller to state
intent).

- `Market` → typed refusal `FirstStakeError::NoShardsAvailable`. When the
  shard-assignment round lands, this arm assigns and posts; the caller shape
  never changes (a posture, never a set, never a raw holdings kind).
- `FoundationCompleteTree` → posts CompleteTree, now opt-in.

The `bond_orchestrator.rs` hardcode is **deleted**, not re-anchored. After
this, no code path produces CompleteTree by default.

**This amends `ARCHIVAL_BOND_CONSTRUCTION.md` §9.1 items 1–2** (from
"separately-named constructor; standard entry takes no holdings argument" to
"one entry, mandatory posture enum"). The amendment preserves §9.1's property
— opt-in by intent, never reachable by accident, no select-all affordance —
and is recorded at the definition site with provenance to this round.

**D-4 — Warning is structural at the RPC boundary; CLI uses a typed phrase.**
*(Ratified 2026-08-15; text in §5.)*

1. **RPC:** foundation posture requires `acknowledge_non_earning_unbounded:
   true`. Absent or false → typed refusal whose error body **is** the full
   warning text. Any client, including third-party wrappers, must round-trip
   the acknowledgment — the warning will be seen or deliberately echoed, by
   construction.
2. **CLI:** `stake --complete-tree-foundation` prints the warning and requires
   typing the exact phrase `serve without reward` (typed phrase, not y/n —
   capital-locking, unbounded-obligation action). Then sends the
   acknowledgment.
3. **GUI:** nothing to implement; the acknowledgment field never exists in its
   `stake` call.

**D-5 — Refresh reads the cursor.** *(Ratified 2026-08-15.)* The refresh
loop's CompleteTree arm reads `next_freeze_seg()` and updates the witness.
Newly frozen segments are servable the moment they freeze — the bytes are
local by construction (the store ingests everything and never prunes under the
posture flag). One-clock staleness discipline carries over unchanged.

**Q-1 — Challenge uniformity: CLOSED, verified at source.** *(2026-08-15.)*
All archivers are challenged the same way over `{P, shard}`; no cut-outs. The
only kind-aware site is pair **enumeration** (structurally unavoidable — a
CompleteTree record has no list to walk), and its source is the chain's frozen
registry, i.e. reality. Everything downstream is uniform.

**Q-2 — Unbounded growth: disk is the operator's commitment; warn at set
points.** *(Ratified 2026-08-15.)* No cap. Disk-headroom observation with
fixed warning thresholds through `shekyl-operator-alarm`. Challenge-load-vs-D
concurrency stays with `ARCHIVAL_CHALLENGE_MECHANISM.md` §12 item 3 where it
lives — named coupling, not this round's scope.

**F-1 — Empty-compact consensus rule.** Stands as landed (correct). Its only
bearing on this round: the Market stub must refuse, not post empty.

**Q-3 — Posture visibility: approved.** *(Ruled 2026-08-15, R3; shape settled
by AF-4.)* Read-only, one field in `staking_info` and the CLI rendering. Rule
80; zero drift surface because it derives from the live serving host rather
than from any stored intent.

**Q-4 — Composed enumeration vs D-1: confirmed as landed, no amendment.**
*(Ruled 2026-08-15, R3.)* No production enumeration path, no pins for
CompleteTree; the enumeration exists only as the tested invariant (the KATs
bind cursor to table in both directions — the rollback direction, where a
stale summary would silently omit owed shards, is the one that earns its
keep). A production enumeration authority would be a second representation of
one fact, which is what D-1 rejected.

**Q-5 — No serve-time off-switch: confirmed deliberate; the exit is Unbond.**
*(Ruled 2026-08-15, R3; verified at source.)* `verify_unbond_bond_post`
(`bond_post.rs:571-586`) is holdings-kind-blind: a CompleteTree record unbonds
under the same rules as any P. **Serving follows the bond**: bonded means
serving; wanting out means ending the obligation itself via Unbond;
un-serving *while bonded* is the §9.6-item-4 silent-slash state and
deliberately has no switch (the superseded serve-time pref was that switch).
Named residue: the prune-disabled flag survives unbond (one-way), so a former
foundation node's store retains everything after a clean exit —
over-retention, conservative, harmless; the clear-path reopen criterion on the
setter owns it.

**AF-1 (slice-3 agent finding, ruled R5) — `PostureMismatch` omitted; the
brief's oracle did not exist.** Nothing posture-shaped is durable wallet-side
pre-connect, so the briefed resume-mismatch KAT was unimplementable without
new schema — out of scope, correctly left out. The residual is safe and
truthful: Foundation-mid-W2 resumed with `Market` refuses
`NoShardsAvailable` before any durable work. Relocated to §10 item 1 with the
implicit-oracle note.

**AF-2 (slice-3 agent finding, ruled R5) — the curve-tree halt fired on a
false premise; the edit is ratified.** The slice-3 brief simultaneously
required an actor message whose handler runs on `CurveTreeClient` and forbade
touching `shekyl-curve-tree` — but slice 1's scope was store-only and never
landed client forwards, and `ServingReader` is write-free by design, so the
declaration write was structurally unreachable. Brief error, owned. The edit
is two pure forwards on the `pin_serve_set` precedent, ratified as slice-1
completion plumbing. Process note: flagging loudly was correct given a
demonstrably false halt premise; a strict halt-and-report would also have been
correct; silent proceeding never is.

**AF-3 (slice-3 agent finding, ruled R5) — one actor handler invocation is the
atomicity unit, accepted.** The cursor moves only through the same actor's
ingest/truncate/rollback messages, kameo serializes, the store is exclusive —
nothing can advance the prefix between the declaration and the read, which is
the entire property a redb transaction would have bought. Documented at
`PinCompleteTreePrefix`, same basis as `AssembleTx`/`PinServeSet`.

**AF-4 (Task-3 halt, ruled R6) — the briefed witness derivation was
unreachable; the snapshot shape is ratified.** `ServingHandle` holds only
`cancel_token`/`join`/`alarms`; the host lives inside the spawned task, so
`pinned_serve_set()` cannot be read from the staking path — a brief error
(same family as AF-2), owned. Ratified shape: an **obligation snapshot on
`ServingHandle` beside `alarms`** — same pattern, same lifetime, read-only
consumer — refreshed at each pin and cleared on teardown. Semantics: the field
is the *serving* truth; absent renders "not serving". Pinned trap: deriving
posture from `prune_disabled` would report `foundation` forever after an
Unbond (the Q-5 residue misread as state).

**AF-5 (Task-4 halt, ruled R6) — both halves resolve; the dependency half is
withdrawn.** `rustix = { version = "1", features = ["fs"] }` is already a
**direct first-party dependency** at `shekyl-engine-prefs/Cargo.toml`;
`shekyl-engine-core` mirrors the same line (no new vetting;
`forbid(unsafe_code)` governs a crate's own code, the unsafe stays in rustix).
The read (`rustix::fs::statvfs`, `f_bavail × f_frsize`) lives with the
reporter on the serving side — not in the alarm crate, which stays a passive
board. The path threads as `ServingConfig.store_fs_path`, populated at
`start_serving_if_staker` — engine-core-only, no curve-tree touch.

**RR-1 (in-PR, #483) — Prefix retention is its own arm, not `PinsDropped`.**
The prefix arm must not impersonate the list arm: retention loss is
`Staleness::PostureLost` / `OperatorAlarm::ServeSetPostureLost`, never a
pin-table diagnosis for a store that has no pin rows. `ServeSet::obligation()`
is the one view of the two arms (a view, not a constructor — the
no-public-constructor rule holds). The **store is the authority for
`frozen_count`**: a report that overstates the cursor is
`PinError::FrozenCountExceedsCursor`; stale-low is accepted (the benign race
direction).

**RR-2 (in-PR, #483) — Declare-before-report; loss-path-only integrity scan;
the clear path does not exist in shipped code.** `LeafStore::set_prune_disabled`
returns `PostureDeclaration::{AlreadyDeclared, NewlyDeclared}`, decided inside
the write transaction. The prefix `ReportedSet` carries that answer —
**declare-before-report is the pinner contract** — and the witness runs the
corpus integrity scan only on the loss path, per D-1's refusal to pay O(D) per
tick. `acquire` scans unconditionally (declaration history cannot be trusted
across a restart) and **refuses over holes with `MembersAlreadyPruned`**;
`refreshed` records and never wedges. The tamper fixture compiles only under
the default-off `test-tamper` feature on the dev-dependency edge: the clear
path does not exist in a production build, which is the rule-21 one-way ruling
made structural.

**RR-3 (in-PR, #489) — the client forward does not police the actor.**
`CurveTreeClient::set_prune_disabled` is a public store write like
`pin_serve_set`: a holder of the client can call it directly and is then a
second writer. Production declaration rides `PinCompleteTreePrefix`; the doc
says that instead of claiming a guarantee the type does not provide.

**RR-4 (in-PR, #489) — the pinner is a dispatcher; `wallet_rpc.yaml` is the
contract, spec-first.** `pin_serve_set` is one `as_of_height` stamp, an
exhaustive match on the connected record's `HoldingsKind`, and two arm methods
— a third kind fails to compile rather than silently becoming a shard list.
`StakePosture::holdings()` is the one conversion from intent to
`HoldingsDescriptor`. **`docs/api/wallet_rpc.yaml` is the RPC contract and
changes land there first.**

**RR-5 (in-PR, #495) — posture is the host's arm, assembled at the surface;
the disk probe is its own task.** *(Ruled 2026-08-17, R7.)* Three corrections
to the slice-4b build, each closing a real defect:

1. **The disk probe must not hitchhike on the serve-set refresh.** Sharing
   that cadence left the volume unwatched for a full tick and would go
   *silent if refresh wedged* — a common-mode failure that silences the disk
   alarm exactly when the node is already failing. It is its own serving-side
   task.
2. **Posture does not belong on `StakingReadView`.** That type is the engine's
   sealed-state aggregation; threading an embedder fact through it made every
   read path invent a default or lie, including `get_staked_balance` /
   `get_staked_outputs`, which threw the value away. `staking_info` and
   `get_wallet_info` take `Tenant::serving_posture` and project it.
3. **The disk row is disarmed from task birth**, so a failed start is *watched*
   rather than missing. `DisarmedReason::NotServing` is the sentence for "no
   host" — used by both serve-set and disk — while `TransportStopped` stays
   the tor supervisor closing.

Also: `ServingPosture` is the **arm** (`Market | FoundationCompleteTree`), not
a sized obligation — the contract projects neither `shard_count` nor
`frozen_count`, and a growing prefix is not a reason to carry a payload nobody
reads. The `posture` wire field is an **open string, not a closed enum**: a
*response* enum would make an older validator reject an entire `staking_info`
reply over one unrecognized display value, and rendering an unknown value as
"not serving" would be a false negative about a node that is serving.

**F-2 — Degradation ladder: coded posture is correct; doc line was drift.**
*(Ruled 2026-08-15; corrected in slice 5.)* Uniform for any P: misses absorb
inside the m-of-n window (nothing to rebond — the node just resumes serving);
crossing the window slashes; for a CompleteTree record the slash **demotes**
to market kind with holdings cleared and collateral taken; from there
**Rebond** reinstates as a market participant, or continued failure degrades
out entirely. Return to CompleteTree posture is a **fresh foundation bond
under a new persona** (`RecordExists` blocks the slot). The
`ARCHIVAL_CONSENSUS_STATE.md` "CompleteTree resume" phrasing was drift and is
corrected.

---

## 4. Design invariants this round establishes

1. **The CompleteTree serve obligation is derived, never stored:** wallet-side
   it is the store's frozen prefix `[0, next_freeze_seg)`; daemon-side it is
   the shard-segment registry. Both freeze on the shared rule
   (`segment_freeze_eligible`).
2. **Freeze-lag window:** the two enumerations share the rule but not the
   driver — daemon tip vs. wallet ingest tip. A wallet trailing inside
   `CAUGHT_UP_SLACK_BLOCKS` has a real window where the chain challenges a
   shard the wallet has not yet frozen-and-begun-serving. The m-of-n sliding
   window (m = 11) absorbs it by design (the daemon's own scan-cost note at
   `db_lmdb.cpp:6074-6085` already prices the absorb window). Documented at
   the prefix arm, so it is explicitly rather than accidentally safe.
3. **Posture is one-way in this round:** the prune-disabled flag has no clear
   path (a foundation node un-declaring its posture while holding a live bond
   is the §9.6-item-4 silent-slash setup). Named reopen criterion recorded on
   the setter (rule 21).
   **The clean exit is Unbond** (Q-5) — `verify_unbond_bond_post` is
   holdings-kind-blind (`bond_post.rs:571-586`), so a CompleteTree record
   unbonds under exactly the rules every other P does. There is deliberately
   no way to stop serving while *remaining* bonded: that state is the silent
   slash this round exists to make unreachable. **Residue, accepted and
   named:** the prune-disabled flag survives the unbond, so a former
   foundation node's store keeps retaining everything after a clean exit. That
   is over-retention — it costs disk and nothing else — and it fails in the
   conservative direction, which is the same asymmetry §9.7 item 5 rules for
   pins. Clearing it is the reopen criterion on the setter, not a silent
   convenience.
4. **Serving follows the bond, across reboots:** the persisted bond record is
   the sole posture marker, and the wallet-rpc open path already starts the
   serving host from it (fail-closed at open; see the F-3 retraction in §2 for
   the three call sites and why their asymmetry is correct). No local setting
   can create, change, or suppress the posture — only bond lifecycle events
   can.
5. **The host still never chooses its own duty:** the prefix arm is reported
   by the pinner, same as the list arm — the `ServeSet` no-public-constructor
   rule is preserved.

---

## 5. D-4 warning text (verbatim; the served string)

This text is the body of `-29506 STAKE_FOUNDATION_UNACKNOWLEDGED` and what the
CLI prints before it will accept the typed phrase. It is single-sourced as
`FOUNDATION_POSTURE_WARNING` and pinned to `docs/api/wallet_rpc.yaml` by test,
so the contract and the served string cannot drift.

> **Foundation CompleteTree posture — read before confirming.**
> This bond declares your node a whole-corpus archival backstop. It is not a staking product:
> **1. It never earns.** CompleteTree holdings are excluded from the reward market by holdings shape, permanently. This is not a phase or a promotion path.
> **2. The obligation grows forever.** You commit to storing and serving every frozen shard the chain ever produces. Disk consumption is unbounded and monotone. Your drive space is your commitment.
> **3. The penalty side is fully live.** You are challenged like any archiver, over the entire frozen corpus. Missed service inside the tolerance window is absorbed; crossing it slashes your collateral, clears your holdings, and demotes this record to an ordinary market position. Reinstatement from there is as a market participant. Returning to CompleteTree posture requires a fresh foundation bond under a new persona.
> **4. Capital is locked at zero yield.** The bond floor is nominal, but it is collateral against the largest possible obligation.
> **5. Durability credit is genesis-gated.** Unless your identity is in the genesis foundation enumeration, this node also receives no durability_count credit — it is a pure donation to the network. Donations are welcome and genuinely valuable; they are simply not compensated.
> To proceed, confirm that you are choosing a non-earning, unbounded-storage service posture.
> CLI: type exactly: `serve without reward` — RPC: set `acknowledge_non_earning_unbounded: true`.

---

## 6. What this round did NOT touch

- **Consensus.** Nothing here changes verify, connect, the scheduler, or the
  wire. No atomic-cutover discipline triggered.
- **Shard assignment.** Named follow-on (§10). The Market posture stub is the
  entire market-side change.
- **The claim stack.** CompleteTree cannot claim (Σwork zero by exclusion);
  nothing changes.
- **GUI repo.** Zero changes; the boundary is the absent acknowledgment field.
- **F5 pruning work.** Inherits the posture flag and the pin-gap constraint
  (§10) but is not built here.

---

## 7. Sequencing and gates

Slices landed in order 1→5; slice 3 depended on 1 and 2; slice 4 on 3; slice 5
last (rule 91). Branch-per-slice off `dev`, signed commits, explicit merge
authorization only, archive tag before any branch deletion. The hardcode died
in the same round the serving arm was born — **no code state ever existed
where an ordinary staker silently owed the corpus.**

**Progress — complete:**

| Slice | What | PR / merge |
|---|---|---|
| 1 | Store surface: `next_freeze_seg`, one-way prune-disabled posture, typed refusal | #479 @ `4828d8dc` |
| 2 | Host: the `ServeSet` prefix arm, posture-as-pin, `PostureLost` | #483 @ `f6aee5f3` |
| 3 | Engine: `StakePosture`, pinner prefix arm, **hardcode deleted** | #489 @ `84908135` |
| 4 | Surfaces: spec-first yaml, `-29506` warning gate, CLI typed phrase | #492 @ `3b108fb9` |
| 4b | Posture visibility + disk-headroom alarm | #495 @ `c92f10ed` |
| 5 | This round record, the §9.1 amendment, the F-2 correction, the fossil sweep | this PR |

Each merged slice carries a signed archive tag (`archive/completetree-*`), and
the superseded pre-plan branch keeps its own
(`archive/complete-tree-activation-superseded-2026-08-15`).

Design gates: all discharged (D-1/D-2/D-3/D-4/D-5 ratified; Q-1 verified;
Q-2/Q-3/Q-4/Q-5 ruled; F-2 ruled and corrected; F-3 retracted;
AF-1…AF-5 and RR-1…RR-5 ruled; §9.1 amendment ratified and recorded; warning
text approved and single-sourced).

---

## 8. What landed, slice by slice

Standing brief rules, all slices: analysis and adversarial review by Claude;
implementation by autonomous agents; every brief carried halt conditions; no
opportunistic refactors; scope lists exhaustive; findings that contradict this
document reported, never patched around. The briefs themselves are retired to
git history — what they produced is below.

### Slice 1 — Store surface (#479)

`LeafStore::next_freeze_seg()` (renamed in review from the drafted
`frozen_segment_count` so the cursor is named after itself and does not
collide with `shekyl_archival_retention`'s first-crossing completeness
vocabulary); `prune_disabled()` / one-way `set_prune_disabled()`; the
`prune_frozen` posture guard **inside the write transaction** (atomic
check-then-mutate under redb's single writer); typed
`StoreError::PruneDisabledPosture`; the `holds_shard` contract comment. KATs
bind cursor↔table in growth, boundary, non-burial, reopen, and rollback
directions, and the refusal KAT asserts non-mutation. All three halt
conditions checked and cleared.

### Slice 2 — Host: the prefix arm (#483)

`serve_set.rs` split under 1k into `serve_set/{mod,set,report,staleness,witness}.rs`.
`ServeSet` carries a private `SetDerivation`; `ServeSet::obligation()` is the
one match site (view, not constructor). `shard_ids()` returns
`Option<&[u64]>` — deliberately not an empty slice for the prefix arm (the
two-empties hazard, closed at the accessor). `contains()` is **exposed, not
wired** (the request path was unchanged; `StoreShardProvider`'s per-read
`Ok(None)` stays the live servability authority — the brief's halt condition,
honored by stopping there). `ReportedSet::CompleteTreePrefix { frozen_count,
declaration }` carries no pin outcomes; the freeze-lag window is documented at
the variant. A `frozen_count = 0` prefix witness mints: the genesis foundation
node starts empty and grows.

### Slice 3 — Engine (#489)

The hardcode is dead. `StakePosture` mandatory on `first_stake` with
`StakePosture::holdings()` as the tree's one intent→`HoldingsKind` conversion,
placed after the idempotency guards (their refusals are more specific) and
before the fee estimate, sweep, and every durable write; `Market` →
`NoShardsAvailable` (`-29505`, kept off `-29500` because "fund and retry"
misdiagnoses a well-funded wallet); the pinner refusal replaced by the prefix
arm via `PinCompleteTreePrefix`; the pinner rebuilt as an exhaustive-match
dispatcher; the two-empties KAT flipped, not deleted.

### Slice 4 — Surfaces (#492)

Spec-first yaml (`posture` defaulting `market` — additive, every pre-parameter
caller byte-identical; `acknowledge_non_earning_unbounded`; `-29506` whose
message is the §5 warning). `FOUNDATION_POSTURE_WARNING` single-sourced with a
KAT asserting it against the yaml's own text. CLI
`--complete-tree-foundation` printing the same constant and requiring exactly
`serve without reward`. In-review tightenings: unknown posture strings refuse
rather than default, and the typed phrase is pinned to the warning that
displays it. D-4 fully discharged.

### Slice 4b — Posture visibility + disk alarm (#495)

Posture snapshot on `ServingHandle` beside `alarms`, published per pin and
cleared on teardown, projected at the wallet-rpc surface (RR-5). Disk-headroom
probe as its own serving-side task: `rustix::fs::statvfs`, its own
`ServingDiskHeadroom` condition, `Episode` lifetime, `DiskUnreadable` disarm
for a failed probe, and disarmed-from-birth so a failed start is watched. The
threshold is a named operator-UX default with its rule-21 reopen criterion.

### Slice 5 — Documentation (this PR)

The §9.1 amendment at its definition site; the `ARCHIVAL_CONSENSUS_STATE.md`
F-2 correction; the FOLLOWUPS sweep (the `first_stake` hardcode item closed as
discharged-by-deletion, with its live remainder carried forward); the
shard-assignment, F5-inheritance, and rule-35 follow-on entries; the
`IMPLEMENTATION_INDEX.md` row (rule 94) and `CHANGELOG.md`; and this document.

---

## 9. Adversarial review summary (wargamed this round)

- **Naive optimizer** (the §9.1 hazard): cannot reach CompleteTree — no GUI
  path, no default, no select-all; CLI requires an explicit flag plus a typed
  phrase; RPC requires an explicit acknowledgment whose absence returns the
  warning itself.
- **Accidental whole-corpus obligation:** eliminated structurally — the
  hardcode is deleted in the same round serving activates; no intermediate
  code state exists where `stake` silently posts CompleteTree.
- **Silent slash via local prune** (§9.6 item 4): unrepresentable under the
  posture flag — a CompleteTree store cannot prune; no pin bookkeeping to
  forget.
- **Freeze-lag challenge window:** real, bounded by catch-up, absorbed by
  m-of-n; documented at the arm rather than accidentally safe.
- **Third-party RPC wrapper:** may reach the posture — accepted per D-2
  (informed volunteer); must still round-trip the acknowledgment, so the
  warning is seen or deliberately echoed.
- **Nominal-bond asymmetry:** cheapest bond, largest obligation — by design (a
  donated backstop); stated plainly in the warning so slash exposure is
  understood as standing, not capital scale.
- **DoS/economics:** no reward exists to be tricked out of (shape exclusion),
  so an open consensus layer accepting CompleteTree from any poster remains
  safe.
- **Observability under common-mode failure** (added R7): a disk alarm that
  shares the serve-set refresh cadence goes silent exactly when refresh wedges
  — the moment an operator most needs it. Separate task, separate condition.

---

## 10. Named follow-ons (rule 7 — shelved with instruments)

1. **Shard-assignment round** (the Market arm's discharge). Reopens the
   `NoShardsAvailable` stub, and **owns `PostureMismatch`** (AF-1). Full
   pre-work notes and the implicit-oracle warning are recorded in
   `docs/FOLLOWUPS.md`.
2. **F5 pruning work** inherits the prune-disabled posture guard (slice 1) and
   the market-arm post→first-refresh pin gap. Recorded in `FOLLOWUPS.md`.
3. **Prune-disabled clear path** — only if ever wanted; requires its own design
   round (reopen criterion on the setter, slice 1).
4. **§12 item 3 concurrency-vs-growing-D** — unchanged owner
   (`ARCHIVAL_CHALLENGE_MECHANISM.md`); this round adds the CompleteTree
   serving host as a consumer of whatever the W₂ rig decides for
   `max_streams` / `MAX_INFLIGHT`.
5. **Superseded branch disposition:** `feat/complete-tree-activation` @
   `661fa8c42` — the pre-plan implementation, superseded by D-1/D-3/D-4.
   Archive tag `archive/complete-tree-activation-superseded-2026-08-15` is cut
   and pushed. Its mining obligation (the one-guard-for-view-and-flag read
   pattern and the wallet-rpc/CLI test shapes) is **complete** as of slice 4b,
   so the deletion gate is open; the branch is deliberately not a `dev`
   ancestor, so removing it needs `git branch -D` and Rick's word.
6. **Degraded-open observability (from the F-3 retraction read):** on the two
   best-effort serving re-arm paths, bonded-but-not-serving is visible only in
   `tracing::warn` until the next open. Bounded and reasoned, but if it wants
   an operator-alarm surface, that is a small named item — not this round's
   scope.
7. **Rule-35 password-copy gap:** pre-existing across five wallet-rpc CLI call
   sites; its own focused PR cut **immediately after round close** — follow-on
   means next, not someday. Enumerated in `FOLLOWUPS.md`.
8. **Cosmetic:** `is_foundation_complete_tree` gather flag naming (correct as a
   market operand, misnamed at worst — per the 2026-07-19 ruling; rename
   opportunistically when `db_lmdb.cpp` is next open for the redb migration).

---

## 11. Rule citations exercised this round

Rule 7 (named follow-ons), Rule 11 (pre-registration deferred to the
assignment round's opening), Rule 12 (posture flag over pin bookkeeping),
Rule 15 (hardcode deleted before genesis), Rule 21 (reopen criteria: flag
clear path; alarm thresholds), Rule 22 (Market refusal is typed with a named
remedy, not a silent deferral), Rule 35 (the password-copy gap, found and
shelved with instruments rather than half-fixed), Rule 36 (no secret handling
introduced), Rule 76 (the disk threshold is provisioned against the stated
device floor), Rule 80/82 (warning UX; typed refusals name remedies; a
disarmed check never renders as healthy), Rule 81 (deferred with the
assignment round), Rule 91 (docs last), Rule 94 (index entry).
