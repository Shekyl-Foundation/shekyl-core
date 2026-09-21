# `shekyl-chain-rules` slice 3 — census 4.E (DRS-E6 increment 4)

**Status:** OPEN — Round 0 pre-flight written 2026-09-20 against `dev` @
`34d111551` (post-#805); **Round 0 RULED 2026-09-20** (Q1–Q7, §8; the
reframing in §0). **Rules-crate commits 1–6 LANDED on the branch
2026-09-20** (§7 record: `implemented 18 / validator-enforced 151`,
`held-by-cxx 2`, `at-open 1`, `4.E 2 / 3`, `ratified 126 / 153` unmoved).
Rebased onto #811's merge (`b680d59e0`, 2026-09-21; #806 was closed and reopened
as #811): **c7** adds `ChainRules::trust()` beside `in_force` and passes it at
the connector's `validate` call (Q2's cross-lane touch, disclosed on the DRS-E2
row). E5's writer wiring is a FOLLOWUPS row (owner DRS-E2).
Template: [`CHAIN_RULES_CRATE.md`](CHAIN_RULES_CRATE.md) §7.5.1; predecessors
[`CHAIN_RULES_SLICE_1.md`](../completed/CHAIN_RULES_SLICE_1.md),
[`CHAIN_RULES_SLICE_2.md`](../completed/CHAIN_RULES_SLICE_2.md). Parent plan:
[`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) §7.5 table 3 (*"slice 3 — after
4.A/4.B"*). Cites `26-sub-pr-design-discipline.mdc`. The living contract is
[`CHAIN_RULES_CRATE.md`](CHAIN_RULES_CRATE.md); do not implement from this
file. Owner: the DRS-E6 lane.

**Scope (table 3).** The three surface-free rows of 4.E — CEN-E1, CEN-E2,
CEN-E5 — all `pending` at `rust/shekyl-chain-rules/src/census.rs:297`–`:299`.
Plus the one decision `CHAIN_RULES_CRATE.md` §13 assigns to *"slice 3 (4.E)
or slice 6 (4.I), whichever opens first"*: the **below-anchor validation
mode** (`PDM-Q-F27`, confirmed `PDM-Q5` 2026-09-18 as `Trust::Full |
BelowAnchor(anchor)`, an input to `validate` orthogonal to `RuleSet`). Plus
the census **re-key of E1 and E2** that `PDM-Q11`/`PDM-Q-F30` bind to *"the
PR that lands `Trust::BelowAnchor`, because that PR moves checkpoint state
into Rust"*.

## 0. What this slice is — the anchor model's Rust home, not a port (RULED 2026-09-20)

**This slice is not porting census 4.E. It is building the Rust home for
the anchor model `PDM-Q5` ratified** ([`ARCHIVAL_PRUNED_DAEMON_MODE.md`](ARCHIVAL_PRUNED_DAEMON_MODE.md)
§`PDM-Q5`, RULED 2026-09-18, `:292`–`:296`): *"a release-carried checkpoint
`C` on the `assumevalid` argument; three bands (`≤ C` skeleton, trusted with
the binary; `(C, tip − W]` filled from archivers; above from peers); the
tip-relative trust horizon and the operator trust-below fallback
REJECTED."* That ruling is the slice's reason for being: it names a
consumer (the band-1 sync driver), a semantics (`assumevalid`; below `C`
proof validity is asserted by the anchor, not checked), and a mode
(`Trust::Full | BelowAnchor(anchor)`, `PDM-Q-F27`, confirmed in the same
ruling) — none of which depends on the C++.

The distinction decides every question in §8, so it is stated first. Read
as a **port**, 4.E is a mechanism with no data, no users and no Rust
presence — the shape `get_output_histogram`, `get_curve_tree_path` and the
stripe engine all had, and the honest disposition for that shape is
deletion, not a port. Read as **PDM's home**, the empty C++ table (F1) is an
*observation* — the release that ships the first anchor has not happened
yet, per `PDM-Q5`'s launch-window item — and not the premise. A later reader
applying the deletion test to a vacuous mechanism gets the wrong answer;
this section exists so they do not.

Consequences the framing fixes directly: the anchor table is **consts
shipped with the binary** (Q6 — *"trusted with the binary"* excludes an
operator-editable carrier; a `config/*.json` is a different mechanism with a
different trust model, and rule 71's data-not-control-flow is a property the
shape has, not the reason for it); `Trust` is the pipeline input (Q1), and
`BelowAnchor`'s meaning when slice 6 lands it is **already written** at
`:293` — band 1's skeleton, not an ad-hoc skip list; and the rows this slice
implements are the model's own — E1 is *the anchor's rule* (`PDM-Q11`), E5
is *the binary's anchors agree with the file it opens*.

**What the sweep found, in one paragraph.** Unlike slices 1 and 2, nothing
here is *adopted*: **no anchor, checkpoint or `Trust` symbol exists anywhere
in Rust** (§3 F1), and the C++ table is empty on every network
(`init_default_checkpoints`, `checkpoints.cpp:136`–`:145`), so every 4.E
row is vacuous on every chain that exists and parity evidence for this slice
is fixture-only. What the slice builds is the **release-carried anchor
table** as per-network data (the `RuleSchedule::for_network` shape), the one
predicate that reads it per block (E1: hash equality at an anchored height),
and the one that reads it at writer open (E5's surviving subject: the
recorded chain agrees with the binary's anchors, else pop or fail-stop). E2
has **no Rust site** — the store admits no alternative block, and on the
main chain the floor is satisfied by construction — and is **subsumed behind
two things** (§2): the alt `ChainView` (slice 9, unscheduled beyond its
table-3 position) and `D_max`'s numeric (`PDM-Q11`, provisional 720,
re-pinned at the Round-2 testnet gate). The load-bearing question was the
channel the anchors reach `validate` through (§8 Q1): every candidate
channel touches the E2 driver's call sites, which PR #806 is growing *now*,
so sequencing against #806 is part of the answer (§8 Q2). Two structural
consequences: B6's block identity must be derived **before** the view-bound
rules run rather than after the last one passes (§4.3, F8), and E5 is the
first row enforced at a site other than `validate` whose holder is **Rust**,
which the registry could not yet say (§8 Q4).

---

## 1. Parents — landed? (§7.5.1 (a))

| Parent | Needed for | State at `34d111551` |
| --- | --- | --- |
| Slice 1 (`Rule`/`BlockRule`, `BlockContext`, `ChainView::tip()`, `Tip::connecting_height`, B6 identity, `held_by_cxx`) | E1 reads the connecting height and the block's B6 hash; E5's holder shape | **Landed** (#762, #767, #768). `rules/mod.rs:157`–`:171` (`BlockContext`), `block.rs:313` (`ValidatedBlock::derive`, B6 at the end — see F8). |
| Slice 2 (`form` → `StructurallyValid` → `validate`; `Substrate`; `Fault`) | the pipeline the anchors enter; a below-anchor *mode* is a pipeline input | **Landed** (#777 …; `validate.rs:106`, `:251`). |
| S-CHAIN-W / S-CHAIN-R (`BatchView::block_at`, `RecordedBlock.hash`) | E5 reads `block_at(anchor.height).hash` | **Landed.** No `ChainView` growth this slice — E1 compares the candidate's own identity, E5 reads a field the view already projects (`view.rs:132`–`:143`). |
| C2-R1b §4b (E1/E2 semantics ratified 2026-09-03 *while the mechanism exists*) | the rows' statements | **Landed as text.** Both rows carry *"existence HELD for C2-R0"*; `PDM-Q5` answered existence: a release-carried `assumevalid` anchor, runtime pins rejected (`PDM-Q-F23`, #733). |
| **`PDM-Q5` (RULED 2026-09-18) — the slice's reason for being (§0):** anchor `C`, three bands, `Trust::BelowAnchor` confirmed; `PDM-Q11`: `D_max` homed at CEN-E2; `PDM-Q-F27`/`F30` | the model this slice houses; the mode's shape; the re-key obligation | **Landed as rulings** ([`ARCHIVAL_PRUNED_DAEMON_MODE.md`](ARCHIVAL_PRUNED_DAEMON_MODE.md) §`PDM-Q5`, §`PDM-Q11`). Reversion clause: the `Trust` shape reverts if `connect`'s in-force check admits a second set per height — falsifier `RuleSetNotInForce` removed or widened; it is present at `connect.rs:359` and compares **by value** since RD-Q10. |
| #805 (height-semantics Phase 2b): `BlockHeight` (absolute) vs `BlockCount`/`ChainCount` (spans) in `shekyl-types` | anchor heights are absolute instants | **Landed** (`shekyl-types/src/block_axis.rs`). Both crates check clean at `34d111551`. Anchor heights are `BlockHeight`; the E2 floor comparison in slice 9 is a `BlockHeight` order, not a count. |
| PR #806 (DRS-E2 inc 2, **in flight**): `shekyl-chain-ingest` `stage.rs:57`/`:75` call `form(...)`, `connector.rs:271` calls `validate(formed, &view, &in_force)`, `schedule.rs:72` `ChainRules` resolves network → rule set | nothing this slice reads — but it is the **only production caller** of the two stage functions | **In flight.** Any new pipeline input lands on its call sites (§8 Q2). |

No parent blocks the rules-crate work. One in-flight PR (#806) sequences
the signature-touching commit.

---

## 2. Row-body audit (§7.5.1 (b)) — 3 rows at `34d111551`

The census pins its C++ line numbers at `02c086f4b`; all four for 4.E have
drifted (F2). The *site* column below is the live one.

| Row | b | Statement (census `:368`–`:372`) | Body (Rust, landed) | C++ site (live) | Proposed disposition |
| --- | --- | --- | --- | --- | --- |
| CEN-E1 | 2 | at a checkpointed height the block id must equal the checkpoint hash (main **and** alt admission; an alt match *forces* the reorg) | **none** — no anchor table, no predicate | main `blockchain.cpp:5545`–`:5552` (`is_in_checkpoint_zone` → `check_block`); alt `:2186`–`:2192` (`check_block(…, is_a_checkpoint)`), the forced switch `:2446` | **Land** — the anchor's own rule (`PDM-Q5`, Q11): `anchors.expected_at(connecting) == candidate.hash` when an anchor sits at `connecting`; vacuous otherwise, **recorded as evaluated** either way (the C++ records nothing; the Rust coverage says the row ran). View-bound: the height is the tip's. Needs B6 **before** the rules (F8). The *forced-reorg* clause is an alt-chain consequence and belongs with E2's alt home (slice 9), not here. |
| CEN-E2 | 2 | an alternative block at or below the last checkpoint preceding the current height is refused; **home of `D_max`** (Q11: a second band, the rolling cap, when the Rust validator takes it) | **none** | `blockchain.cpp:2105`–`:2110` → `checkpoints.cpp:97`–`:109` (`is_alternative_block_allowed`) | **Subsumed pending the alt view (slice 9)** — the D5 shape. On the main chain the predicate holds by construction: `is_alternative_block_allowed(H, h)` requires `last_anchor_at_or_below(H) < h`, and a main-chain candidate has `h = tip + 1 > H ≥ any anchor ≤ H`. Its only refusing arm is alt admission, which no Rust path has. Stays `pending` with a `subsumed-by` registry comment. **Subsumed behind two things, and the wait is the longer of them:** the alt `ChainView` (slice 9 — D5 waits on the same view, and slice 9 has a table-3 position but no schedule), and `D_max`'s band (`PDM-Q11`: shape frozen, **numeric provisional** at 720, re-pinned at the Round-2 testnet gate as one of four numerics). *"Pending the alt view"* alone would imply the shorter wait. **Re-keyed in the census now** (F30 binds the re-key to this PR; §8 Q3), with both blockers named in the row. |
| CEN-E5 | 2 | *(mechanism removed, `PDM-Q-F23`)* **what survives:** at init the recorded chain is checked against the compiled-in set; a conflict below tip rolls back to `max(checkpoint − 2, 1)`; a conflict **at genesis** fail-stops (*"wrong network for the binary"*); a rollback that would cross the prune watermark fail-stops | **none** | `blockchain.cpp:6368`–`:6450` (`check_against_checkpoints`), `:6452` (`enforce_checkpoints`), `cryptonote_core.cpp:660` (fail-stop `core::init`) | **Land the predicate, hand the remedy to the writer.** The *rule* is E1 over the recorded chain instead of the candidate: for every anchor with `height < chain height`, `block_at(height).hash == anchor.hash`, else `AnchorConflict { height, expected, recorded }`. The *remedy* (pop to `max(h − 2, 1)`; refuse at genesis; refuse when the pop would cross the floor — `StoreCannot::PopBelowFloor` already exists, `pop.rs:87`) is the writer's, and the writer is the E2 driver at open. E5 is thus enforced at a site other than `validate` — the registry needs a status for that (§8 Q4). C++ holder today: `tests/core_tests/checkpoint_conflict_rollback.cpp :: gen_checkpoint_conflict_rollback`. |

Row-count check: 3 = the `pending` entries at `census.rs:297`–`:299`.

---

## 3. Findings from the code sweep (what the plan assumed vs. what landed)

- **F1 — the whole 4.E substrate is greenfield.** `rg 'Trust::|BelowAnchor|assumevalid|checkpoint' rust/ --type rust` (excluding `shekyl-oxide`) returns only the wallet's cancellation "checkpoints". Nothing to adopt; slices 1–2 adopted `shekyl-difficulty`/`shekyl-pow-randomx` bodies, this slice writes the anchor table and two predicates from the census text. The bodies are trivial (a lookup and an equality); the design weight is all in *where the data lives and how it enters the pipeline* (§4).
- **F2 — the census line pins for 4.E have all drifted.** E1 `5829–5837` → `:5545`–`:5552`; alt `2315`/`2481` → `:2186`/`:2446`; E2 `2233` → `:2105`, `checkpoints.cpp:137` → `:97`; E5 `6392`/`6308` → `:6452`/`:6368`. Census amendment in this PR (§8 Q3), the F3/F13 precedent from slice 2.
- **F3 — CEN-E1's statement is stale.** It reads *"the hardcoded/**JSON-loaded** checkpoint hash"*; the JSON path was deleted under `PDM-Q-F23` (#733). The re-key rewrites the statement to the anchor model: *"the release-carried anchor hash"*.
- **F4 — CEN-E5's heading contradicts its bucket, and the earlier claim that this moves the denominator was wrong.** The row leads with **"Removed"** yet sits in bucket 2 (live, surface-free, counted in `enforced 153`), and the first paragraph of this document's predecessor sweep read it as a registry drift. Reading the whole row: the *mechanism* (runtime JSON pins) was removed; the *rule* that survives (init-time reconciliation with the compiled-in set) is live at `blockchain.cpp:6368` and correctly bucket 2. The status column `—` is honest (the survivor was ratified only *as part of* the removed shape). So: **not a denominator change — 151 stands** — but a rule-91 heading defect (*"a corrected body under a stale heading is worse than an uncorrected item"*): the row must lead with what it *is* and carry the removal as its history. Amendment in this PR.
- **F5 — the C++ holds a *table*, `PDM-Q5` speaks of *one* anchor; both are right.** `checkpoints::m_points` is `map<height, hash>`; `PDM-Q5`'s `C` is the release's *current* anchor, and `PDM-Q11`/`F27` say *"the release-carried **table**"*. So the Rust type is a per-network, strictly-ascending table of `(BlockHeight, BlockHash)`; the current anchor `C` is its last entry; E1 checks *every* entry (as `check_block` does); the E2 floor is the last entry `≤ H`; `Trust::BelowAnchor` is mintable only from the table's last entry (`F27`: *"so `D_max` never has to defend a node below its anchor"*). All three networks' tables are **empty** today, exactly as `init_default_checkpoints` is — the first entry ships with the first checkpoint release (`PDM-Q5` launch window: before day ~195, then cadence `≤ W`), together with the `SIGNING.md` release-flow sentence `PDM-Q5` owes. Not this slice's to write; this slice makes it a one-line data edit.
- **F6 — E2 has no Rust site and cannot refuse anything on the main chain** (§2). The store has no alt admission (`shekyl-chain-store` has `connect`/`pop` only); `validate`'s connecting height is always `tip + 1`. Same finding shape as slice 2's D5 (LWMA-1 over an alt window), same disposition. **What this PR does owe E2** is F30's re-key: the census row's site column gains its Rust home ("alt `ChainView`, slice 9, with `D_max`") and loses the C2-R0 HELD clause.
- **F7 — E5 is a writer-open rule, not a per-block predicate**, and the pieces split cleanly: the *check* is chain-state arithmetic the rules crate owns (it is literally E1's equality over recorded blocks); the *remedy* is a sequence of `pop()` calls or a refusal to run, which only the writer can do, and the writer is the E2 ingest driver (`shekyl-chain-ingest`, live since #804). The C++ fail-stops on three conditions: conflict at genesis (no pop can fix a wrong-network file), the pop would cross the prune watermark (`C2-R1b F-1(b)`), a pop failed mid-rollback. In the Rust store the second is already `StoreCannot::PopBelowFloor` (the floor is 1 today, S-PRUNE raises it to `≥ D_max`, SCW-7); the first is a check before the first pop; the third is the poison latch. Nothing new on the store side.
- **F8 — B6's placement conflicts with E1.** `ValidatedBlock::derive` (`block.rs:313`) computes the block identity *"after the last rule has passed and nowhere else"*; E1 needs the identity *while* the rules run. Two ways out: derive B6 twice (E1 computes its own keccak — breaks "derived once", B6's whole point) or **derive B6 once, first**, as a definition row at the top of `validate` beside D4's target, carried on `BlockContext`, and handed to `ValidatedBlock::derive`. The cost is one keccak over the hashing blob for a block the view-bound rules then refuse — the C++ pays it up front unconditionally (`get_block_hash` at the head of `handle_block_to_main_chain`) and it is three orders below the longhash already paid in `form`. The pattern (definition derived once, recorded where derived, carried in the verdict) is D4's from slice 2 §4.3. Default: move it (§4.3).
- **F9 — `connect` already records what a verdict did not bring.** `header::widen_gaps(CoverageGaps::of(in_force.enforced().filter(!coverage.contains)))` at `connect.rs:377`–`:381`, persisted as the engine-local `rule_coverage_gaps` cell (`codec/property.rs:262`). `PDM-Q5`'s *"their absence is recorded in `RuleCoverage` and `connect`'s provenance so a band-1 file is never parity evidence"* is therefore satisfied by the **existing** cell the day a proof row is skipped. What the cell does not carry is *why* a row is absent — unimplemented vs. asserted-by-anchor. Both make the file non-evidence, which is the property that matters; distinguishing them is a cell change (`SCHEMA_VERSION`) with no row to record until slice 6. Recorded, not built (§8 Q5).
- **F10 — the mode decision is due now by the contract's own clause, but its effect has no subject until slice 6.** §13: *"decide **before** `validate` acquires callers beyond the store tests and the E2 driver — the signature is one parameter today and every later caller is a retrofit"*. The E2 driver is the caller, it is being written in #806, and `validate` has **one** production call site (`connector.rs:271`). Yet the mode's *effect* — proof rows not run — has nothing to act on (4.I `implemented 0 / enforced 19`), and its stated falsifier (*"a band-1 sync test that connects a skeleton block under `RuleSet::GENESIS` and is refused"*) cannot even be written: nothing refuses a skeleton today, and `Candidate` (`block.rs:95`) holds full `Transaction`s, so a skeleton block has **no type**. That last point is a slice-6 / `PDM-Q6` finding this pre-flight surfaces and does not resolve: band-1 needs a candidate shape before it needs a trust posture. The resolution the defaults take (§4.1): settle the **parameter** now in its final shape — it is what E1 needs anyway — and let it grow the posture arm when there is a row to skip, with constructors so no caller is retrofitted.
- **F11 — one predicate, two C++ arms.** The main-chain arm guards `check_block` with `is_in_checkpoint_zone(height)` (`checkpoints.cpp:68`: `height ≤ last anchor`), which is redundant with `check_block`'s own `find` (`:75`); the alt arm calls `check_block` unguarded. Behaviour is identical — equality at exactly the anchored heights — so the Rust predicate is one function and the zone test is not a rule (it is the C++ avoiding a map lookup). `is_in_checkpoint_zone` **is** load-bearing elsewhere: `PDM-Q5`'s band 1 is *"height ≤ C"*, the same predicate; it lands as `ReleaseAnchors::covers(height)` for `Trust` to use, not as a rule.
- **F12 — E1 refuses as `form` in C++ (`reject_block_form`) but is view-bound in Rust.** The equality needs the connecting height, which only the view knows; the stateless stage cannot evaluate it. It joins the `judge_block!` list in census order (A2, B5, C1, C2, D1, **E1**), `Locus::Block`.
- **F13 — the C++ holder for E5 exists and is named.** `tests/core_tests/checkpoint_conflict_rollback.cpp :: gen_checkpoint_conflict_rollback` (registered `chaingen_main.cpp:128`), plus `tests/unit_tests/checkpoints.cpp` for E2's three arms and `checkpoint_uniformity.cpp` for rule 71 across networks. Relevant to §8 Q4: if E5 is held until the Rust writer wires the remedy, the hold has a citable test in the `held_by_cxx` form.

---

## 4. Substrate this slice adds

### 4.1 `Trust` — what the node takes on the release's word

```rust
/// One release-carried anchor: the block the binary vouches for at `height`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor { pub height: BlockHeight, pub hash: BlockHash }

/// The release-carried anchor table for one network — rule-71 DATA, the
/// `RuleSchedule::for_network` shape. Strictly ascending by height (a
/// `const fn well_formed` refuses a table that is not, at compile time, as
/// `RuleSchedule::well_formed` does). Empty on every network today, exactly
/// as `init_default_checkpoints` is; the first entry ships with the first
/// checkpoint release (PDM-Q5's launch window).
pub struct ReleaseAnchors { entries: &'static [Anchor] }

impl ReleaseAnchors {
    pub const fn for_network(network: Network) -> Self;      // MAINNET / TESTNET / STAGENET, all `&[]`
    pub const EMPTY: Self;                                    // Fakechain: no release vouches for a regtest chain
    pub fn expected_at(&self, height: BlockHeight) -> Option<BlockHash>;   // E1's read
    pub fn current(&self) -> Option<Anchor>;                  // `C`, the last entry (F5)
    pub fn covers(&self, height: BlockHeight) -> bool;        // `height ≤ C` — band 1 (F11)
    #[cfg(test)] pub(crate) const fn for_tests(entries: &'static [Anchor]) -> Self;   // the `admitting_for_tests` shape
}

/// What this node takes on trust: the release's anchors. An input to
/// `validate` orthogonal to `RuleSet` (PDM-Q5): an anchor addition is a
/// *release*, a rule-set change is a *hard fork*, and `connect`'s in-force
/// check compares rule sets by value — anchors on the rule set would
/// either be refused or would have to be excluded from the comparison.
pub struct Trust { anchors: &'static ReleaseAnchors /* , posture — slice 6 */ }

impl Trust {
    pub const fn full(anchors: &'static ReleaseAnchors) -> Self;   // verify everything; consult the anchors
    // slice 6: `pub fn below_anchor(anchors) -> Option<Self>` — `None` on an
    // empty table (F27: mintable only from the release-carried table), and a
    // `posture: Posture::{Verify, AssertedBelow(Anchor)}` field the 4.I rows read.
    // Its meaning is already ruled, not slice 6's to derive: PDM-Q5 `:293`,
    // "`≤ C` skeleton, trusted with the binary" — band 1, not a skip list.
}

pub fn validate<'id, V: ChainView<'id>>(
    formed: StructurallyValid, view: &V, rule_set: &RuleSet, trust: &Trust,
) -> Result<Verdict<ChainValid<'id, V>>, Fault<V::Fault>>;
```

Why the anchors ride on a `Trust` value rather than on `RuleSet`,
`Substrate`, or the `form` token:

- **Not `RuleSet`** — `PDM-Q5`'s ruling and its reversion clause; lifecycle
  (release vs. hard fork); `connect` compares rule sets by value
  (`connect.rs:359`), so a table on the set is either refused when the
  driver's copy differs or has to be carved out of the comparison.
- **Not `Substrate`** — `Substrate` is *services with faults* (a clock that
  may be unavailable, a VM that may fail; since #811 also advisory hints to
  them, `pin_seed`, defaulted). The table is static data with no failure mode
  and nothing to serve; a method returning it would make the trait carry
  configuration, and every mock would answer with a table it has no reason
  to hold. *(Round 0 also said "adding a trait method breaks every
  implementor" — a defaulted method does not, as `pin_seed` shows; that
  clause is withdrawn and the argument rests on the kind of thing the trait
  is.)*
- **Not the `form` token** — `form` is stateless and has no height; E1 is
  view-bound (F12). Carrying a `&'static` table through the token would work
  mechanically but would make the token describe node configuration it never
  read, and the posture arm (slice 6) is a per-sync-session choice, not a
  property of one block's stateless judgement.
- **A `Trust` parameter** is what `PDM-Q5` named and what §13 describes; the
  constructor `Trust::full(anchors)` means slice 6's posture field lands with
  a second constructor and **no existing caller changes** — which is the
  retrofit F10 exists to avoid.

### 4.2 The two predicates

- **E1** (`rules/anchors.rs`, `BlockRule`): `match cx.trust.anchors().expected_at(cx.connecting) { Some(expected) if expected != cx.hash => refuse, _ => pass }`, recorded evaluated on both paths. Reads `cx.hash` — B6's identity, on `BlockContext` after F8's move.
- **E5** (`ReleaseAnchors::conflict_with<'id, V: ChainView<'id>>(&self, view: &V) -> Result<Option<AnchorConflict>, V::Fault>`): for each anchor below the tip, compare `view.block_at(height)` (an `AtHeight::Recorded`; `Absent` at an anchored height below tip is itself the conflict — the file is missing a block it claims) against the table; the first mismatch is the conflict. `AnchorConflict { height, expected, recorded: Option<BlockHash> }`. The **remedy** is documented on the type, executed by the writer: *at genesis → refuse to run (wrong network for this binary); else pop to `max(height − 2, 1)`, each `pop()` refusing at the floor.*

### 4.3 B6 moves to the head of `validate` (F8)

`validate` derives the identity once after the seed check and before the
window/target (`let hash = B6::identity(candidate.block(), &mut coverage)`),
`BlockContext` gains `hash: BlockHash`, and `ValidatedBlock::derive` takes it
instead of computing it. B6's doc comment moves with it: *"derived once, at
the head of the view-bound stage, before any rule that reads it; E1 is the
first."* The `derive` doc's *"after the last rule has passed"* clause is
**refuted, not superseded** (rule 16 §comment-that-outlived): its premise
was that no rule reads the identity, and E1 does.

---

## 5. Fixtures per row (§7.5.1 (c)) and commit plan

| Row | Fixture (negative first) | Positive / vacuous |
| --- | --- | --- |
| E1 | `ReleaseAnchors::for_tests(&[Anchor { height: 3, hash: OTHER }])`; a valid candidate connecting at 3 → `InvalidBlock { rule: E1, locus: Block }` | same table, candidate whose B6 hash equals `OTHER` → `Ok`, `E1 ∈ coverage`; empty table, any height → `Ok`, `E1 ∈ coverage` (vacuous, recorded) |
| E2 | — (subsumed; slice 9 with the alt view) | registry comment names the site and the D5 precedent |
| E5 | mock chain of 5 with an anchor at 3 whose hash differs → `Some(AnchorConflict { height: 3, … })`; anchor at 0 differing → conflict at genesis (the caller's fail-stop case) | matching anchor → `None`; anchor above tip → `None` (not yet checkable, as the C++ `continue`s) |
| F8 | coverage is not returned on refusal, so the move is pinned positively: `ValidatedBlock::hash()` equals `B6::identity` of the same block computed independently, and E1's refusal fixture proves the identity was available to a rule (it could not refuse otherwise) | — |

Commit plan (rules crate first; the signature commit sequenced per Q2):

1. `anchors.rs`: `Anchor`, `ReleaseAnchors` (+ `for_network`, `well_formed` compile gate, `EMPTY`, `for_tests`), tests, rule-71 uniformity test (the three public tables are identical today and the test says so *as data*).
2. B6 to the head of `validate` (F8); `BlockContext.hash`; `ValidatedBlock::derive(hash, …)`; refute the stale doc clause.
3. `Trust` + `validate(…, trust: &Trust)`; every in-tree caller (store fixtures/tests, harness) passes `&Trust::full(&ReleaseAnchors::EMPTY)`; **`connector.rs:271` if #806 has merged** (Q2).
4. E1 rule + fixtures; registry `E1 implemented(crate::rules::anchors::E1)`.
5. E5 `conflict_with` + `AnchorConflict` + fixtures; registry per Q4.
6. E2 registry comment (subsumed-by, slice 9); census re-key of E1/E2/E5 (F2, F3, F4, F6); `CHAIN_RULES_CRATE.md` §13 mode item → LANDED-as-parameter with the slice-6 posture owed; `PDM` F27/F30 rows pointed at this PR; index rows; CHANGELOG (the `validate` signature is API).
7. Writer wiring of E5's remedy: **a FOLLOWUPS row, Owner: DRS-E2** (Q2 as
   ruled — an "if the ingest crate is quiet" condition would make this PR's
   scope depend on another lane's timing, which is how a PR grows between
   plan and push). The row names `ReleaseAnchors::conflict_with` as the
   callee, the driver's open path as the site, and the remedy verbatim: pop
   to `max(h − 2, 1)`, refuse at genesis, refuse across the prune floor
   (`StoreCannot::PopBelowFloor`, already landed).

Commit order on the branch: 1, 2, 5, then 3 and 4 (the signature and the
rule that reads it) — all on the branch before #806 merges; the PR **lands
after #806**, and the rebase adds the one-line `connector.rs:271` update
(commit 3's file set on `dev` by then).

Expected record at close: `implemented 17 / validator-enforced 151` (E1),
E5 as the first `EnforcedAt` row (Q4 (a): counted as Rust-enforced, printed
beside the held rows, excluded from per-block completeness), `ratified 126 /
153` unmoved (E5's `—` stands; the survivor was ratified inside a shape that
no longer exists — a fresh ratification is the census lane's, not this
slice's), `4.E 2 / 3`. No `SCHEMA_VERSION` change; no `ChainView` growth;
no `ConnectFacts` change.

---

## 6. What this slice does not build (denominator)

- `Trust`'s posture arm and the 4.I skip — slice 6, with the **skeleton
  candidate type** F10 surfaces (a block without prunable bodies has no
  `Candidate` today).
- E2's refusing arm and `D_max`'s band — slice 9 (alt `ChainView`).
- A "why absent" discriminator on `rule_coverage_gaps` — F9; decide with the
  first row that is asserted rather than unimplemented.
- The first anchor entry, and `SIGNING.md`'s release-flow sentence —
  `PDM-Q5`'s launch-window item, a data edit when the release ships.
- C++ retirement of `checkpoints.cpp` — cutover (E4), not a rule slice.

---

## 7. Record at close of the rules-crate commits (1–6, 2026-09-20) and round log

`check_chain_rules_coverage.py --describe` on the branch:

```text
consensus: implemented 18 / validator-enforced 151   held-by-cxx 2   at-open 1   enforced 153   ratified 126 / enforced 153
  4.E: implemented 2 / enforced 3
  enforced at open (Rust-enforced, outside per-block coverage):
    CEN-E5: crate::rules::anchors::E5 :: a_recorded_block_that_is_not_the_anchor_is_the_conflict
```

What landed, by commit: **c1** `anchors.rs` — `Anchor`, `ReleaseAnchors`
(`for_network`, `EMPTY`, `expected_at`, `current`, `covers`, `for_tests`;
`well_formed` const-asserted; `no_release_has_shipped_an_anchor_yet`). **c2**
B6 derived once in `form`, carried as `StructurallyValid::hash` — one stage
earlier than Q7 asked, same property, outside the write transaction; the
token's `Debug` was re-hashing the block and now prints the field. **c5**
`E5::conflict_with` (public as `ReleaseAnchors::conflict_with`),
`AnchorConflict::remedy` → `Remedy::{RefuseToRun, PopTo}` with
`rollback_target` pinned at the floor; `RowStatus::EnforcedAt { site, test }`
/ `enforced_at(path, "test")` with the gate asserting the proof test is
*defined* (12 self-test cases); `RuleSet::enforced()` excludes it; the gate's
`at-open` term. **c3+c4** `Trust { anchors }` / `Trust::full` /
`Trust::UNANCHORED`; `validate(…, trust: &Trust)`; `BlockContext.trust`;
E1 in the block list with four fixtures; the harness probe re-labelled to
CEN-F1. Landed together because the context field's only reader is E1 — a
parameter no rule reads is the callee-without-caller smell, and clippy
refused it. **c6** census re-key of E1/E2/E5 (F2, F3, F4, F6, F30);
contract, changelog, index, FOLLOWUPS (E5 wiring, owner DRS-E2), PDM F27/F30.

**Sweep of `dev` `34d111551` → `b680d59e0` (2026-09-21, after #807–#811)
for anything this slice's claims rest on:** census 4.E rows untouched
(J13/J18 renamed for `Reinstate`); `PDM-Q5` still at `:292`–`:296`;
`connect`'s by-value in-force check (the `Trust` reversion falsifier) still
at `connect.rs`; `Candidate` still holds full transactions (F10 stands);
`Substrate` gained a **defaulted** `pin_seed` (#811) — which withdraws one
clause of §4.1's "not on `Substrate`" argument (a defaulted method breaks
no implementor) and leaves the load-bearing one (services vs. static data);
the CSR register's CEN-E1/E5 rows are pinned verdicts at `eb1b60198` and
stay as records-was; the E2 grader counts a row no connected block
exercised as `not_exercised`, never as a failure — so E5, enforced at open,
is `not_exercised` in every replay **by construction**, and its evidence is
the fixture and the writer's open path, not a replay. `#811`'s
`export_conformance_register` fixture check passes over the re-keyed census
(it reads the CSR register, not the census).

Deviations from §5's plan, disclosed: commits 3 and 4 merged (above);
`Box::leak` builds the `'static` fixture tables in tests (the production
type holds `&'static [Anchor]`, which is the point — no runtime table).

- **Round 0 (2026-09-20, `34d111551`).** Sweep; §1–§6; §8 questions posed.
- **Round 0 RULED (2026-09-20).** All seven on the defaults, with the
  reframing that decides them written into §0: this slice houses `PDM-Q5`'s
  anchor model; it does not port 4.E. Q6's reason is the ruling's *"trusted
  with the binary"*, not rule 71. Q1 inherits `BelowAnchor`'s semantics from
  `PDM-Q5` `:293` (band 1's skeleton). Q2's E5 wiring goes to FOLLOWUPS
  (owner DRS-E2), not in-PR. E2's subsumption names both blockers.

---

## 8. Questions for the reviewer — Round 0 (RULED 2026-09-20)

- **Q1 — the channel.** `Trust { anchors }` as a fourth `validate` parameter,
  `Trust::full(&ReleaseAnchors)` the only constructor today, the posture
  field and `below_anchor` constructor arriving with slice 6 (§4.1). This
  settles the signature §13 says must be settled before callers accrue,
  lands only what E1 reads, and grows without touching a caller. The
  alternatives considered and why not (§4.1): on `RuleSet`, on `Substrate`,
  on the `form` token. **Default: as proposed.** The honest tension: the
  parameter is named for a mode whose effect does not exist until slice 6;
  the name is right (anchors *are* the node's trust — `assumevalid`) and the
  alternative — a bare `&ReleaseAnchors` today, renamed and re-shaped in
  slice 6 — is exactly the retrofit F10 forbids.
  **RULED: default.** And the posture arm's semantics are already written:
  `PDM-Q5` `:293` — *"`≤ C` skeleton, trusted with the binary"* — is what
  `BelowAnchor` must mean when slice 6 lands it: **band 1's skeleton, not an
  ad-hoc skip list.** Cited on `Trust`'s doc so slice 6 inherits the
  definition instead of re-deriving one.
- **Q2 — sequencing against #806.** Every channel touches the E2 driver's
  call sites (`stage.rs`, `connector.rs`) or its `ProductionSubstrate`. Land
  slice 3 **after #806 merges** and update `connector.rs:271` in this PR (one
  line, disclosed on the DRS-E2 row), or land before and let #806 absorb the
  one-line rebase? **Default: after** — #806 is the larger and older branch,
  and the commit-3 edit to a file on `dev` is a trivial cross-lane touch;
  commits 1, 2, 4, 5 do not wait. Same answer for E5's writer wiring
  (commit 7): in this PR if the ingest crate is quiet when this lands, else
  a FOLLOWUPS row owned by DRS-E2.
  **RULED: after #806; E5's writer wiring to FOLLOWUPS, owner DRS-E2, not
  in-PR** — the "if the ingest crate is quiet" condition would make this
  PR's scope depend on another lane's timing. The remedy is the writer's,
  `PopBelowFloor` already exists, so the row has a real owner and a real
  home.
- **Q3 — the census re-key in this PR.** F30 binds E1/E2's re-key to *"the PR
  that lands `Trust::BelowAnchor`"*. This PR lands `Trust` without the
  `BelowAnchor` arm. Re-key now (the anchor state moves into Rust here, which
  is the trigger both rows named), or hold the re-key for slice 6? **Default:
  now** — the trigger is *"moves checkpoint state into Rust"*, and that is
  this PR; F2/F3/F4's line-and-text corrections ride with it. F30's row in
  `ARCHIVAL_PRUNED_DAEMON_MODE.md` is amended to cite the PR that actually
  did it.
  **RULED: yes** — *"moves checkpoint state into Rust"* is the trigger and
  this is that; F30 binds it here anyway.
- **Q4 — E5's registry status.** E5 is enforced at writer open, not in
  `validate`; per-block completeness (`Coverage::is_complete_for`) can never
  contain it. `RowStatus` has `Pending` / `Implemented` (a `Rule` type
  compile-pinned) / `HeldByCxx` (a non-predicate the C++ driver decides, with
  a cited test, excluded from the validator-enforced denominator). Three
  options: **(a)** a new `RowStatus::EnforcedAt { site, test }` — a Rust
  function, compile-pinned by path, excluded from per-block completeness
  like a hold but counted as Rust-enforced (record `implemented 18 / 151`
  with the gate printing the at-open row beside the held ones); **(b)**
  `held_by_cxx("tests/core_tests/checkpoint_conflict_rollback.cpp",
  "gen_checkpoint_conflict_rollback")` until the writer wires the remedy,
  then (a) — a hold with an expiry we control rather than cutover's;
  **(c)** `implemented(E5)` with E5 a `Rule` whose `judge` is the per-block
  restatement *"the anchors at or below the connecting height agree with the
  recorded chain"* — true per block but checks the same thing as E1 did for
  every block already recorded, and puts an O(anchors) view read on every
  connect. **Default: (a)**, because it says what is true — the row is
  Rust-enforced, at open, by a named function with a fixture — and because
  it is the status A1/A4 will need at cutover when their holder becomes the
  Rust ingest driver; (b) is the fallback if (a) is judged too much registry
  for one row.
  **RULED: (a), `RowStatus::EnforcedAt { site, test }`.** The registry
  having no vocabulary for a Rust-enforced row outside `validate` is a gap,
  not a reason to distort the row. (b) would be **false** — `held_by_cxx`
  asserts the C++ holder enforces the row, and here the enforcement is Rust.
  (a) is needed twice already: A1 and A4 need exactly this at cutover when
  their C++ holders disappear; minting it now with two future consumers named
  is the cheap moment.
- **Q5 — provenance cause (F9).** Leave `rule_coverage_gaps` as is, with the
  discriminator decided in slice 6 when the first asserted row exists?
  **Default: yes**; recorded in §6, no FOLLOWUPS row (it is scoped to slice
  6's plan, which this document is not).
  **RULED: yes** — a "why absent" discriminator has no subject until slice 6
  gives it one.
- **Q6 — the anchor table's home.** Rust consts in `shekyl-chain-rules`
  beside `RuleSchedule` (`for_network`, rule-71 data), or `config/*.json`
  through the genesis tool's pin machinery? **Default: consts** — the table
  is consensus-adjacent release data with a compile-time well-formedness
  gate, like the schedule, and it is empty; a `config/` carrier is a
  release-tooling question for the first checkpoint release
  (`PDM-Q5`'s item), not for the type.
  **RULED: consts — and `PDM-Q5` is the reason, not rule 71.** *Release-
  carried* means shipped with the binary. A `config/*.json` an operator can
  edit is a different mechanism with a different trust model: it would let
  an operator set their own anchor, which is exactly what *"trusted with the
  binary"* excludes (the operator trust-below fallback is REJECTED in the
  same ruling). Consts beside `RuleSchedule` is not a tidiness preference; it
  is the only shape that implements the ruling.
- **Q7 — B6 first (F8).** Move the identity derivation to the head of
  `validate` and refute the *"after the last rule"* clause, or let E1
  derive its own hash? **Default: move** — one keccak per refused block, paid
  unconditionally by the C++ today; "derived once" is the property B6 was
  landed for.

  **RULED: move.** Computing identity only after the last rule passes is
  wrong for a validator whose rules need the identity while running; one
  keccak per refused block against the C++ paying it unconditionally is not
  a cost worth an architecture around.