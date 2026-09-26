# `shekyl-chain-rules` slice 1 — census 4.A + 4.B (DRS-E6 increment 2)

**Status:** CLOSED-as-record — **implementation LANDED** on PR #768
(2026-09-17). #762 (`Rule`/`BlockRule`, SCW-18 pin, B1/B2/B7), #767
(`held_by_cxx`, A1/A4) and #768 (`ChainView::tip()`, A2, B5, B6;
`PDM-Q-F26` items 1–2) are the three landing PRs; this file archives with
the last of them. Round 1 = pre-flight written against `dev` @ `3560b80c2`;
ruled in full the same day (Q1 §2, Q2–Q6 §8). Record at close:
`consensus: implemented 6 / validator-enforced 151   held-by-cxx 2
enforced 153   ratified 126 / enforced 153`. Residue F2 (CEN-A7 count
bounds) lives in FOLLOWUPS, owner the wire-format port. Template:
[`CHAIN_RULES_CRATE.md`](../design/CHAIN_RULES_CRATE.md) §7.5.1. Parent
plan: [`DAEMON_REDB_STORE.md`](../design/DAEMON_REDB_STORE.md) §7.5.
Cites `26-sub-pr-design-discipline.mdc`. The living contract is
[`CHAIN_RULES_CRATE.md`](../design/CHAIN_RULES_CRATE.md); do not implement
from this file.

**Scope (table 3).** The surface-free rows of 4.A (7) and 4.B (6; CEN-B3 is
surface-bound and arrived with S-CHAIN-W — table 2). Plus the one `ChainView`
method the scaffold owed this slice: `tip()` (`CHAIN_RULES_CRATE.md` §13,
Q12-2). Plus the first real rule, so SCW-18's `trait Rule { const ROW }` pin is
decided here, before the migration is 153 call sites
(`DRS_E1_SCHAIN_W.md` SCW-18).

**What this pre-flight found, in one paragraph.** Of the thirteen rows, **six
are predicates `validate` can evaluate** over `(Candidate, ChainView, RuleSet)`
and land here (CEN-A2, B1, B2, B5, B6, B7). **Two** (CEN-A3, B4) have a Rust
body already but an **unlanded parent** — the bond-pubkey read has no store
table until E4 S-ARCH — and are proposed for a disclosed deferral (Q3).
**Five** (CEN-A1, A4, A5, A6, A7) are what the subsystem's own name says:
*acceptance topology* — dedup against three stores, orphan marking, and three
wire/ingest bounds that fire before a `Candidate` exists. They are not
predicates on the recorded chain and the registry has no status that can
represent them; how they are counted is the slice's load-bearing ruling (Q2).
Three substrate findings were made on the way (§6).

---

## 1. Parents — landed? (§7.5.1 (a))

| parent | needed by | state at `3560b80c2` | verified |
| --- | --- | --- | --- |
| `shekyl-chain-rules` scaffold (increment 1) | everything | LANDED PR #753 | `rust/shekyl-chain-rules/src/{census,view,validate,verdict,block,harness}.rs` read in this worktree |
| S-CHAIN-W: `BatchView: ChainView`, `connect`, `root_at(h)` = key `h` | `tip()` gets a store implementor in the same PR; B5's read | LANDED PR #757 | `rust/shekyl-chain-store/src/store/view.rs:144–207` (re-anchored by PR #764, which moved the body into `store/chain_reads.rs`); `connect.rs:280–320` |
| SCW-19 (`root_at(h)` is the state **at** `h`) | B5 | fixed in #757; trait doc `view.rs:117–131` agrees | both ends read |
| SCW-18 (`trait Rule { const ROW }` shape) | first `implemented(...)` entry | shape decided, "lands in E6 with the first real rule" | `DRS_E1_SCHAIN_W.md:766–780` |
| `CurveTreeRoot::EMPTY == selene_hash_init()` | B5 at genesis | present | `shekyl-types/src/lib.rs:460–467`; genesis header root `shekyl-genesis-tool/src/builder.rs:185` |
| `Block::hash` KAT against the daemon | B6 (adopt) | present | `shekyl-wire/tests/coinbase_hash.rs:57–103` (live-oracle vectors, height 0 == published mainnet genesis id) |

No parent is missing for the six predicate rows. B4's parent is not landed
(§3, Q3).

---

## 2. `ChainView::tip()` — the owed method (Q12-2), shape RULED 2026-09-16

Round-2 sketch was `fn tip(&self) -> Result<Tip { height, hash, root }, Fault>`.
Two of the three fields survive contact with the substrate; the third does not,
and the empty chain needs a case.

```rust
/// The last recorded block. `None` from `tip()` is the empty chain — the
/// candidate is genesis — and a rule that reads the tip writes that arm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tip {
    pub height: BlockHeight,
    pub hash: BlockHash,
}

pub trait ChainView<'id> {
    // …existing three…
    /// CEN-A2 (`hash`: `previous` must be the tip's hash); the connecting
    /// height every height-indexed rule is stated at (`height`: B1, B5 here;
    /// C2/C3, F5 later). `None`: nothing recorded (genesis admission).
    fn tip(&self) -> Result<Option<Tip>, Self::Fault>;
}
```

**RULED 2026-09-16 (maintainer, at PR #761 review) — `Option<Tip>`, not a
bespoke enum.** The round-1 draft proposed `enum Tip { Empty, Recorded {..} }`
"for consistency with `AtHeight`". The S-CHAIN-R ruling on the store's own
`RecordedTip` (SCR-4) states the discriminator, and it applies here
unchanged: a custom absence type earns its keep when the default **lies
inside the valid range of the type** — `AtHeight` exists because the LMDB
reader once returned 32 zero bytes for a missing root, a *valid* encoding of
the identity point; `curve_tree_roots[0]` read as data. A tip has no such
alternative: there is no zero tip that reads as a recorded block, so `None`
cannot be mistaken for one, and an enum would buy nothing. The C++ shows the
hazard in the other direction — `top_block_hash` hands back **two** sentinels
on an empty chain, `null_hash` *and* `*block_height = UINT64_MAX`
(`db_lmdb.cpp:3185` writes `m_height − 1` before the `:3186` guard), neither
distinguishable from data — and `Option` is what makes both unrepresentable.
The genesis arm is still written explicitly in every rule that reads the tip
(A2, B5 here), and `MockChain::tip()` already has this shape.

- **`height`** — justified by B5 (`root_at(connecting height)`); later by 4.C
  and CEN-F5 (the caller-derived height operand the census names against
  `txin_gen.height` spoofing, census 4.F notes). B1 does not read it: the
  rule set in force is an input the caller chose with `rules_at(height)`.
- **`hash`** — justified by CEN-A2: the fail-closed re-check
  `bl.prev_id != top_hash` (`blockchain.cpp:5423`). The store already has
  this as **belt** SI-2 `TipMismatch` (`connect.rs:303`); without the rule, a
  wrong-parent block reaches `connect` and fires a *fatal* instead of a
  verdict — the exact hazard C2-R8 drew the rule/belt line for.
- **`root` — dropped.** `root_at(connecting_height)` is the ruled read
  (SCW-19, key `h`), and the store implements it. A second root on `Tip`
  would be a second read path to the same cell, and which-key ambiguity is
  the defect SCW-19 just closed. One read path.
- **Genesis is a case, written at the `None` arm**: A2 at `None` requires
  `previous == [0; 32]` (`get_tail_id()` → `top_block_hash()` → `null_hash` on
  an empty store, `db_lmdb.cpp:3186–3191`); B5 at `None` reads `root_at(0) ==
  CurveTreeRoot::EMPTY` (`view.rs:218–220`), which is what the genesis header
  carries. The round-1 draft's worry — `tip()?.map(..)` letting genesis fall
  through as a pass — is answered by the fixtures, not the type:
  `cen_a2_genesis_previous_is_the_null_hash` and
  `cen_b5_genesis_root_is_the_empty_tree` (§7) both refuse a wrong genesis, so
  a rule that forgot the arm is red.

**Connecting height** is a crate-private helper, `fn connecting_height(tip:
Option<&Tip>) -> BlockHeight` (`None → 0`, `Some(t) → t.height + 1`), used
by every height-indexed rule so the operand is derived once from the view and
never from the candidate (F5's spoof).

**Store side — landed as sequenced with S-CHAIN-R** (#764 first, then the
`tip()` PR; `BatchView::tip()` reads through `chain_reads::tip_of`, the
inherent helper renamed `tip_row`). *Pre-flight text:* `BatchView` today has a
private `fn tip() -> Result<Option<u64>, StoreError>` (`view.rs:97–108`)
reading `block_info.last()`. S-CHAIN-R's commit 1 ([`DRS_E1_SCHAIN_R.md`](DRS_E1_SCHAIN_R.md) — plan PR #760, increment PR #772, archived 2026-09-18)
§7, SCR-13) replaces that helper with a private `store/chain_reads.rs`
(`tip_of`, `cell`, `block_body`) shared by `BatchView` and `ReadSnapshot`, so
both lanes edit `store/view.rs`. **Order agreed 2026-09-16:** S-CHAIN-R's
`chain_reads` lands first (its code may start once #760 merges; this slice
waits on Q2–Q6), and this slice's commit 1 then implements
`ChainView::tip` for `BatchView` as `chain_reads::tip_of(..)` → `Some(Tip {
height, hash: BlockInfo.hash })` / `None` — one read body, no second
`last()`. If the order inverts, this slice adds the impl on the private
helper and S-CHAIN-R's rewire absorbs it; either way `view.rs` is touched by
one lane at a time and the trait method lands with its implementor. No
`ReadSnapshot: ChainView` impl exists or is planned (SCR-16, out), so the
new trait method has exactly three implementors: `BatchView`, `MockView`,
`FaultingView`. `block_at`/`root_at`'s AboveTip classification reads through
the same body unchanged. `MockChain::tip()`
(`harness.rs:58–61`, today `Option<BlockHeight>`) grows the hash;
`FaultingView::tip` faults. S-CHAIN-R's `ReadSnapshot::tip()` returns the
store's own `Option<RecordedTip { height, hash, connect }>` — a wider type for
a different reader (RPC/wallet), not this trait's; the two share the `Option`
shape and the SCR-4 reason for it. The workspace must compile at every commit (rule 26
B5), so the trait method and its two implementors are **one commit**.

---

## 3. Row-body audit (§7.5.1 (b)) — 13 rows at `3560b80c2`

Sites re-read at the dev tip, not copied from the census's pinned lines (which
have drifted by ~15 lines in `blockchain.cpp`). *class* (as ruled 2026-09-16, Q2/Q3):
**rule** = a predicate `validate` evaluates and lands here; **adopt** = Rust
body exists, wrapped; **wire invariant** = holds under any rule set, held by
the parser (R8 arm B with a wire holder — §4); **subsumed-by-X** = never
arrives as its own rule, its row closes when X lands; **held-by-cxx** =
acceptance topology the C++ ingest driver decides, a deferral that expires at
cutover (§4); **deferred** = rule-22 shape, blocker named (Q3).

| row | b | C++ body (this tree) | Rust body | class | view read | disposition |
| --- | --- | --- | --- | --- | --- | --- |
| CEN-A1 | 2 | `have_block_unlocked` `blockchain.cpp:3011–3041`: main (`block_exists`) ∪ alt (`get_alt_block`) ∪ `m_invalid_blocks`; consumer `add_new_block` `:6338–6343` → outcome byte `ALREADY_EXISTS`, `return false` | — | **held-by-cxx** | none possible: two of the three stores are not recorded-chain facts, and the outcome is not `InvalidBlock` | where a block *goes*, not whether it is valid — the ingest driver's; §4 |
| CEN-A2 | 2 | routing `:6346–6355` (`prev_id == get_tail_id()` → main, else alt); **re-check** `:5423–5428` `bl.prev_id != top_hash` → `reject_block_internal` | store **belt** SI-2 `TipMismatch` `connect.rs:303` | **rule** (the re-check); routing is the driver's | `tip()` | lands: `previous == tip.hash`; at `None` (empty chain), `previous == [0; 32]` |
| CEN-A3 | 1 | 2-arg `add_new_block` guard `:6320–6322`: `attestation_root == empty_attestation_root()` or assert | `shekyl_archival_retention::empty_attestation_root` | **subsumed-by-B4** | — | **RULED Q3:** the guard is about a C++ *overload* ("a caller dropped the witness"); once `Candidate` carries the witness there is no witness-less entry and A3 *is* B4's empty-witness arm — it never arrives as its own rule; its row closes when B4 lands (not "deferred": a deferral would send B4's implementer looking for a rule that does not exist) |
| CEN-A4 | 2 | orphan marking `:2462–2464` in `handle_alternative_block`: parent in neither main nor alt → `ORPHANED`, not stored | — | **held-by-cxx** | alt-store membership is not a recorded-chain fact (E5 S-ALT) | routing, not validity — the ingest driver's; the store half (a parentless block cannot connect) is already SI-2; §4 |
| CEN-A5 | 4 | `cryptonote_core.cpp:1450` `block_blob.size() > cumulative_block_weight_limit + BLOCK_SIZE_SANITY_LEEWAY (100, :71)` — **pre-parse** | — (`shekyl_wire::MAX_BLOCK_BLOB_SIZE` is a parse-DoS cap, `block.rs:48`, a different bound) | **subsumed-by-4.G** (proposed) | operand is 4.G state (the weight limit) | fails the R8 invariant test (the limit is a consensus parameter, so it would *not* hold under a rule change) and is not a rule of its own: the census names it "pre-parse approximation of CEN-G6b"; any blob it rejects has weight > limit and is refused by the 4.G weight rule at slice 7. Its row closes there; the pre-parse fast path is an ingest-DoS choice the Rust driver makes or drops consciously (bucket-4 keep-or-drop), not a row. §4 |
| CEN-A6 | 4 | `cryptonote_core.cpp:1381` parse failure rejects | `shekyl_wire::Block::from_bytes` (exact consumption, `block.rs:186–206`) | **wire invariant** | `validate` takes a parsed `Block`; the parse is `BLOCK_TX_WIRE_FORMAT_PORT.md`'s subject | passes the R8 test (a blob that does not parse cannot be judged under *any* rule set); home is a wire-side invariant register, the SI register's analogue, owned by the wire-format port — re-homed there the way L2–L6 went to `SI-` (census bucket 3, leaves the denominator). §4 |
| CEN-A7 | 4 | `cryptonote_basic.h:914` `tx_hashes.size() > 0x10000000` fails (de)serialization | `Block::read` caps `n_tx` at `READ_LEN_CAP = 1_000_000` (`lib.rs:67`, `block.rs:162–167`) | **wire invariant** + arm-C value | — | the *existence* of a count bound passes the R8 test (you need one to deserialize at all) → wire invariant beside A6; the *value* (2^28 vs 10^6, neither derived) is arm C — nobody decided it — routed to the wire-format port as F2 (§6, re-derived) |
| CEN-B1 | 2 | `:5445` `m_hardfork->check(bl)` → `do_check` `hardfork.cpp:109–113`: `major == heights[cur].version && vote ≥ version`; alt `check_for_height` `:121–126` (ideal at height) | — | **rule** | none (the rule set is an input) | lands: `header.major_version == rule_set.header_major_version()` — a new `RuleSet` parameter, Q4. The alt arm collapses: the caller passes `rules_at(height)` |
| CEN-B2 | 4 | `hardfork.cpp:41–50` vote normalisation (`minor 0 → 1`); `vote ≥ 1` unfailable | — | **rule, port-as-is** | none | lands: evaluates, never refuses; coverage records B2 |
| CEN-B3 | 4 | — | store belt `hf_versions[h]` `connect.rs:387` | **out** — surface-bound, table 2 (S-CHAIN-W) | — | not this slice |
| CEN-B4 | 1 | `:5463–5470` `verify_block_attestation(bl, predecessor_height, …, witness)` → FFI `shekyl_archival_verify_attestation` with `ShekylArchivalAttestationVerifyCtx { predecessor_height, anchor_hashes[L+1], headers, pairs(p_id, pubkey) }` | `shekyl-ffi/src/archival_ffi/attestation.rs:117–164`; `shekyl-archival-retention::attestation_wire` | **deferred** | `block_at` for the anchor window (landed); **bond `(p_id, pubkey)` pairs — no table, no view method until E4 S-ARCH**; the witness is not a `Candidate` component | **RULED Q3 — DEFERRED** (rule 22: blocker E4 S-ARCH, consumer the increment landing the bond-pubkey read, falsifier §8 Q3). A3 is subsumed into it, not deferred beside it |
| CEN-B5 | 1 | `:5579–5591` `bl.curve_tree_root != m_db->get_curve_tree_root()` (tip root = state at the connecting height) → `reject_block_form` | store `root_at(h)` key `h` (`view.rs:216–233`) | **rule** | `tip()`, `root_at(connecting_height)` | lands: `Recorded(root) if root == header.curve_tree_root` passes; else refuses; `AboveTip` refuses (unreachable against a conforming view — SI-4 keeps `tip + 1` recorded — written as the fail-closed arm G11 requires) |
| CEN-B6 | 4 | `get_block_hashing_blob` (cryptonote_format_utils) | `shekyl_wire::Block::hash` (`block.rs:217–247`); KAT `coinbase_hash.rs` | **adopt** | none | lands: the identity derivation site moves behind the row's function (Q5) |
| CEN-B7 | 4 | `:5431–5441` one-time `MCLOG_RED` warning if `major > get_ideal_version()`; **no reject** | — | **rule, port-as-is** | none | lands: evaluates, never refuses; the log side-effect is not ported (the crate has no logging, G12) — recorded, not hidden |

**Denominator of this audit:** all 13 rows of 4.A/4.B were read at their C++
site in this tree and, where a Rust body was claimed, at the Rust site. Nothing
outside 4.A/4.B was examined for slice 1; 4.C–4.M are the later slices'.

---

## 4. The registration gap (Q2) — the grouping, then the mechanism

*As found at pre-flight (records-was):* `census_rows!` knew two statuses,
`pending` and `implemented(path)`; `RuleSet::GENESIS.enforced` was
`CenRow::ALL` (153); and `Coverage::is_complete_for` was true only when every
enforced row was in coverage. Five slice-1 rows can never be in coverage
because `validate` cannot evaluate them, so with the registry as it then
stood `is_complete_for` was permanently false. *As landed (#767):* a third
status `held_by_cxx("<file>", "<test>")` for A1/A4, and `RuleSet::enforced()`
excludes held rows so completeness is `E − H` (§4.1). The round-1 draft proposed one new status for all five;
**the review (2026-09-16) asked for the grouping to be checked first, and
the five are not one thing.** C2-R8's category test (§2 there: *would this
still have to hold if the consensus rules changed?*) applied per row:

| row | R8 test | disposition |
| --- | --- | --- |
| A6 parse failure rejects | **yes** — a blob that does not parse cannot be judged under any rule set | **wire invariant**: arm B with a wire holder (`shekyl_wire::Block::from_bytes`). Home: a **wire-side invariant register**, the `SI-` register's analogue, owned by the wire-format port (`BLOCK_TX_WIRE_FORMAT_PORT.md`), which does not exist yet. Re-homed the way L2–L6 went to `SI-` — the census row moves to bucket 3 and leaves the enforced denominator — **when that register is minted**; not a rules-registry status |
| A7 tx-count bound | **yes** for the bound's existence (you need a length bound to deserialize at all); **no document names the value** | **wire invariant** (existence) beside A6; the **value** is arm C, routed to the wire-format port as F2 |
| A5 blob size vs weight limit + 100 | **no** — the weight limit is a consensus parameter; the row would not have to hold under a rule change | **subsumed by the 4.G weight rule** (slice 7): the census already calls it a "pre-parse approximation of CEN-G6b", and any blob it rejects has weight > limit. Its row closes when the 4.G rule lands (the A3 → B4 model); the pre-parse fast path is an ingest-DoS choice for the Rust driver to keep or drop consciously, not a row |
| A1 dedup across main / alt / invalid | the *store* half holds under any rule set (a hash is recorded once) — but the row's subject is the **outcome byte** `ALREADY_EXISTS` and *which* store answered | **held-by-cxx**: where a block goes, not whether it is valid. Acceptance topology is the ingest driver's, and the driver is C++ until the daemon rewrite / E2 replay driver |
| A4 orphan → not stored | same shape: the store half is **SI-2** already (a parentless block cannot connect); the row is the routing outcome `ORPHANED` | **held-by-cxx**, beside A1 |

So: **two** rows need a new status (A1, A4), **two** re-home to a register
that the wire-format port mints (A6, A7 — until then they stay `pending`
with this disposition written on them, and the denominator they leave is the
census's to move, not this crate's), **one** is subsumed (A5). The
`held(<rust path>)` variant the draft proposed is **not minted**: it has no
consumer today (rule 21) — it reopens when the Rust ingest driver takes A1/A4
over, at which point the question is whether those rows re-home (a driver
register) or the registry needs a Rust holder status.

### 4.1 `held_by_cxx(<test>)` — the mechanism, under the review's three conditions

**Condition 1 — holder-*enforces*, not holder-*exists*.** A `file:token` grep
succeeding proves a token appears in a file (PWD-B10: the probe ran, the
output was real, the verdict was about the wrong subject). The entry therefore
names **a test that the holder rejects** — the same standard the negative
fixtures get — and the gate asserts that test's *name* exists at the cited
path (rule 47: the gate's subject is the test) while the C++ CI lane runs it.
**Finding F4 (§6), as corrected at implementation:** A4's rejection test
**already existed** — `gen_block_invalid_prev_id`
(`tests/core_tests/block_validation.cpp:244–265`) submits a block whose parent
is unknown and asserts `orphaned ∧ ¬added ∧ ¬rejected` plus `check_block_purged`
(height unmoved); the pre-flight's search read its name and missed its
assertion. A1's did not exist: nothing submitted a known block and observed
`ALREADY_EXISTS`. Minting `held_by_cxx` therefore cost **one** C++ core test,
`gen_block_already_known_is_already_exists` (same block submitted twice; the
second submission asserts `already_exists ∧ ¬added ∧ ¬rejected ∧ ¬orphaned`,
height 2), in `block_validation.cpp` — the minimum C++ touch (rule 20 bars new
C++ *logic*; a test that proves the holder refuses is the evidence the status
requires). The entries name `gen_block_already_known_is_already_exists` (A1)
and `gen_block_invalid_prev_id` (A4); the existing test gained a comment
naming CEN-A4 and the gate's dependence on its name.

**Condition 2 — a C++ holder is not a durable home; type it.** `held_by_cxx`
is a **deferral with a known expiry**: it is *not* `held(<rust path>)` (not
minted), and the gate refuses an entry whose cited test file no longer exists
— which is what cutover does by construction, so cutover **forces** the
resolution of every held row at the moment the C++ leaves, instead of leaving
them quietly held by a deleted file. Rule-22 shape on each: *blocked on the
Rust ingest driver — falsify by the driver PR that routes `ALREADY_EXISTS` /
`ORPHANED`*.

**Condition 3 — the third figure is a subtraction, not a denominator.** The
record keeps `enforced E` fixed and prints, on the consensus line:
`implemented I / validator-enforced (E − H)   held-by-cxx H   enforced E
ratified R / enforced E`. `RuleSet::enforced` excludes held rows so
`is_complete_for` measures `E − H`; `E` never moves for a hold, so coverage
cannot improve by moving rows out of scope — the failure the two-number
format exists to prevent, and which this programme has relearned twice
already. `--describe` lists the held rows by id with their cited test.

Grammar: `A1 held_by_cxx("tests/core_tests/block_validation.cpp",
"gen_block_already_known_is_already_exists"),` — the gate parses the pair,
asserts the file exists (repo-relative, inside the repo) and contains the
test **identifier** (word-bounded: a longer identifier with the same prefix
does not match), refuses a bare path / unquoted / non-identifier form as an
unparseable entry, and refuses `held_by_cxx` on a row whose census `site(s)`
cell places the rule outside C++ (a Rust `.rs:N` site; a bare line citation
is C++ by the census's own §4 default, `blockchain.cpp`). `--selftest`
exercises every refusal red (49 in total at #767's second review pass — the
first cut had 41; the review added the holder-path, registration and
comment-stripping refusals). Rust side:
`RowStatus::HeldByCxx`, and `RuleSet::enforced()` filters held rows so
`is_complete_for` measures `E − H`; the `RuleSet` `Debug` prints
"151 of 153 rows (validator-enforced; held rows excluded)". **Record as
landed (this PR):** `consensus: implemented 3 / validator-enforced 151
held-by-cxx 2   enforced 153   ratified 126 / enforced 153`; the `tip()` PR
takes `implemented` to 6.

## 5. SCW-18 — `trait Rule { const ROW }`, the first real rule's shape (Q6)

```rust
// rules/mod.rs
pub(crate) trait Rule {
    const ROW: CenRow;
}
/// The registry-generic face of `Rule`, so one macro serves both enums;
/// every `Rule` is `Bound<CenRow>`, a policy rule (E5) will be `Bound<PolicyRow>`.
pub(crate) trait Bound<R> { const ROW: R; }
/// What a block rule reads besides the view. A struct so the set can grow
/// without moving any rule's signature; the view is passed *beside* it so a
/// new chain fact is a new `ChainView` method, never a new parameter.
pub(crate) struct BlockContext<'a> { candidate: &'a Candidate, rule_set: &'a RuleSet }
pub(crate) trait BlockRule: Rule {
    fn check<'id, V: ChainView<'id>>(cx: &BlockContext<'_>, view: &V)
        -> Result<Verdict<()>, V::Fault>;
}
/// Predicate rows: inserts `R::ROW` iff `R` passed. Definition rows (B6)
/// record at the derivation site `implemented(...)` names.
pub(crate) fn run<'id, R: BlockRule, V: ChainView<'id>>(cx, view, coverage) -> Result<Verdict<()>, V::Fault>;

// census.rs — the entry names a TYPE; the macro emits both pins:
//   use $path as _;                                                      (G9: exists)
//   const _: () = assert!(matches!(<$path as Bound<$name>>::ROW, $name::$var)); (SCW-18: is this row)
B1 implemented(crate::rules::header::B1),
```

*As landed (rules PR, commit "Rule/BlockRule + B1/B2/B7"):* the pre-flight
sketch passed `tip: &Tip` positionally; the landed shape reads the tip from
the view inside the rules that need it (A2, B5), so `tip()` landing on
`ChainView` moves no rule signature — the property the parallel start relied
on. The pin was forced red once before landing: registering `header::B1`
under the `B2` entry fails with `E0080: evaluation panicked: … the type
registered under B2 is bound to a different census row (SCW-18)`.

Unit structs per row (`rules/topology.rs`: `A2`; `rules/header.rs`: `B1 B2 B5
B6 B7`). `validate` runs `for each R in slice-1 list { match R::check(..)? {
Ok(()) => coverage.insert(R::ROW), Err(r) => return Ok(Err(r)) } }`. The
refusal is still written at the site that judged (`refused(R::ROW, Locus::Block)`),
so the row is named twice — once structurally, once at the arm — and the two
must agree or the pin fails. `census_status!`/`census_pin!` grammar is
unchanged (`implemented(path)`), so the Python gate's regex is unchanged; only
the emitted pin grows.

**B6 under this shape (Q5).** The row's body is the identity derivation.
`ValidatedBlock::derive` today calls `block.hash()` directly (`block.rs:112`);
under slice 1 it calls `rules::header::B6::identity(&Block) -> BlockHash`, so
the function `implemented(B6)` names *is* the derivation site and coverage
records B6 when the identity is derived — no no-op "check". The KAT that makes
"adopt" true is `shekyl-wire/tests/coinbase_hash.rs` (vectors captured from
the daemon); the crate's own test pins `ValidatedBlock::hash() ==
BlockHash::from_bytes(candidate.block.hash())`, which the scaffold already has
(`validate_tests.rs`).

---

## 6. Substrate findings (pre-flight, rule 26 B6/A2)

**F1 — the census's `blockchain.cpp` line pins have drifted (~+15).** Census
says A2 re-check `5741–5745`, B1 `5727`, B5 `5885–5897`, B7 `5713–5723`; this
tree has `5423`, `5445`, `5579–5591`, `5431–5441`. The census header carries
its own pinned sha, so this is not a census defect; recorded so this document's
sites are read as *this tree's*. No action.

**F2 — CEN-A7: two count bounds on one field, neither derived (re-derived
2026-09-16 after the review asked for the units to be checked).** The review
read C++'s `0x10000000` as a blob *byte* bound and proposed comparing it with
`MAX_BLOCK_BLOB_SIZE`; **read at source it is not**: `cryptonote_basic.h:914`
is `if (tx_hashes.size() > CRYPTONOTE_MAX_TX_PER_BLOCK) return false;` — an
**element count**, inside the serializer. So the matched-units pair is the one
first stated: C++ refuses `tx_hashes.size() > 2^28`; `shekyl_wire::Block::read`
refuses `n_tx > READ_LEN_CAP = 1_000_000` (`block.rs:163`). Same subject,
same unit, values apart by ~268×, Rust tighter and fail-closed. The *byte*
pair, for completeness: C++ has **no** fixed blob byte cap on 64-bit hosts
(`cryptonote_core.cpp:1374`'s `0x3fffffff` is inside a `sizeof(size_t) == 4`
guard); its operative byte bound is CEN-A5's `weight_limit + 100`. Rust's
`MAX_BLOCK_BLOB_SIZE = MAX_TX_SIZE + READ_LEN_CAP × 32 + 128` (≈ 33 MB,
`block.rs:48`) is documented as a DoS pre-allocation guard "**not** a
consensus bound", provably `≥` any blob `read` accepts — it never rejects a
parseable block, so it is not a second consensus bound. Nothing in the
conclusion changes; the mismatch the review feared was in the *reading*, and
it is now pinned at both sources so the wire-port owner is handed one
comparison in one unit.

In the three-field form (§9): *reproduced* — a per-block tx-count bound
whose value is `2^28` in C++ and `10^6` in Rust, neither with a derivation
record; *why* — parity first, and no real block approaches either; *correct*
— one constant with a derivation (a count bound derived from the
block-weight limit, or ruled unbounded-below-weight), owned by the
wire-format port, which is also where A6/A7's wire-invariant register lives
(§4). **Route (A5 carry):** one `FOLLOWUPS.md` line in this PR's doc commit,
Target pre-genesis, falsifier "one constant with a derivation record, or the
divergence ruled". A7's value is arm C: nobody decided it, and this finding
says so rather than inventing an answer. *The reading error itself is the
case for Rust typing (maintainer, 13:57):* a units mismatch between two bare
integers — a count read as a byte length because 268 M "looks like a size" —
is the class of error C++'s `size_t` invites and a `TxCount` / `ByteLen`
newtype makes a compile error. When the wire-format port derives the one
constant, it should be typed, not bare.

**F5 — the mock was one height off the store on the SCW-19 axis (found by
B5's fixture at implementation).** `MockChain::root_at(h)` returned the root
pushed *with* block `h`, and `AboveTip` at `tip + 1`; the store returns key
`h` (the state at `h`, written by `h − 1`'s connect) and has `tip + 1`
recorded. A B5 fixture written against the old mock would have passed with
the wrong operand and failed against the store. Corrected in the `tip()` PR:
`roots[0] = EMPTY`, the root pushed with block `h` is `roots[h + 1]`,
`root_at(tip + 1)` recorded, `root_at(tip + 2)` `AboveTip`; the harness's own
probe tests pin both ends. The same class as SCW-19 (a which-key ambiguity),
reached from the mock side — the reason the pre-flight fixture list carried
`cen_b5_reads_tip_plus_one_not_tip`, which is what bit.

**F3 — the store already holds A2's belt but nothing holds A2's rule.**
`connect.rs:303` refuses `previous != tip.hash` as SI-2 `TipMismatch`
(fatal, poisons the batch). Until A2 lands here, the S-CHAIN-R driver would
route a wrong-parent block into a fatal. Not a defect — the belt is doing what
a belt does — but it makes A2 the first rule to land, before any driver
connects real blocks.

**F4 — the C++ holder of A1 has no rejection test; A4's exists under a name
that does not say so** (*corrected at implementation — the pre-flight said
"neither"*). Searched `tests/core_tests/` and `tests/unit_tests/` for a test
that submits a duplicate block to `add_new_block` and observes
`ALREADY_EXISTS`: none — `peer_policy_block_ingest.cpp` tests the
outcome-byte encoding, `sync_orphan_arm.cpp` the p2p re-request arm. For an
unknown parent observed as `ORPHANED` + not stored: `gen_block_invalid_prev_id`
(`block_validation.cpp:244–265`) is exactly that test; the search matched its
line and misread it as the sync arm — a records-was worth keeping, since the
next reader will grep the same way. Under §4.1 condition 1 the `held_by_cxx`
entries need a rejection test each, so commit 5 writes A1's and names A4's.
Same standard as the negative fixtures: a hold without a rejection test is a
claim, not a check.

---

## 7. Fixtures per row (§7.5.1 (c)) and commit plan

Every fixture asserts **rejection** with the row id in the test name
(`harness.rs` `assert_refused` / `boundary_pair`); port-as-is rows whose
statement is "does not reject" assert that *no* row fires on the mutated
field, and that the row which *does* fire on the adjacent field is the right
one.

| row | fixture (in `rules/*_tests.rs`, against `MockChain`) |
| --- | --- |
| A2 | *landed as:* `cen_a2_previous_must_be_the_tip_hash` (tip recorded; a flipped bit and the null hash → A2/Block); `cen_a2_genesis_previous_is_the_null_hash` (`None`; `[0;32]` passes, any other refused); `cen_a2_propagates_a_fault_and_does_not_judge` (`FaultingView` → `Err(Faulted)`) |
| B1 | `cen_b1_major_version_must_be_the_admitted_one` — `boundary_pair(1, 2)`, `0` and `255` refused, at `Locus::Block` |
| B2 | `cen_b2_minor_version_is_unconstrained_under_genesis` — `0`, `1`, `2`, `127`, `255` all pass; no row fires |
| B5 | *landed as:* `cen_b5_header_root_is_the_root_at_the_connecting_height` (mutated root → B5); `cen_b5_reads_the_state_at_the_connecting_height_not_the_tips_own` (the header carrying the *tip's* root is **refused** — the SCW-19 off-by-one, bitten from the rules side; it also caught the mock, F5); `cen_b5_genesis_root_is_the_empty_tree`; `cen_b5_above_tip_is_a_refusal_not_a_pass` (a view with no roots) |
| B6 | *landed as:* `cen_b6_identity_is_block_hash_and_records_the_row` — `B6::identity` equals `Block::hash` and inserts exactly its row; the derivation site is the row's function (Q5) |
| B7 | `cen_b7_never_refuses_a_future_version_is_b1s_refusal` — B7 **called alone** passes `major_version ∈ {2, 7, 255}` (the pipeline stops at B1, so this is the only way to observe B7 on such a header — PR #762 review); through the pipeline the same header is refused by **B1**, `assert_refused(.., CenRow::B1, ..)`, never B7 |
| B2 (later set) | `cen_b2_ports_the_predicate_not_the_effect` — under `RuleSet::admitting_for_tests(2)` (a `#[cfg(test)]` crate-private constructor: no second set is issued, and the refusal arm has no other way to run), `boundary_pair(2, 1)` on the vote refuses B2 with the rule alone, and through the pipeline `(major 2, minor 1)` is refused B2 while `(2, 2)` passes — PR #762 review |
| all | `a_well_formed_candidate_passes_and_covers_only_the_landed_rows` (`validate_tests.rs`) — a passing candidate's `coverage().iter()` is `{A2, B1, B2, B5, B6, B7}`; `covers_landed` holds, `is_complete_for` does not. *Records-was:* `slice_1_version_rows_…` at #762 (`{B1, B2, B7}`); `slice_1_rows_are_exactly_what_a_pass_covers` in `header_tests.rs` was the same assertion and is deleted. |

Commit plan (rule 90; each builds, `fmt`/`clippy` clean, tests green).
**Amended 2026-09-16 (maintainer OK at PR #761 review, cross-lane):** commit 1
ships as **its own PR**, cut the day S-CHAIN-R's `chain_reads` PR merges,
because S-CHAIN-R's `RecordedTip { tip: Tip, connect }` composes this crate's
`Tip` and its commit 2 must not wait on Q2–Q6. That PR depends only on Q1
(ruled) and is the one time this slice touches `store/view.rs`. Commits 2–6
stay here behind Q2–Q6.

1. `chain-rules: ChainView::tip() + Tip; BatchView/MockChain/FaultingView impls (Q12-2)` — **own PR** (above); `BatchView` reads through `chain_reads::tip_of`. *Landed* with commits 3–4 folded in (A2, B5, B6 share the harness correction F5), as the `tip()` PR.
   *PR shape, settled 2026-09-16 13:57:* this document lands as the docs PR
   (#761); commit 1 is the `tip()` PR; commits 2–6 are the **rules PR**, cut
   after the `tip()` PR merges (A2 and B5 read the tip). Three PRs, each
   under the 5-day / 10-commit ceiling.
2. `chain-rules: Rule/BlockRule + SCW-18 pin; CEN-B1/B2/B7; RuleSet::header_major_version`
   — commits 2 and 3 of the sketch **landed as one** (rule 26 B5): the traits
   with no rule are dead code at the intermediate SHA, and `-D warnings`
   would need a transient `expect(dead_code)` there that the next commit
   removes — a marker with a one-commit life is noise, not staging. Cut
   before the `tip()` PR on the maintainer's 14:43 ruling: none of these
   reads the tip. Touches one store test (`connect_tests.rs`: coverage gaps
   are now `enforced − implemented`, as the test's own comment anticipated)
   — disclosed to S-CHAIN-R.
3. `chain-rules: CEN-A2 parent-is-tip` — after the `tip()` PR
4. `chain-rules: CEN-B5 header root == root_at(connecting height); CEN-B6 identity under the row`
5. `chain-rules: held_by_cxx(test) entry status; A1/A4 held; gate prints the subtraction` — macro arm, gate grammar + `--selftest`, `RuleSet::enforced` excludes held rows; **plus the C++ core test A1's entry names** (`gen_block_already_known_is_already_exists`; A4's, `gen_block_invalid_prev_id`, already existed — F4 as corrected). Shipped as its own PR before `tip()` (maintainer, 2026-09-16 20:49: nothing in it reads the tip).
*Rule 20, stated in the commit message rather than in a review reply:* these
are C++ tests for code that will be deleted, which reads cold as new C++.
Rule 20 bars new C++ *logic*; a test establishing that the holder actually
refuses is the evidence the `held_by_cxx` status requires, and without it the
status is a grep wearing a test's name (PWD-B10). A5 gains its `subsumed-by` note in the registry comment (no status: it stays `pending` until slice 7 closes it); A6/A7 stay `pending` with the wire-invariant disposition in their registry comment until the wire-format port mints the register and moves the census rows
6. `docs: slice 1 landed — CHAIN_RULES_CRATE.md §13, DRS §7 row + §15, index, FOLLOWUPS F2, CHANGELOG`

Gate figures, dated: *at the pre-flight tip (`3560b80c2`)* `consensus:
implemented 0 / enforced 153`; *after #762* `implemented 3 / enforced 153`
(4.B `3/7`); *after #767* `implemented 3 / validator-enforced 151
held-by-cxx 2   enforced 153   ratified 126 / enforced 153` (4.A `0/7`, held
2); *at slice close (after the `tip()` PR)* `implemented 6 /
validator-enforced 151   held-by-cxx 2   enforced 153   ratified 126 /
enforced 153` — 4.A `1/7` (+2 held), 4.B `5/7`.

---

## 8. Questions for the reviewer — round 1

Each has a default the implementation follows unless ruled otherwise.

**Q1 — `tip()` shape.** **RULED 2026-09-16 (maintainer, PR #761 review;
re-affirmed 13:57 after a same-day contradiction — §2):
`Result<Option<Tip { height, hash }>, Fault>`** — §2 carries the reasoning
(SCR-4's discriminator, refined: absence with caller-actionable semantics
earns a type; an empty chain has none). The round-1 draft's default
was a bespoke `enum Tip { Empty, Recorded {..} }`, withdrawn: it would have
bought nothing over `Option` and cost consistency with the store's own tip
read. No `root` in either shape (one read path to the root cell; SCW-19).
**Two same-day rulings, resolved 13:57 — `Option` stands.** The 13:40 review
approved the round-1 draft's `Tip::Empty` on the `top_block_hash` reasoning;
the maintainer withdrew it: that reasoning does not discriminate (both shapes
make `UINT64_MAX` + `null_hash` unrepresentable; `if let Some(t)` and `if let
Tip::Recorded {..}` are the same ergonomics), and applying the `AtHeight`
pattern without its test is the cargo-culting the 12:55 ruling warned
against. **The discriminator, refined:** a bespoke absence type earns its
keep when its absence case carries *specific semantics the caller must act
on* — `AtHeight::AboveTip` (walk back to the latest key ≤ h) and S-CHAIN-R's
`TreeAfter` (the tree did not grow) do; an empty chain is one behaviour and
`Empty` would carry none. Add that the store's read is already
`Option`-shaped, and it is not close. Both lanes released on `Option<Tip>`,
with `RecordedTip { tip, connect }` composed over it.

**Q2 — the five topology rows (A1, A4, A5, A6, A7).** **RULED 2026-09-16
(maintainer): check the grouping first; mint `held` only under three
conditions.** Grouping done (§4): A6/A7 are **wire invariants** (R8 arm B,
wire holder; re-home to a wire-side invariant register the wire-format port
mints; A7's value is arm C → F2); A5 is **subsumed by the 4.G weight rule**;
only **A1/A4** take the new status, typed **`held_by_cxx(<test>)`** — a
deferral with cutover expiry, holder-*rejects* test not holder-exists grep,
and the third figure printed as the subtraction `validator-enforced = E − H`
with `E` fixed (§4.1). `held(<rust path>)` is not minted (no consumer). The
round-1 draft's single-status default is withdrawn. *Open detail for the
reviewer:* A5's subsumption and A6/A7's re-homing are proposed here from the
R8 test; each moves a census row's disposition, which is a census edit — the
landing PR makes A5's and A6/A7's registry comments say so, and the census
row edits ride with the increments that close them (slice 7; the register's
minting PR), not with slice 1.

**Q3 — CEN-B4 and CEN-A3 out of slice 1.** **RULED 2026-09-16 (maintainer):
approved as two dispositions, not one.** **B4 is DEFERRED** (below, rule 22
clean). **A3 is SUBSUMED-by-B4**: it dissolves into B4's empty-witness arm
and never arrives as its own rule; its row closes when B4 lands. Filed apart
so B4's implementer is not sent looking for an A3 rule that does not exist.
B4's rule-22 record — **blocked on**
a `ChainView` read of the bond `(p_id, pubkey)` pairs, which has no store
table until **E4 S-ARCH**; **falsify by** `rg -n "bond.*pubkey|PidPubkey" rust/shekyl-chain-store/src/schema.rs`
returning a table. **Lands with** slice 8 (4.J archival — the same crate,
`shekyl-archival-retention`, already the Rust body) or with E4, whichever
comes first; `Candidate` gains its `attestation_witness` component there
(`#[non_exhaustive]` was minted for this). A3 dissolves into B4's
empty-witness arm and is registered with it. **The archival side is
greenfield and still iterating** (maintainer, 2026-09-16: "we may have more
than one iteration of design and refine") — so the landing target is named as
*the increment that lands the bond-pubkey read*, not as a fixed slice number,
and B4's shape here (witness as a `Candidate` component, pairs through a
`ChainView` method) is what the census row implies today, to be re-read
against the archival design in force when that increment opens. The falsifier
does not move. Alternative: land B4's
empty-witness half now — rejected: a rule that can only refuse when the
witness is empty and must *fault* when it is not is not a rule, it is the
pre-population special case wearing a row id. Disclosed here and in the
landing commit; `FOLLOWUPS.md` gets the one-liner in commit 6.

**Q4 — `RuleSet::header_major_version`.** **RULED 2026-09-16: default.** a `u8` parameter on
`RuleSet` (`GENESIS` → `1`), read by B1. `CHAIN_RULES_CRATE.md` §4.2 already
names "the header version a rule set admits" as the next parameter. Not
`RuleSetId` (the 1:1 is a fact about today's table; both `compile_fail` pins
stay).

**Q5 — B6 registration.** **RULED 2026-09-16: default** ("a check that
always passes is a gate that cannot fail, which is the one thing this
programme has decided it doesn't ship"). §5: `B6::identity` is the derivation site
`ValidatedBlock::derive` calls; coverage records B6 there. Alternative: a
no-op `check` — rejected as a vacuous pass wearing a row.

**Q6 — SCW-18 pin shape.** **RULED 2026-09-16: default.** §5: entry names a unit-struct type; macro
emits `use path as _` **and** `const _: () = assert!(ROW == variant)`;
`BlockRule::check` with one signature for the slice. Alternative: keep
function paths and bind the row by signature only — rejected by SCW-18 itself
("signature, not identity").

---

## 9. Program ruling: parity, then repair — authority is DRS §7.6 (PR #760)

The 2026-09-16 ruling — the ported partition is transitional; parity is a
phase with a defined end; repairs land after cutover in Rust only (the
CEN-I12 ground: a half-C++/half-Rust repair is two implementations of one
correction); every knowingly-reproduced deviation carries its ratified state
and they share one query, owed to DRS-E2's pre-flight; bucket-4 rows and
reproduced deviations share one denominator; the comparator gates cutover
and `ratified / enforced` gates release — is **recorded once, at
[`DAEMON_REDB_STORE.md`](../design/DAEMON_REDB_STORE.md) §7.6**, minted by the
S-CHAIN-R lane's PR #760 at the same review, with the §8.1 release-gate
checklist item beside it. This document does **not** restate it (an earlier
revision of this PR did, in DRS §7.5.1 and §15; withdrawn 2026-09-16 when
the two lanes synchronised — one ruling, one home). What slice 1 owes to
§7.6 is narrower and is recorded here:

- **Slice 1's port-as-is rows (B2, B6, B7) and F2 are §7.6 item-1 work.**
  The fixture pins the inherited behaviour so the repair round has a
  boundary pair to move, not a read-around to find; F2 is written in the
  three-field form (reproduced / why / what correct looks like) so it moves
  into the one query unchanged when E2 mints it.
- **The crate-side statement of what its two figures gate** is
  [`CHAIN_RULES_CRATE.md`](../design/CHAIN_RULES_CRATE.md) §6.3, pointing at §7.6.
- **Two figures checked against landed text while folding (rule 26 B6),
  reported to the §7.6 owner on PR #760 rather than edited across lanes:**
  (i) §7.6 item 3 says parity evidence "was already defined as `implemented
  == ratified == enforced` (§8.1's E6 item, D12)" — the landed definition
  (DRS §3 provenance: coverage gaps, stubbed applies, passed-through facts all
  empty; §8.1's E6 item: `implemented = enforced`) has **no `ratified` term**;
  the second figure is printed (`ratified 126 / enforced 153` at this tip)
  and gated nothing until §7.6 — the printing is the mechanism, the gate is
  what §7.6 adds. (ii) The enforced-and-unratified consensus figure at this
  tip is **27** (`check_drs_e6_partition.py --describe`, table 1: `b4` = 25
  free + 2 bound; C2-R8 §9.5 recorded 34 → 27); §7.6 item 2 correctly defers
  to the census's own sum-check rather than quoting a number, so nothing to
  change there — recorded so "thirty-four" is not copied from the review
  transcript into any doc.

## 10. What this round did not find (denominator)

No finding against: the scaffold's `AtHeight` shape (B5's `AboveTip` arm is
writable as G11 asks); `RecordedBlock`'s fields (no slice-1 row needs a new
one); the harness (`MockChain` is dense from 0 and already has a tip notion);
the conversion-ban gate (no store type is named by any planned rule); the G1
belt (no new dependency is proposed — B4's `shekyl-archival-retention` edge is
deferred with B4 and its `cargo tree` closure is a slice-8 pre-flight item).
Not examined: 4.C onward; alt-path re-validation (K4/K5 — slice 9 re-enters
these rows over an alt view); the S-CHAIN-R driver's use of `Tip` (that lane's
pre-flight reads this document, not the reverse).
