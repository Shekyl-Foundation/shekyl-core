# `shekyl-chain-rules` slice 1 — census 4.A + 4.B (DRS-E6 increment 2)

**Status:** OPEN — **round 1 = pre-flight (rule 26 Round 0), written
2026-09-16** against `dev` @ `3560b80c2` (S-CHAIN-W landed, PR #757). **Q1
RULED 2026-09-16 (§2); Q2–Q6 (§8) open. No production commit lands until they
are ruled** — rule 26's halt condition, cited here on purpose. §9 points at
DRS §7.6 (PR #760), the same-day parity-then-repair ruling, and records what
slice 1 owes to it. Template: [`CHAIN_RULES_CRATE.md`](CHAIN_RULES_CRATE.md)
§7.5.1 (the increment's pre-flight names its parents, audits each row's body,
lists the fixture per row). Parent plan: [`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md)
§7.5 (table 3 row "slice 1"). Cites `26-sub-pr-design-discipline.mdc`
(A2 audit-against-actual-code, B5 per-commit cleanliness, B6 numeric
verification, the review-round denominator).

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
| S-CHAIN-W: `BatchView: ChainView`, `connect`, `root_at(h)` = key `h` | `tip()` gets a store implementor in the same PR; B5's read | LANDED PR #757 | `rust/shekyl-chain-store/src/store/view.rs:155–234`; `connect.rs:280–320` |
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

- **`height`** — justified by B1 (the rule set in force is `rules_at(height)`)
  and B5 (`root_at(connecting height)`); later by 4.C and CEN-F5 (the
  caller-derived height operand the census names against `txin_gen.height`
  spoofing, census 4.F notes).
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
  `cen_a2_genesis_previous_is_zero` and `cen_b5_genesis_root_is_empty` (§7)
  both refuse a wrong genesis, so a rule that forgot the arm is red.

**Connecting height** is a crate-private helper, `fn connecting_height(tip:
Option<&Tip>) -> BlockHeight` (`None → 0`, `Some(t) → t.height + 1`), used
by every height-indexed rule so the operand is derived once from the view and
never from the candidate (F5's spoof).

**Store side, same PR — sequenced with S-CHAIN-R.** `BatchView` today has a
private `fn tip() -> Result<Option<u64>, StoreError>` (`view.rs:97–108`)
reading `block_info.last()`. S-CHAIN-R's commit 1 (`DRS_E1_SCHAIN_R.md` (PR #760, not yet on `dev` — linked at landing)
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
have drifted by ~15 lines in `blockchain.cpp`). *class*: **rule** = a predicate
`validate` evaluates and lands here; **adopt** = Rust body exists, wrapped;
**topology** = an acceptance-path outcome or ingest bound that is not a
predicate over `(Candidate, recorded chain)` — Q2; **deferred** — Q3.

| row | b | C++ body (this tree) | Rust body | class | view read | disposition |
| --- | --- | --- | --- | --- | --- | --- |
| CEN-A1 | 2 | `have_block_unlocked` `blockchain.cpp:3011–3041`: main (`block_exists`) ∪ alt (`get_alt_block`) ∪ `m_invalid_blocks`; consumer `add_new_block` `:6338–6343` → outcome byte `ALREADY_EXISTS`, `return false` | — | **topology** | none possible: two of the three stores are not recorded-chain facts, and the outcome is not `InvalidBlock` | Q2 |
| CEN-A2 | 2 | routing `:6346–6355` (`prev_id == get_tail_id()` → main, else alt); **re-check** `:5423–5428` `bl.prev_id != top_hash` → `reject_block_internal` | store **belt** SI-2 `TipMismatch` `connect.rs:303` | **rule** (the re-check); routing is the driver's | `tip()` | lands: `previous == tip.hash`; at `None` (empty chain), `previous == [0; 32]` |
| CEN-A3 | 1 | 2-arg `add_new_block` guard `:6320–6322`: `attestation_root == empty_attestation_root()` or assert | `shekyl_archival_retention::empty_attestation_root` | **deferred with B4** | — | the guard is about a C++ *overload* ("a caller dropped the witness"); once `Candidate` carries the witness there is no witness-less entry and A3 is B4's empty-witness arm. Q3 |
| CEN-A4 | 2 | orphan marking `:2462–2464` in `handle_alternative_block`: parent in neither main nor alt → `ORPHANED`, not stored | — | **topology** | alt-store membership is not a recorded-chain fact (E5 S-ALT) | Q2 |
| CEN-A5 | 4 | `cryptonote_core.cpp:1450` `block_blob.size() > cumulative_block_weight_limit + BLOCK_SIZE_SANITY_LEEWAY (100, :71)` — **pre-parse** | — (`shekyl_wire::MAX_BLOCK_BLOB_SIZE` is a parse-DoS cap, `block.rs:48`, a different bound) | **topology** (ingest) | operand is 4.G state (the weight limit) | Q2; a slice-7 dependency if it ever becomes a predicate |
| CEN-A6 | 4 | `cryptonote_core.cpp:1381` parse failure rejects | `shekyl_wire::Block::from_bytes` (exact consumption, `block.rs:186–206`) | **topology** (wire boundary) | `validate` takes a parsed `Block`; the parse is `BLOCK_TX_WIRE_FORMAT_PORT.md`'s subject | Q2 |
| CEN-A7 | 4 | `cryptonote_basic.h:914` `tx_hashes.size() > 0x10000000` fails (de)serialization | `Block::read` caps `n_tx` at `READ_LEN_CAP = 1_000_000` (`lib.rs:67`, `block.rs:162–167`) | **topology** (wire boundary) | — | Q2; **value divergence** recorded, §6 F2 |
| CEN-B1 | 2 | `:5445` `m_hardfork->check(bl)` → `do_check` `hardfork.cpp:109–113`: `major == heights[cur].version && vote ≥ version`; alt `check_for_height` `:121–126` (ideal at height) | — | **rule** | none (the rule set is an input) | lands: `header.major_version == rule_set.header_major_version()` — a new `RuleSet` parameter, Q4. The alt arm collapses: the caller passes `rules_at(height)` |
| CEN-B2 | 4 | `hardfork.cpp:41–50` vote normalisation (`minor 0 → 1`); `vote ≥ 1` unfailable | — | **rule, port-as-is** | none | lands: evaluates, never refuses; coverage records B2 |
| CEN-B3 | 4 | — | store belt `hf_versions[h]` `connect.rs:387` | **out** — surface-bound, table 2 (S-CHAIN-W) | — | not this slice |
| CEN-B4 | 1 | `:5463–5470` `verify_block_attestation(bl, predecessor_height, …, witness)` → FFI `shekyl_archival_verify_attestation` with `ShekylArchivalAttestationVerifyCtx { predecessor_height, anchor_hashes[L+1], headers, pairs(p_id, pubkey) }` | `shekyl-ffi/src/archival_ffi/attestation.rs:117–164`; `shekyl-archival-retention::attestation_wire` | **deferred** | `block_at` for the anchor window (landed); **bond `(p_id, pubkey)` pairs — no table, no view method until E4 S-ARCH**; the witness is not a `Candidate` component | Q3 |
| CEN-B5 | 1 | `:5579–5591` `bl.curve_tree_root != m_db->get_curve_tree_root()` (tip root = state at the connecting height) → `reject_block_form` | store `root_at(h)` key `h` (`view.rs:216–233`) | **rule** | `tip()`, `root_at(connecting_height)` | lands: `Recorded(root) if root == header.curve_tree_root` passes; else refuses; `AboveTip` refuses (unreachable against a conforming view — SI-4 keeps `tip + 1` recorded — written as the fail-closed arm G11 requires) |
| CEN-B6 | 4 | `get_block_hashing_blob` (cryptonote_format_utils) | `shekyl_wire::Block::hash` (`block.rs:217–247`); KAT `coinbase_hash.rs` | **adopt** | none | lands: the identity derivation site moves behind the row's function (Q5) |
| CEN-B7 | 4 | `:5431–5441` one-time `MCLOG_RED` warning if `major > get_ideal_version()`; **no reject** | — | **rule, port-as-is** | none | lands: evaluates, never refuses; the log side-effect is not ported (the crate has no logging, G12) — recorded, not hidden |

**Denominator of this audit:** all 13 rows of 4.A/4.B were read at their C++
site in this tree and, where a Rust body was claimed, at the Rust site. Nothing
outside 4.A/4.B was examined for slice 1; 4.C–4.M are the later slices'.

---

## 4. The registration gap (Q2) — what the audit surfaced

`census_rows!` knows two statuses: `pending` and `implemented(path)`
(`census.rs:91–111`). `RuleSet::GENESIS.enforced == CenRow::ALL` (153), and
`Coverage::is_complete_for` is true only when every enforced row is in
coverage. Five slice-1 rows can **never** be in coverage because `validate`
cannot evaluate them; so with the registry as it stands, `is_complete_for` is
permanently false and *no* `ChainValid` is ever parity evidence — which is
true today and would stay true after all 141 free rows land. The gap is not
slice-1-specific: table 2's CEN-H5 ("dissolves into `ValidatedBlock`'s typed
input `enum`") and CEN-B3 ("the surface; body as R4 rules") already have no
representable status either. Slice 1 is the first increment where it bites.

Options, with the proposed default first:

**(a) — default — a third entry status, `held(<holder>)`.** The row is
enforced, but by a **named component that is not this validator**, and is
therefore excluded from `RuleSet::enforced` (the parameter that already
exists for "the rows this rule set holds a block to"). The gate prints a third
figure, `held H`, beside `implemented I` and `enforced E`, with `E` unchanged
(the census denominator does not move) and completeness measured over
`enforced − held`. Rule 47: every `held(...)` names a holder that **exists** —
a Rust path is compile-pinned exactly like `implemented` (`use $path as _`);
a C++ holder is a `file:token` the gate greps for. Slice 1's five: A6, A7 →
`held(shekyl_wire::Block::from_bytes)`; A1, A4 → `held("src/cryptonote_core/blockchain.cpp:have_block_unlocked")`
/ `…:handle_alternative_block`; A5 → `held("src/cryptonote_core/cryptonote_core.cpp:BLOCK_SIZE_SANITY_LEEWAY")`.
Falsifier for each C++ holder: the daemon-driver rewrite that re-homes it
(the token disappears → gate red → the row is re-classified then).
*Cost:* macro arm, gate grammar + selftest, one `RuleSet` field. *Why not
just leave them `pending`:* "pending" reads as *owed to this crate*; these are
not, and a queue that says they are will have someone write an `ingest()`
here to clear it.

**(b) — leave `pending`, accept `is_complete_for == false` until the daemon
driver is Rust.** Honest but silent: the five rows are indistinguishable from
the 128 that *are* owed here, and the parity-evidence bit stays dark for the
whole E-series for a reason nobody can read off the gate.

**(c) — widen the crate:** `ingest(blob) -> Verdict<Candidate>` (A5, A6, A7)
and `route(candidate, view) -> Route` (A1, A2-routing, A4). **Rejected by this
pre-flight** for A1/A4: they need alt-store and invalid-set membership, which
are not recorded-chain facts, so `ChainView` would grow methods that violate
Q3's "recorded chain only" and the mock stops being smaller than the store.
`ingest` is arguable for A6/A7 but adds an entry point whose only body is a
call into `shekyl-wire` — a shim.

---

## 5. SCW-18 — `trait Rule { const ROW }`, the first real rule's shape (Q6)

```rust
// rules/mod.rs
pub(crate) trait Rule {
    const ROW: CenRow;
}
/// Block-level rules of this slice: one signature, so `validate` runs them
/// from a list and records `R::ROW` itself — a rule cannot record another
/// row's coverage.
pub(crate) trait BlockRule: Rule {
    fn check<'id, V: ChainView<'id>>(
        candidate: &Candidate, tip: &Tip, view: &V, rule_set: &RuleSet,
    ) -> Result<Verdict<()>, V::Fault>;
}
// census.rs — the entry names a TYPE; the macro emits both pins:
//   use $path as _;                                              (G9: exists)
//   const _: () = assert!(<$path as Rule>::ROW as u8 == CenRow::$var as u8); (SCW-18: is this row)
A2 implemented(crate::rules::topology::A2),
```

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

**F2 — CEN-A7's bound is not the Rust parser's bound.** C++ refuses
`tx_hashes.size() > 0x10000000` (2^28); `shekyl_wire::Block::read` refuses
`n_tx > READ_LEN_CAP = 1_000_000` (`lib.rs:67`). Both are structural parse
bounds; the values differ by ~268×. Not a slice-1 rule (A7 is topology) and not
a consensus divergence today (no block approaches either), but it is exactly
the "value has no derivation record" the census row already flags, now with a
second undocumented value beside it. **This is a knowingly-reproduced
deviation** in the sense of DRS §7.6 item 1 (the parity phase reproduces; the
repair phase judges — §9), so it is recorded in the form every such deviation must carry —
*what we reproduced, why, and what correct looks like:* reproduced — two
structural bounds on one field, 2^28 (C++) and 10^6 (Rust), neither derived;
why — parity first, and no block approaches either; **correct** — one
constant, one derivation record (a per-block tx-count bound derived from the
block-weight limit, or ruled unbounded-below-weight), owned by the wire-format
port. **Route (A5 carry):** one `FOLLOWUPS.md` line in this PR's doc commit
carrying those three fields, Target pre-genesis, falsifier "one constant with
a derivation record, or the divergence ruled"; it migrates into the unified
repair backlog when E2 mints that artifact (DRS §7.6 item 1) — the row is written so the
migration is a move, not a rewrite.

**F3 — the store already holds A2's belt but nothing holds A2's rule.**
`connect.rs:303` refuses `previous != tip.hash` as SI-2 `TipMismatch`
(fatal, poisons the batch). Until A2 lands here, the S-CHAIN-R driver would
route a wrong-parent block into a fatal. Not a defect — the belt is doing what
a belt does — but it makes A2 the first rule to land, before any driver
connects real blocks.

---

## 7. Fixtures per row (§7.5.1 (c)) and commit plan

Every fixture asserts **rejection** with the row id in the test name
(`harness.rs` `assert_refused` / `boundary_pair`); port-as-is rows whose
statement is "does not reject" assert that *no* row fires on the mutated
field, and that the row which *does* fire on the adjacent field is the right
one.

| row | fixture (in `rules/*_tests.rs`, against `MockChain`) |
| --- | --- |
| A2 | `cen_a2_previous_must_be_the_tip_hash` (tip recorded; `previous` ← other hash → A2/Block); `cen_a2_genesis_previous_is_zero` (`Empty`; `[0;32]` passes, any other refused); `cen_a2_propagates_a_fault` (`FaultingView`) |
| B1 | `cen_b1_major_version_must_be_the_admitted_one` — `boundary_pair(1, 2)` and `0` refused, at `Locus::Block` |
| B2 | `cen_b2_minor_version_is_unconstrained` — `0`, `1`, `255` all pass; no row fires |
| B5 | `cen_b5_header_root_is_the_root_at_the_connecting_height` (mutated root → B5); `cen_b5_reads_tip_plus_one_not_tip` (a chain whose root at `tip` ≠ root at `tip+1`: the header carrying the *tip's* root is **refused** — the SCW-19 off-by-one, bitten from the rules side); `cen_b5_genesis_root_is_empty`; `cen_b5_above_tip_refuses` (a mock with no root at `tip+1`) |
| B6 | `cen_b6_identity_is_block_hash` (already `validate_tests.rs`; re-homed under the row) |
| B7 | `cen_b7_never_refuses` — `major_version = 2` is refused by **B1**, `assert_refused(.., CenRow::B1, ..)`, never B7 |
| all | `slice_1_coverage_names_exactly_its_rows` — a passing candidate's `coverage().iter()` is `{A2, B1, B2, B5, B6, B7}`; `covers_landed` holds |

Commit plan (rule 90; each builds, `fmt`/`clippy` clean, tests green).
**Amended 2026-09-16 (maintainer OK at PR #761 review, cross-lane):** commit 1
ships as **its own PR**, cut the day S-CHAIN-R's `chain_reads` PR merges,
because S-CHAIN-R's `RecordedTip { tip: Tip, connect }` composes this crate's
`Tip` and its commit 2 must not wait on Q2–Q6. That PR depends only on Q1
(ruled) and is the one time this slice touches `store/view.rs`. Commits 2–6
stay here behind Q2–Q6.

1. `chain-rules: ChainView::tip() + Tip; BatchView/MockChain/FaultingView impls (Q12-2)` — **own PR** (above); `BatchView` reads through `chain_reads::tip_of`.
2. `chain-rules: Rule/BlockRule traits; census_rows! emits the SCW-18 ROW pin`
3. `chain-rules: CEN-A2 parent-is-tip; CEN-B1/B2/B7 header version rows` (+ `RuleSet::header_major_version`, Q4)
4. `chain-rules: CEN-B5 header root == root_at(connecting height); CEN-B6 identity under the row`
5. `chain-rules: held(...) entry status + gate figure` — **only if Q2 rules (a)**; else this commit is the `pending` disclosure in the doc
6. `docs: slice 1 landed — CHAIN_RULES_CRATE.md §13, DRS §7 row + §15, index, FOLLOWUPS F2, CHANGELOG`

Gate figure expected after commit 4 (verified shape from `--describe` at this
tip: `consensus: implemented 0 / enforced 153`): `implemented 6 / enforced
153`, 4.A `1/7`, 4.B `5/7`; with (a), `held 5`.

---

## 8. Questions for the reviewer — round 1

Each has a default the implementation follows unless ruled otherwise.

**Q1 — `tip()` shape.** **RULED 2026-09-16 (maintainer, PR #761 review):
`Result<Option<Tip { height, hash }>, Fault>`** — §2 carries the reasoning
(SCR-4's discriminator; the two C++ sentinels). The round-1 draft's default
was a bespoke `enum Tip { Empty, Recorded {..} }`, withdrawn: it would have
bought nothing over `Option` and cost consistency with the store's own tip
read. No `root` in either shape (one read path to the root cell; SCW-19).

**Q2 — the five topology rows (A1, A4, A5, A6, A7).** Default §4 (a):
`held(<holder>)` status, excluded from `RuleSet::enforced`, third gate figure,
holder existence asserted. Alternatives (b) leave `pending`; (c) widen the
crate. This is the load-bearing ruling: it decides what "141 surface-free rows
are E6's" means for every later slice (H5, and 4.K's routing rows, are the
same class).

**Q3 — defer CEN-B4 and CEN-A3 out of slice 1.** Rule 22 shape: **blocked on**
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

**Q4 — `RuleSet::header_major_version`.** Default: a `u8` parameter on
`RuleSet` (`GENESIS` → `1`), read by B1. `CHAIN_RULES_CRATE.md` §4.2 already
names "the header version a rule set admits" as the next parameter. Not
`RuleSetId` (the 1:1 is a fact about today's table; both `compile_fail` pins
stay).

**Q5 — B6 registration.** Default §5: `B6::identity` is the derivation site
`ValidatedBlock::derive` calls; coverage records B6 there. Alternative: a
no-op `check` — rejected as a vacuous pass wearing a row.

**Q6 — SCW-18 pin shape.** Default §5: entry names a unit-struct type; macro
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
[`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) §7.6**, minted by the
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
  [`CHAIN_RULES_CRATE.md`](CHAIN_RULES_CRATE.md) §6.3, pointing at §7.6.
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
