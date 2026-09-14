# `SO-D8` — ruling-round proposal: cross-epoch admission and the settlement writer's production caller

**Status:** OPEN — **PROPOSAL, not a ruling.** Drafted 2026-09-13 for Rick's
ratification. Nothing in this file is authority until the disposition table in
§9 is stamped RULED; until then `ARCHIVAL_SETTLEMENT_WRITER.md` §12's rule-22
hold on the writer's call site **stands** and this document does not route
around it. No admission code, no consensus code, and no writer call site were
written for this round (Slices A and B of the 2026-09-13 brief were authorized;
Slice C — implementation — was not, and §8 is its plan, not its work).

**Grounded at** `dev@37accf6f` (fresh worktree `~/shekyl/wt-so-settlement`,
branch `feat/so-a-settlement-surface` carrying the three Slice-A commits
`cf09d6f3e`, `dc070a985`, `a6f602d33`). Every `file:line` below was read at
that tree on 2026-09-13; where a line number is quoted from an older document
it is marked as such.

**Process:** [`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc).
No new identifier family is minted: sub-dispositions here are `SO-D8a`…`SO-D8e`,
which parse under the registered `SO-` prefix (rule 94 §1) and are folded back
into `ARCHIVAL_SETTLEMENT_WRITER.md` §12/§13 when ruled. This file then
archives per rule 95.

---

## 0. What this round was opened to rule, quoted

`ARCHIVAL_SETTLEMENT_WRITER.md` §12 (2026-08-24):

> Under derived assignment a challenge issued in the epoch's last `W₂` blocks
> resolves *after* `h_close`, so its response names epoch `E` while landing in
> `E+1`'s blocks. […] What is genuinely open is the arithmetic at the boundary:
> a response naming `E` admitted during `E+1`, and what dedup and the emission
> gather do with it.

The brief's five items: (a) boundary arithmetic, (b) dedup at
`blockchain.cpp:5156`, (c) emission-gather handling of cross-epoch records,
(d) `passes > issued` after relaxing the deadline, (e) the `assign_epoch` FFI
shape.

**§1 finds that `SO-D8`'s premise stands, and that the round has MORE to rule
than §12 listed, not less.** A record naming `E` is fully representable in a
block of `E+1`; exactly one live consensus rule refuses it today (the C++
`h_close` gate), and the "ruled per-challenge deadline" §12 proposed
re-pointing that gate at **does not exist in code**. §2 states the two shapes
the ruling can take; item (e) is where the implementation work is under either.

> **CORRECTED 2026-09-13 (Rick's review of the first cut, same day).** The
> first cut of this section claimed the premise was *"unrepresentable on the
> frozen wire and refused by two live gates"* and that items (a)–(d)
> *dissolve*. That rested on reading `ERR_EPOCH_MISMATCH` as a check of the
> record's epoch against the block's. **It is a tautology** — SO-D9 below — and
> once it is removed from the argument the dissolution does not survive. The
> wrong finding is struck here rather than deleted because an agent that read
> the first cut will otherwise build against it; the class is recorded in
> §1.2. The reviewer's walk is the authority for this correction; every line
> anchor was re-read at the tree before the text was changed.

---

## 1. Findings F1 and SO-D9 — what actually binds a record, read at the admission path

### F1 — the wire binds a record to the block it rides in, and to a **prover-declared** epoch

| # | Binding | Where | Holds? |
|---|---|---|---|
| 1 | Nonce `H(block_hash(h−1) ‖ cb_out_key(h) ‖ P ‖ s ‖ E)` — `prev_block_hash` and `cb_out_key` populated from **the block being validated** | `blockchain.cpp:5504` (`cb_out_key` from `b.miner_tx`), `:5515` (`b.prev_id`); `attestation_wire.rs:79–80` | **Yes.** A countersignature made for block `h` verifies in no other block. |
| 2 | `PC-D3`: `challenge_leaf_index(P, s, E, prev_block_hash, …)` derived from the including block's predecessor | `serve_credit.rs:172–200` | **Yes.** The leaf a record opens is drawn by the block it rides in. |
| 3 | Kept header is `p_id ‖ shard_id ‖ settlement_epoch ‖ kind` — no issuing height, no claimed block | `attestation_wire.rs:92–97` | **Yes.** There is no field in which a record names an issuing `h`. |
| 4 | `settlement_epoch` in that header is **written by the prover** and parsed by C++ at `get_archival_serve_credit_key` | `blockchain.cpp:5124` | **Yes** — and this is the row the first cut missed: **nothing in rows 1–3 ties `E` to the including block's epoch.** |
| 5 | The only live rule relating `E` to the block's height: `if (current_height > h_close(E)) reject "past credit deadline"` | `blockchain.cpp:5186–5190` (C++, reachable, per-epoch); duplicated Rust-side as `ERR_CREDIT_DEADLINE`, `serve_credit.rs:211–212`, unreachable only because C++ refuses first | **Yes.** This is *exactly* the gate §12 named. |

So: a record for `(P, s, E)` **can** ride a block of `E+1` — its nonce and leaf
are bound to *that* block, its `E` is whatever the prover wrote — and is
refused today by row 5 alone. `SO-D8` §12 stands as written.

### `SO-D9` — `ERR_EPOCH_MISMATCH` is a check that cannot fire (filed as its own finding)

`serve_credit.rs:168–169` refuses when `response.settlement_epoch !=
ctx.settlement_epoch`. `ctx.settlement_epoch` is populated at
`blockchain.cpp:5304` from `sc_settlement_epoch` — **the value parsed out of
the same record at `:5124`**. `shekyl_archival_verify_serve_credit_vin` has one
production caller (`:5315`). The check compares the record against a copy of
itself and refuses nothing.

Second instance of rule 50's *"checks that cannot fail"* class in this arc.
Filed in `docs/FOLLOWUPS.md` independently of how `SO-D8` resolves, because a
tautological consensus check is a defect whether or not this round makes it
load-bearing. Two dispositions, one of which is a consensus tightening and is
therefore **Rick's**:

- **(i) Make it fire:** populate `ctx.settlement_epoch` from
  `shekyl_archival_settlement_epoch_at_height(current_height)`
  (`shekyl_ffi.h:2594`, exists) — one C++ line — so *"the record's epoch is the
  including block's epoch"* becomes an explicit enforced rule. Reviewer's
  preference, and this proposal's: it is the check the round needs once
  assignment is derived (`SO-D8b`).
- **(ii) Delete it** and let the row-5 `h_close` gate be the single expression.

### 1.1 What is true about `W₂`, and why it makes the round larger

`CHALLENGE_RESPONSE_BLOCKS` has **no admission consumer** — verified:
`constants.rs:171`, `:183–185`, `:194–195` are const-asserts and `lib.rs:139`
is the re-export; nothing else reads it. Its doc string — *"blocks after a
challenge's issuing block to accept its serve-credit response"*
(`constants.rs:59`) — describes a gate that does not exist. **There is no
per-challenge deadline anywhere in code.**

This does not shrink `SO-D8`; it removes its escape hatch. §12's argument was
*"the ruled per-challenge deadline already exists and is per-challenge"*, so
the `h_close` gate could simply be re-pointed at it. It does not exist. Under
shape R-B (§2) the round must **design** that deadline, not re-point to it.

`SO-D7`'s lag argument (*"a challenge drawn at epoch-relative block 9,999
resolves 500 blocks into `E+1`"*, `IMPLEMENTATION_INDEX.md` SO row) reads the
same doc string as a mechanism. It describes shape R-B, which is one of the
two things this round can rule — not a property the tree has.

### 1.2 The class, recorded

The first cut framed itself as *"the fourth dissolve-on-grounding in the SO/RF
arc"* (`RF-D3`, the W₂ floor, the Pi-4 question). Those three were real. The
review's point, adopted here: **pattern-matching to them is plausibly how this
one got written.** A round that has logged three constraints dissolving at
source arrives at the fourth expecting a fourth, and reads a check whose
**shape** looks load-bearing (a comparison, an error code, a refusal path)
without reading where its **operands** come from — which is reading the doc
string one level down. A prior in favour of dissolution is not evidence for
it; the class this instance belongs to is *finding what one came to find*, and
it is recorded under that name rather than as a fifth member of the other.

Two operational rules this adds: **for every refusal cited as a binding, name
the source of each operand**; and **when a finding matches a class the round
has already logged three times, that match is a reason to re-check, not a
reason to stop.**

---

## 2. The two shapes the ruling can take

Neither is "what the tree is". The tree today is the interim beacon: one
challenge per pair-epoch, response accepted anywhere in `(h_fire, h_close]`,
epoch prover-declared. Derived assignment replaces that, and the replacement
must pick one of:

| | **R-A — same-block** (`PC-D2`'s shape, made an enforced rule) | **R-B — post-issuance window** (`W₂`'s doc string, `SO-D7`, `SO-D8` §12) |
|---|---|---|
| Record answers the challenge of | the block it rides in: `(P,s) ∈ assignment(h_incl)` and `E = epoch(h_incl)` | an issuing block `h < h_incl ≤ h + W₂`, which the verifier must identify |
| How `E` is bound to the block | **SO-D9 (i)**: `ctx.settlement_epoch` from height — a consensus tightening, one C++ line | replaced by `epoch(h) == E` where `h` is the issuing block |
| How `h` is identified | it is `h_incl`; nothing to identify | **new**: a header field naming `h`, or a verifier-side search of `assignment(E)` for `(P,s)` disambiguating among up to `λ` draws — either way a change to a **genesis-frozen surface** (`RF` round closed 2026-08-21) and the nonce must rebind to `cb_out_key(h)` / `block_hash(h−1)` of the *issuing* block |
| `h_close` gate (`blockchain.cpp:5186`) | stays; redundant with SO-D9 (i) and kept as defence in depth (`SO-D8a`) | replaced by a **per-challenge** deadline that must be **designed** (§1.1) |
| Dedup (`blockchain.cpp:5156`) | one record per `(P,s,E)` per block is **exact** — the urn draws without replacement within a block | must key on `(P,s,E,h)`: two records answering different draws may share a block |
| Emission gather at `h_close(E)` (`db_lmdb.cpp:8411`) | **complete** — every record for `E` is in `E`'s blocks | **incomplete** — records for `E` land up to `W₂` into `E+1`; the writer round's *"emission timing is untouched by the lag"* (verified against the gather's read set, not its timing) becomes **false**, and the gather must move to the slash pass or re-run. **§12 did not price this.** |
| `passes > issued` | unreachable once the membership gate lands | reachable only through the same missing gate |
| `SO-D7` writer home | slash pass, for the reasons `SO-D7` gave (ascending order, existing revert) | slash pass, and emission must join it |
| Cost R-A carries and R-B does not | fetch latency sits **inside block production**: a miner that cannot fetch `~97` segments (§6) within the block interval omits records (draws fall to non-observation) or delays its block; every pool attempting `h` fetches the same pairs from `P` concurrently — a thundering-herd shape `PC-D2` chose the implicit-block design specifically to avoid arbitrating. **Q1, Rick's.** | the witness has `W₂` blocks |

**Recommendation: R-A, as a ruling, not as a description.** It is `PC-D2`'s
shape; it touches no frozen byte; its consensus delta is two gates (SO-D9 (i) and
the membership gate), both tightenings; and items (a)–(d) are *ruled* by it
rather than dissolved. R-B re-opens a closed wire round, designs a deadline
that has never existed, and moves the emission gather. The cost of R-A is Q1,
and this proposal does not decide it.

---

## 3. `SO-D8a` — boundary arithmetic and the two deadline gates

**Proposed under R-A: the boundary rule is `E = epoch(h_incl)`, enforced by
SO-D9 (i).** Issuance at epoch-relative block 9,999 is answered in block 9,999 or
falls to non-observation for that draw. Nothing straddles *by rule* — where the
first cut said *by construction*.

The gates at `serve_credit.rs:208–212` and their C++ twin:

- `ERR_FIRE_NOT_REACHED` (`current_height <= h_fire`) — the single-beacon fire
  height. **Dies with the beacon**; replaced by the membership gate (`SO-D8b`).
- `ERR_CREDIT_DEADLINE` / C++ `h_close` gate — **keep, untouched** (Q5,
  answered by the review). It is a live C++ rule with a Rust defence-in-depth
  duplicate; the duplicate is unreachable only because C++ refuses first,
  which is the correct relationship for a duplicate. The first cut proposed
  deleting it on the ground that the tautology made it unreachable —
  inverted: the vacuous check is `EPOCH_MISMATCH`, not this one.
- `ERR_EPOCH_MISMATCH` — SO-D9 (i) or (ii). Under R-A, (i).

Consensus-visibility: SO-D9 (i) and the membership gate both shrink the accepted
set. Both are consensus changes and belong to the §5 atomic cutover.

## 4. `SO-D8b` — dedup at `blockchain.cpp:5156` and the membership gate

**Proposed: dedup unchanged; add the gate `PC-D7` kept alive.**

- Dedup today: one serve-credit vin per `(P,s,E)` per block
  (`serve_credit_preblock_duplicate`, mirrored in
  `serve_credit_decisions.rs`). Under R-A that is **exact**, because a pair is
  drawn at most once per block (without-replacement within `advance_block`).
  No change.
- **New gate, consensus-visible:** a record for `(P,s,E)` in block `h` is
  admitted only if `(P,s) ∈ assignment(h)`. This is the *count bound* and the
  *anti-adaptive-selection* check `PC-D7` names. Without it a miner colluding
  with `P` includes two pass records for `P`'s own pair in blocks it mines —
  regardless of whether the urn ever drew the pair — and settles **Served**
  with zero honest draws. With it, a collusive pass costs a *won block at an
  assigned height*, which is the 2-of-3 quadratic's pricing assumption.
- Cost: answering `(P,s) ∈ assignment(h)` needs the urn state at `h`. See
  `SO-D8e` — this is why the FFI shape is the real item.

## 5. `SO-D8c` — emission gather

**Proposed: unchanged under R-A.** `gather_archival_epoch_rows` at
`process_archival_epoch_close_at_height` (`db_lmdb.cpp:8411`) walks
`m_archival_serve_credit` for epoch `E` at `h_close(E)`; under R-A every record
for `E` is already in the table. `PC-D6`'s fold (one credit per pair-epoch,
`:8195`) stands. **Noted, not opened:** emission credits on *presence* (`≥ 1`
pass, `PC-D6` *"three passes credit a pair once"*) while settlement slashes on
absolute-2; `PC-D6` says *"no economic disposition opens"* and this proposal
does not open one — it is recorded so the next reader does not rediscover it
as a bug.

Under R-B this item is the largest change in the round (§2 row 6); that is the
principal reason to prefer R-A.

## 6. `SO-D8d` — `passes > issued`

**Proposed: unreachable once `SO-D8b`'s membership gate and SO-D9 (i) both hold;
kept as a typed refusal that is FATAL at settlement, never clamped.** Both
gates are needed: without SO-D9 (i) a record can carry a stale `E` into a block of
`E+1` and, if admitted, count as a pass for `E` after `issued(E)` was fixed.
`settle_epoch` (`attestation.rs:142–145`) already returns
`SettleError::MorePassesThanIssued`; `SettlementRow::settle`
(`settlement_row.rs:150`) refuses to compose a row. The writer maps that to a
FATAL (`db_lmdb.cpp` `set_archival_settlement` throws) rather than `min(passes,
issued)`: a clamp converts the collusion of `SO-D8b` into **Served**, silently,
which is the one outcome the check exists to prevent. This is rule 50's
"a check that cannot fail" in its useful form — the check is unreachable only
while the gate holds, and the FATAL is the alarm that it stopped holding.

## 7. `SO-D8e` — the `assign_epoch` FFI shape (the real item)

### 7.1 Two consumers, two cadences

| Consumer | Question | Cadence | Cost if answered by pure replay (`assign_epoch`) |
|---|---|---|---|
| Admission (`SO-D8b`) | `(P,s) ∈ assignment(h)`? | **every block** | replay from `h_open(E)` to `h`: `O(draws so far)` — at maturity up to 972,000 cSHAKE draws **per block** |
| Settlement writer (`SO-D1`) | `issued(P,s,E)` for every pair | once per epoch, in the slash pass | one full replay: 972,000 draws |

Measured 2026-09-13, release, this host (`measure_full_epoch_replay_cost_at_maturity`,
`challenge_assignment.rs:534–556`): **1.09 s for 972,000 draws.** Per rule 76
the provisioning floor is the Pi 4, not this host; the Pi-4 figure is **owed**,
not estimated here. Even at this host's speed, ~1 s of pure derivation per
block on the admission path is not acceptable; per epoch in the slash pass it
is.

### 7.2 Proposed shape: a Rust-owned, in-memory, sequentially-fed urn with checkpoints

**Rust owns the urn; nothing else does.** `ChallengeUrn` already is the
sequential form (`advance_block(prev_hash)` per block, `draws_done()`;
`challenge_assignment.rs:131–255`, `advance_block` at `:211`). The proposal is a wrapper type in
`shekyl-archival-retention`, no new crate:

```text
EpochAssignmentCache  (derived state; NEVER persisted — SO-D3 derive-don't-store)
  open(E, drawable_pairs_at_h_open)                        // fresh urn; λ = CHALLENGES_PER_PAIR_PER_EPOCH, not a parameter (Q4)
  advance(prev_hash) -> &[DrawablePair]                    // assignment(h); O(λ·pairs/SEB) per block
  is_assigned(h, P, s) -> bool                             // admission gate, O(1) after advance
  issued_histogram() -> impl Iterator<(DrawablePair, u32)> // writer input at settlement
  checkpoint() / rewind_to(checkpoint)                     // pop_block, no replay for shallow reorgs
```

- **Precedent:** `ArchivalSealHashCache` — derived, in-memory, rebuilt from
  chain on restart, the pattern `SO-D3` named.
- **Reorg:** `pop_block` rewinds to the checkpoint at the popped height; a
  reorg deeper than the retained checkpoints replays from `h_open(E)` (bounded
  by one epoch = 1.09 s here). `SO-D6` already deletes settlement rows on
  revert; the cache follows the same height.
- **Restart mid-epoch:** replay from `h_open(E)` on first use. Same bound.
- **Ordering hazard, named:** the cache must be advanced with the *validated*
  predecessor's hash, never `prev_id` as supplied on an alt path — the same
  constraint `RF-D5` states on `prev_block_hash`.

**FFI, for as long as the C++ daemon exists (rule 20: shim, not logic):**
one opaque handle, five entry points —
`shekyl_archival_assignment_open / advance / is_assigned / issued_rows / rewind`
— C++ marshals heights and 40-byte pair keys and does nothing else. **In the
redb store this FFI does not exist:** the Rust `apply_block` / `pop_block`
(`DAEMON_REDB_STORE.md` §3.5 S-CHAIN-W, *"Long-term Rust `apply_block` /
`pop_block`"*) calls `EpochAssignmentCache` directly. The type is designed for
the second caller; the FFI is a temporary adaptor and is listed on the credit
wire's deletion surface from birth.

### 7.3 Inputs the shape needs that the tree does not yet supply

- **`drawable_pairs_at_h_open(E)`** — the set the urn is seeded with. The
  drawability relocation (`ARCHIVAL_CHALLENGE_MECHANISM.md` §4.1) fixes *when*
  it is evaluated; **no enumerator exists in the tree** (`rg -i drawable
  src/blockchain_db/` → none; Rust has only the `DrawablePair` type). This is
  Slice C work and a question (Q3): which table is the denominator, and is it
  frozen at `h_open(E)` or at the seal?
- **`lambda_target`** — a bare `u32` parameter at `challenge_assignment.rs:152`
  and `:264`. `CHALLENGES_PER_PAIR_PER_EPOCH = 3` exists (`constants.rs:27`)
  and is const-asserted against `SERVE_THRESHOLD_PASSES` (`attestation.rs:77,
  :82`), but **nothing connects it to the urn** — its only non-test consumers
  are in `shekyl-economics-sim`. The 972,000 figure assumes `λ = 3` by hand.
  **Must be pinned before any production caller** (Q4, confirmed by review):
  `EpochAssignmentCache::open` takes no `lambda_target` argument and reads the
  constant, so the two cannot disagree. Filed in `docs/FOLLOWUPS.md`.

---

## 8. Slice C — implementation plan (NOT AUTHORIZED; written so it can be built when ruled)

Rust to the maximum extent (`20-rust-vs-cpp-policy`; the 2026-09-01 countermand
rules the C++ unshippable and `DRS-E1` is in flight). Everything below that
computes lives in `shekyl-archival-retention`; C++ is a marshaling shim that
dies with the daemon.

| Item | Plan |
|---|---|
| **Where the enumeration walk goes** | `shekyl-archival-retention::settlement::settle_epoch_rows(issued: impl Iterator<(DrawablePair,u32)>, passes: impl Fn(&DrawablePair)->u32) -> Vec<(ArchivalPairEpochKey, SettlementRow)>` — pure, testable, no storage. `issued` comes from `EpochAssignmentCache::issued_histogram()` (or one `assign_epoch` replay if the cache is not resident). One FFI `shekyl_archival_settlement_rows_for_epoch` returns the batch; C++ `process_archival_slash_for_epoch` (`db_lmdb.cpp:6075`) loops `set_archival_settlement` **before** the fold, per `SO-D7` (*"write the row, then fold it, in one hook"*). Under redb: the Rust apply path calls `settle_epoch_rows` and writes directly. |
| **How `issued` is obtained** | From the urn (§7), never from records (`SO-D1`: the forcing case has zero records). |
| **How `passes` is obtained** | `archival_serve_credit_pass_count(P,s,E)` (`db_lmdb.cpp:5138`) — already a per-pair-epoch count over the `PC-D4` widened key; under R-A it is complete at `h_close(E)` and certainly by the slash deadline. Redb: the same count over the same table. |
| **Cost** | One epoch replay per settled epoch if the cache is not resident (1.09 s here; Pi-4 owed), inside the slash pass, off the admission path. Zero additional derivation if the cache is retained until `h_slash_deadline(E) = h_close(E) + CHALLENGE_RESOLUTION_BLOCKS` — one epoch of retention, so at most two epochs' urns resident. Row writes: one per pair with `issued ≥ 1` (~324,000 × 51 B ≈ 16.5 MB per epoch at maturity, pruned at `MAX_CLAIM_AGE_W`). |
| **Reader precondition (`SO-D7`'s lag)** | Unchanged in shape, re-grounded in cause: rows for `E` are absent until the slash pass at `h > h_slash_deadline(E)`, so the window walk (`db_lmdb.cpp:5870–5890`) must **exclude** `E` until settled, not read absence as non-observation. Stated as a reader constraint and tested (§10 item 5, restated: *inside `(h_close(E), h_slash_deadline(E)]`*, not *`[h_close, h_close + W₂)`*). The walk's `> 0` presence read at `:5880` is the interim predicate and is what the cutover replaces with the settlement row's `outcome`. |
| **Evidence plan (`ARCHIVAL_SETTLEMENT_WRITER.md` §10)** | Items 1, 2, 3, 6 unchanged. **Item 4 restated:** *a pass at epoch-relative block 9,999 is counted* — under R-A it rides block 9,999 and is in the table at `h_close`; the red edit is no longer "move the writer to `h_close`" but "run the writer before the slash deadline with a synthetic lagged pop/reconnect" — i.e. the test becomes the reorg test. **Item 5 restated** as above. **New item 7:** the membership gate — a record for an unassigned pair in block `h` is refused; the red edit is deleting the gate. **New item 8:** collusion — two records for one pair in one epoch from a miner that won two *unassigned* heights settle **NonObservation/Missed**, never Served. |
| **`CEN-L8` promotion path** | The census row's settlement clause names *"an unwired writer"* and puts settlement at epoch close; `SO-D7` puts it in the slash pass. Path: (1) ruling lands here → (2) census row re-worded to the slash-pass hook, two hooks per boundary stay (close + settlement) → (3) writer call site lands with the gate → (4) `DRS-P0f` re-reviews the row against the merged sha and records CHECKED-CONFORMANT. Not before step 3: a row promoted against a hold is the failure `CEN-L11` was. |
| **What changes at the same cutover** | **Added:** SO-D9 (i) — `ctx.settlement_epoch` from `shekyl_archival_settlement_epoch_at_height(current_height)` at `blockchain.cpp:5304`, which makes `ERR_EPOCH_MISMATCH` a live rule; the membership gate (`SO-D8b`). **Deleted:** `challenge_fire_height` path and `ERR_FIRE_NOT_REACHED`; `archival_baseline_observed_at_epoch` as the interim `issued`. **Kept:** `ERR_CREDIT_DEADLINE` and its C++ twin (`SO-D8a`). **Ruled separately (Q2, rule 21):** `CHALLENGE_RESPONSE_BLOCKS` — no consensus consumer; either the doc string is rewritten to what it is under R-A (a witness fetch budget, not consensus) and the const-assert coupling it to `CHALLENGE_RESOLUTION_BLOCKS` is dropped, or under R-B it becomes the per-challenge deadline the round must design. |

**Sequencing against `DRS-E1`:** none of the above blocks on redb, and none of
it thickens the C++ beyond one loop and one FFI call. If redb's `apply_block`
lands first, the FFI half is simply never written.

---

## 9. Proposed dispositions — **NONE RULED**

| ID | Proposed disposition | State |
|---|---|---|
| `SO-D8` (parent) | Premise **stands** (§1, corrected): cross-epoch records are representable and refused today by one live C++ rule. Shape **R-A** adopted *as a ruling*: `E = epoch(h_incl)`, enforced. | **PROPOSED** |
| `SO-D9` (standalone) | `ERR_EPOCH_MISMATCH` is a tautology (`blockchain.cpp:5124 → :5304 → serve_credit.rs:168`). Disposition (i) make it fire from height / (ii) delete — Rick's, because (i) is a consensus tightening. Filed in FOLLOWUPS independent of `SO-D8`. | **PROPOSED (i)** |
| `SO-D8a` | Boundary rule is SO-D9 (i). `ERR_FIRE_NOT_REACHED` dies with the beacon; **`ERR_CREDIT_DEADLINE` and its C++ twin kept untouched** (Q5, answered — the first cut's "delete as unreachable" was inverted). No relaxation. | **PROPOSED** |
| `SO-D8b` | Dedup unchanged (exact under without-replacement draws). **Add** `PC-D7`'s membership gate — with SO-D9 (i), the cutover's two consensus changes. | **PROPOSED** |
| `SO-D8c` | Emission gather unchanged **under R-A only**; presence-vs-absolute-2 asymmetry recorded, not opened. Under R-B this is the largest change in the round. | **PROPOSED** |
| `SO-D8d` | `passes > issued` unreachable once `SO-D8b` + SO-D9 (i) hold; FATAL at settlement, never clamped. | **PROPOSED** |
| `SO-D8e` | `EpochAssignmentCache`: Rust-owned, in-memory, sequential, checkpointed, never persisted; `λ` read from `CHALLENGES_PER_PAIR_PER_EPOCH`, not a parameter (Q4); 5-call opaque FFI as a deletion-surface adaptor; direct call from redb `apply_block`. | **PROPOSED** |
| `W₂` (Q2, rule 21) | `CHALLENGE_RESPONSE_BLOCKS` has no consensus consumer; the const-assert `CHALLENGE_RESOLUTION_BLOCKS ≥ CHALLENGE_RESPONSE_BLOCKS` couples a consensus constant to one without a referent. Row filed in FOLLOWUPS regardless of how `SO-D8` goes. | **FILED** |
| Slice A1 (Q6) | **Keep**, per review, on grounds narrower than §12 gave: the LMDB path needs a virtual to be reachable polymorphically, and a method with no interface presence is invisible to any port-surface check that enumerates `BlockchainDB`. In tension with `DRS-W12`; one commit. | **ANSWERED — keep** |
| Sweep on ruling | `constants.rs:59` W₂ doc; `ARCHIVAL_SETTLEMENT_WRITER.md` §6/§12/§13 and the `IMPLEMENTATION_INDEX.md` SO-row `SO-D7` lag sentence; `TJ` `:819–822`; mechanism §2 step list — under R-A all `PC-D2`-superseded, marked in-line per rule 23. **Not swept before the ruling:** under R-B they are the design. | owed with the ruling PR |

### 9.1 Figures flagged for re-derivation

| Figure | Source | Status 2026-09-13 |
|---|---|---|
| ~972,000 assignments / epoch | `3 × 324,000`, `challenge_assignment.rs:534`, asserted at `:555` | **Holds** as `λ·pairs`; `λ = 3` is a test parameter, not a pinned constant (Q4). Cost **measured** 1.09 s release on this host; Pi-4 owed. |
| 72 % unobservable at `k_cap = 30` | `ARCHIVAL_CHALLENGE_MECHANISM.md:1185` histogram `{0: 35 %, 1: 37 %, 2: 28 %}` | **Not re-derived** — no code artifact produces this histogram; it is a doc-only figure. Under R-A the capped-regime mechanics are unchanged, so the inputs did not move. Flagged as *unverifiable at source* rather than re-asserted. |
| ~3,411 B record | `ARCHIVAL_RESPONSE_FORMAT.md:974` (post-`RF-D6`) | Not re-derived here; `RF-D6` removed two fields after the 5,331 figure and the doc records the drop. No wire change since the `RF` close (2026-08-21) per `git log` on `attestation_wire.rs`/`serve_credit` wire. |

### 9.2 Wargames under R-A

| Scenario | What happens | What stops it |
|---|---|---|
| **Adaptive-selection archiver** — `P` serves only when it can predict it is assigned | Assignment for `h` is public one block early (`block_hash(h−1)`); `P` can predict, but the *witness* is whoever wins `h`, unknown until it is mined, and the leaf is `PC-D3`-drawn by `h−1`. `P` must serve every assigned draw to every prospective winner. | Membership gate + `PC-D3`; residual = `P` colluding with a pool that wins the assigned block, priced by the quadratic. |
| **Boundary-straddler** — issuance at epoch-relative 9,999 | Rides block 9,999 or falls to non-observation for that draw. A record carrying `E` into block 10,000 (epoch `E+1`) is representable — nothing in the nonce or leaf stops it — and is refused. | **Today:** the C++ `h_close` gate alone (`blockchain.cpp:5186`). **After the cutover:** SO-D9 (i) refuses it first (`epoch(h_incl) ≠ E`), `h_close` second, and the membership gate would refuse it anyway unless `(P,s) ∈ assignment(10,000)` — in which case it is an `E+1` record wearing an `E` header, which SO-D9 (i) is exactly the rule against. Today only `h_close` stands between that record and admission; §12's original proposal was to *relax* `h_close`, which would have admitted it with nothing behind. |
| **Reorg across `h_close(E)`** | Alt branch's blocks carry their own records (nonce-bound to them); losing branch leaves no residue (`verify_block_attestation` is pure). Settlement rows for `E`, if already written, are deleted by `revert_archival_slashes_at_height` and recomputed on reconnect (`SO-D6`). Cache rewinds to checkpoint. | `SO-D6` + §7.2 checkpoints. **Unread, named:** the pop order in `blockchain_db.cpp:748–749` reverts slashes before epoch-close; confirm the cache rewind is sequenced before either. |
| **Under-issuance regime** (`k_cap` binding) | Pairs with `issued ≤ 1` settle NonObservation with a row (`SO-D1`), so degradation is measured, not silent. Unchanged by R-A. | `SO-D1`/`SO-D2`'s `issued` byte. |

---

## 10. Questions for Rick

Four of seven were answered in the 2026-09-13 review of the first cut; the
answers are recorded here so the list is not re-asked. **Open: 1, 3, 7, and the
SO-D9 (i)/(ii) ruling.**

1. **OPEN — (Mechanism, decides R-A's cost)** Under the same-block shape every
   miner attempting `h` fetches `~λ·pairs/SEB ≈ 97` segments from their `P`s
   inside the block interval, concurrently with every other pool. Is that load
   and latency acceptable, or does it re-open `PC-D2`'s "no herd" claim? The
   review flagged this as the one question the agent must not decide: it is a
   thundering-herd shape, and `PC-D2` chose the implicit-block design
   specifically to avoid arbitrating one.
2. **ANSWERED — no referent.** `CHALLENGE_RESPONSE_BLOCKS` is read only by
   const-asserts. The assert `CHALLENGE_RESOLUTION_BLOCKS ≥
   CHALLENGE_RESPONSE_BLOCKS` couples a consensus constant to one with no
   consensus consumer — a rule-21 item worth a row regardless of `SO-D8`.
   Filed (FOLLOWUPS).
3. **OPEN — (Slice C input)** What is the drawable set at `h_open(E)`, and
   from which table is it enumerated? No enumerator exists.
4. **ANSWERED — unpinned, must be pinned before any production caller.**
   `lambda_target` is a bare `u32` at `challenge_assignment.rs:152` / `:264`;
   `CHALLENGES_PER_PAIR_PER_EPOCH` exists but only the economics sim reads it.
   §7.2's `open()` drops the parameter and reads the constant. Filed
   (FOLLOWUPS).
5. **ANSWERED — inverted.** `ERR_CREDIT_DEADLINE` is untouched: a
   defence-in-depth duplicate of the live C++ `h_close` rule. The vacuous
   check is `ERR_EPOCH_MISMATCH` (SO-D9). **What remains for Rick is SO-D9's
   disposition**, (i) make it fire from height — a consensus tightening, the
   reviewer's and this proposal's preference — or (ii) delete it.
6. **ANSWERED — keep A1**, on grounds narrower than §12's: the LMDB path
   needs a virtual to be reachable polymorphically, and a method absent from
   the interface is invisible to any port-surface check that enumerates
   `BlockchainDB`. Genuinely in tension with `DRS-W12`; one commit.
7. **OPEN — (Retention)** Is the cache retained through `h_slash_deadline(E)`
   (two urns resident, zero replay at settlement) or dropped at `h_close(E)`
   (one replay per settlement)?
