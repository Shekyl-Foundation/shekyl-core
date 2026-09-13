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

**§1 finds that the premise — a record naming `E` landing in `E+1` — is
unrepresentable on the frozen wire and is refused by two live gates.** Four of
the five items dissolve under the shape the tree already has; the fifth (e) is
real and is where the work is. §2 states the alternative shape honestly so the
choice is Rick's, not the draft's.

---

## 1. Finding F1 — the wire binds every record to the block it rides in

Read at the admission path, not from any design doc:

| # | Binding | Where | What it does to a record for `E` landing in a block of `E+1` |
|---|---|---|---|
| 1 | `response.settlement_epoch != ctx.settlement_epoch` ⇒ `ERR_EPOCH_MISMATCH` | `rust/shekyl-ffi/src/archival_ffi/serve_credit.rs:168–169`; `ctx.settlement_epoch = sc_settlement_epoch` is the epoch of **the block being validated**, `src/cryptonote_core/blockchain.cpp:5304` | **Refused** before the deadline gate is reached |
| 2 | `ctx.current_height > h_close(E)` ⇒ `ERR_CREDIT_DEADLINE` | `serve_credit.rs:211–212` | Refused (unreachable after #1) |
| 3 | Nonce `H(block_hash(h−1) ‖ cb_out_key(h) ‖ P ‖ s ‖ E)` — `prev_block_hash` and `cb_out_key` are populated from **the block being validated** | `blockchain.cpp:5504` (`cb_out_key` from `b.miner_tx`), `:5515` (`b.prev_id`); `attestation_wire.rs:79–80` (`NONCE_INPUT_LEN`) | A countersignature made for block `h` **cannot verify** in any other block |
| 4 | `PC-D3`: `challenge_leaf_index(P, s, E, prev_block_hash, …)` is derived from the including block's predecessor | `serve_credit.rs:172–200` | The leaf a record opens is **drawn by the block it rides in** |
| 5 | The kept header is `p_id ‖ shard_id ‖ settlement_epoch ‖ kind` — **no issuing height, no claimed block** | `attestation_wire.rs:92–97` | There is no field in which a record could *name* `h` |

And the ruling that made this the design rather than an accident,
`ARCHIVAL_PER_CHALLENGE_RECORD.md` `PC-D2` (RULED 2026-08-24): *"the block is
implicit: the record rides its own producer's block […] consensus reads the
block it is already validating."* `PC-D7` (same file) then keeps exactly one
admission check alive from the old "claimed block" design — *"verify that this
block's assignment names this pair — survives"* — and that check is **not yet
implemented** (`assign_epoch` has no FFI export and no admission caller;
`challenge_assignment.rs:262`, `rg assign_epoch src/ rust/shekyl-ffi` → none).

**`W₂` has no admission consumer.** `CHALLENGE_RESPONSE_BLOCKS` is read by
exactly one thing in the tree: the const-assert `CHALLENGE_RESOLUTION_BLOCKS ≥
CHALLENGE_RESPONSE_BLOCKS` (`constants.rs:39–44`), plus its `lib.rs` re-export.
Its doc string — *"blocks after a challenge's issuing block to accept its
serve-credit response"* (`constants.rs:59`) — describes a gate that does not
exist. `SO-D7`'s lag argument (*"a challenge drawn at epoch-relative block
9,999 resolves 500 blocks into `E+1`"*, `IMPLEMENTATION_INDEX.md` SO row) and
`SO-D8`'s premise were both read off that doc string.

**This is the dissolve-on-grounding class the SO round itself logged three
times (`RF-D3`, the W₂ floor, the Pi-4 question) and committed a fourth time in
its own §6:** a constraint re-derived from a document instead of read at the
path that enforces it. Recorded as the class, per that round's own instruction.

### 1.1 What the same-block shape actually is

Assignment for block `h` is derived from `block_hash(h−1)` (`assign_epoch`,
`prev_hashes[h]` is the predecessor hash). Every miner attempting `h` therefore
knows the pairs assigned to `h`, performs the reads **while mining `h`**, and
the winner's block carries the records. The "witness" is whoever produced `h`
— `ARCHIVAL_CHALLENGE_MECHANISM.md` 2026-08-10, *"the witness is the producer
of block h; the anchor is that block's `cb_out_key`"*, chosen because PoW is
the only liveness attestation on the chain. `W₂` in this shape is not a chain
window at all; it is the witness's **local fetch budget** — a mining-time
constraint, off-chain, with no consensus meaning.

Two passages still describe a *post*-issuance transfer window
(`ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md:819–822`, *"the transfer window that
follows still needs the witness to stay up"*; the mechanism's §2 step list).
They predate `PC-D2` and are the same shape as the `W₂` doc string. Under §9's
recommended ruling they are swept as `PC-D2`-superseded, in the same PR as the
ruling, not before.

---

## 2. The two shapes, stated so the choice is visible

| | **R-A — same-block** (what the frozen wire and `PC-D2` are) | **R-B — post-issuance window** (what `W₂`'s doc string, `SO-D7` and `SO-D8` §12 describe) |
|---|---|---|
| Record identifies its challenge by | the block it rides in (nonce, leaf index, epoch all bound to it) | **a new field or a verifier-side derivation** naming `h`: the header (`attestation_wire.rs:92`) gains an issuing height, or the verifier searches `assignment(E)` for `(P,s)` and disambiguates among up to `λ` draws |
| Wire change | **none** | **yes, on a genesis-frozen surface** (`RF` round closed 2026-08-21; the nonce must rebind to `cb_out_key(h)` and `block_hash(h−1)` of the *issuing* block, which the verifier must look up) |
| `ERR_EPOCH_MISMATCH` | stays | must be replaced by `epoch(h) == E` |
| `ERR_CREDIT_DEADLINE` | unreachable after `EPOCH_MISMATCH`; see `SO-D8a` | replaced by per-challenge `h < h_incl ≤ h + W₂` |
| Dedup (`blockchain.cpp:5156`) | one record per `(P,s,E)` per block is **exact** — the urn draws without replacement within a block (`challenge_assignment.rs`, `working.swap`) | must key on `(P,s,E,h)`: two records answering different draws may share a block |
| Emission gather at `h_close(E)` (`db_lmdb.cpp:8411`) | **complete** — every record for `E` is in `E`'s blocks | **incomplete** — records for `E` land up to `W₂` into `E+1`; the writer round's *"emission timing is untouched by the lag"* (verified only against the gather's read set, not its timing) becomes **false**, and the gather must move to the slash pass or re-run. **§12 did not see this.** |
| `passes > issued` | unreachable once `PC-D7`'s membership gate lands | reachable only through the same missing gate |
| `SO-D7` writer home | slash pass, unchanged — for the *other* reasons `SO-D7` gave (ascending order, existing revert) | slash pass, and now emission must join it |
| Cost that R-A carries and R-B does not | fetch latency sits **inside block production**: a miner that cannot fetch `~97` segments (§6) within the block interval either omits records (draws fall to non-observation — `k_cap`'s failure direction) or delays its block. Every pool attempting `h` fetches the same pairs from `P` concurrently — a herd `PC-D2` says *"never was"*; that claim is about the old reader-broadcast, and is **re-opened here as a load question for Rick**, not asserted either way. | none of the above; the witness has `W₂` blocks |

**Recommendation: R-A.** It is what the tree is; it is what `PC-D2` ruled; it
touches no frozen byte; and it dissolves items (a)–(d). R-B re-opens a closed
wire round and moves the emission gather, neither of which §12 priced. The
herd/latency cost of R-A is real and is **question Q1** in §10 — it is a
mechanism-round question (`ARCHIVAL_CHALLENGE_MECHANISM.md`), not a writer one,
and this proposal does not resolve it.

---

## 3. `SO-D8a` — boundary arithmetic and the `CREDIT_DEADLINE` gate

**Proposed: there is no cross-epoch boundary.** Under R-A a record's epoch is
the including block's epoch by gate #1. Issuance at epoch-relative block 9,999
is answered in block 9,999. Nothing straddles.

The two beacon-era gates in `serve_credit.rs:208–212`:

- `ERR_FIRE_NOT_REACHED` (`current_height <= h_fire`) — the single-beacon fire
  height (`challenge_fire_height` over `block_hash_at_seal`). **Dies with the
  beacon**; replaced by `PC-D7`'s membership gate (`SO-D8b`).
- `ERR_CREDIT_DEADLINE` (`current_height > h_close`) — **unreachable** behind
  `EPOCH_MISMATCH`. Proposed: **delete** with the beacon (rule 15 default), not
  keep as belt-and-braces — an error code that can never fire is a namespace
  entry that reads as a live rule, and the FFI error table would carry a
  REJECTED-marked row for it (rule 23). *Alternative for Rick:* keep as a FATAL
  invariant (`debug_assert`-class) if the cutover wants a second witness that
  gate #1 held. Either way, **no relaxation** — the premise for relaxing it is
  gone.

Consensus-visibility: deleting an unreachable refusal changes no accepted set.
The membership gate (`SO-D8b`) does, and is the cutover's consensus change.

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

**Proposed: unreachable by construction after `SO-D8b`; kept as a typed
refusal that is FATAL at settlement, never clamped.**
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
  open(E, drawable_pairs_at_h_open, lambda_target)        // fresh urn
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
- **`lambda_target`** — `assign_epoch` takes it as a parameter; **no constant
  pins it** (`rg LAMBDA constants.rs` → none). The 972,000 figure assumes
  `λ = 3` over 324,000 pairs. Q4.

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
| **What is deleted at the same cutover** | `challenge_fire_height` path and `ERR_FIRE_NOT_REACHED`; `ERR_CREDIT_DEADLINE` (or FATAL-ised, `SO-D8a`); `archival_baseline_observed_at_epoch` as the interim `issued`; `W₂`'s doc string rewritten to what it is (a witness fetch budget) or the constant deleted with its const-assert if Rick rules it has no remaining referent (Q2). |

**Sequencing against `DRS-E1`:** none of the above blocks on redb, and none of
it thickens the C++ beyond one loop and one FFI call. If redb's `apply_block`
lands first, the FFI half is simply never written.

---

## 9. Proposed dispositions — **NONE RULED**

| ID | Proposed disposition | State |
|---|---|---|
| `SO-D8` (parent) | Premise refuted at source: cross-epoch records are unrepresentable (§1). Shape **R-A** adopted. | **PROPOSED** |
| `SO-D8a` | No boundary arithmetic. `ERR_FIRE_NOT_REACHED` dies with the beacon; `ERR_CREDIT_DEADLINE` deleted as unreachable (alt: FATAL). No relaxation. | **PROPOSED** |
| `SO-D8b` | Dedup unchanged (exact under without-replacement draws). **Add** `PC-D7`'s membership gate — the cutover's consensus change. | **PROPOSED** |
| `SO-D8c` | Emission gather unchanged; presence-vs-absolute-2 asymmetry recorded, not opened. | **PROPOSED** |
| `SO-D8d` | `passes > issued` unreachable after `SO-D8b`; FATAL at settlement, never clamped. | **PROPOSED** |
| `SO-D8e` | `EpochAssignmentCache`: Rust-owned, in-memory, sequential, checkpointed, never persisted; 5-call opaque FFI as a deletion-surface adaptor; direct call from redb `apply_block`. | **PROPOSED** |
| Sweep on ruling | `constants.rs:59` W₂ doc; `ARCHIVAL_SETTLEMENT_WRITER.md` §6/§12/§13 and the `IMPLEMENTATION_INDEX.md` SO-row `SO-D7` lag sentence; `TJ` `:819–822`; mechanism §2 step list — all `PC-D2`-superseded, marked in-line per rule 23. | owed with the ruling PR |

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
| **Boundary-straddler** — issuance at epoch-relative 9,999 | Rides block 9,999 or falls to non-observation for that draw. Nothing crosses. | Gate #1 (`EPOCH_MISMATCH`). |
| **Reorg across `h_close(E)`** | Alt branch's blocks carry their own records (nonce-bound to them); losing branch leaves no residue (`verify_block_attestation` is pure). Settlement rows for `E`, if already written, are deleted by `revert_archival_slashes_at_height` and recomputed on reconnect (`SO-D6`). Cache rewinds to checkpoint. | `SO-D6` + §7.2 checkpoints. **Unread, named:** the pop order in `blockchain_db.cpp:748–749` reverts slashes before epoch-close; confirm the cache rewind is sequenced before either. |
| **Under-issuance regime** (`k_cap` binding) | Pairs with `issued ≤ 1` settle NonObservation with a row (`SO-D1`), so degradation is measured, not silent. Unchanged by R-A. | `SO-D1`/`SO-D2`'s `issued` byte. |

---

## 10. Questions for Rick

1. **(Mechanism, decides R-A's cost)** Under the same-block shape every miner
   attempting `h` fetches `~λ·pairs/SEB ≈ 97` segments from their `P`s inside
   the block interval, concurrently with every other pool. Is that load and
   latency acceptable, or does it re-open `PC-D2`'s "no herd" claim? This is
   the one place R-B has a real advantage.
2. **(Rule 15)** Does `CHALLENGE_RESPONSE_BLOCKS` have a remaining referent
   under R-A? If it is only the witness's fetch budget, it is not a consensus
   constant and the const-assert coupling it to `CHALLENGE_RESOLUTION_BLOCKS`
   asserts a relation between a consensus value and a non-consensus one.
3. **(Slice C input)** What is the drawable set at `h_open(E)`, and from which
   table is it enumerated? No enumerator exists.
4. **(Slice C input)** Is `λ_target = 3` a pinned constant, and where does it
   live? `assign_epoch` takes it as a parameter today.
5. **(`SO-D8a`)** Delete `ERR_CREDIT_DEADLINE` as unreachable, or keep it as a
   FATAL witness that gate #1 held?
6. **(Slice A1 retention)** `DRS-W12` (2026-09-08) *withdrew* a `= 0` +
   `BaseTestDB` patch for the fifteen archival hooks — *"no blocker to name,
   because the rewrite closes the row"* — four days before §12 / `DAEMON_REDB_STORE.md:697`
   scoped the same shape for the settlement four. A1 (`a6f602d33`) implements
   the later instruction and contradicts the earlier ruling's spirit. It is one
   commit; keep or drop is yours. Its honest benefit is narrower than §12
   stated (the redb denominators never read `BlockchainDB`'s virtuals; see the
   `:697` update).
7. **(Retention)** Is the cache retained through `h_slash_deadline(E)` (two
   urns resident, zero replay at settlement) or dropped at `h_close(E)` (one
   replay per settlement)?
