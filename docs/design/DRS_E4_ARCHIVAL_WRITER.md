# DRS-E4 — the archival writer: pre-flight

**AMENDED 2026-09-29 by the `SHT-Q2` build (PR #910), three places, no
ruling reopened.** (1) **The shard universe (§3.7, `ARW-Q6`)** is
`⌊C(h) / W⌋` over `block_info.cumulative_archival_len`
(`ARCHIVAL_SHARD_T_DERIVATION.md` §8.6, RULED) — not `⌊cumulative_tx_count
/ T⌋`; `ARW-Q6`'s ruling, *the view, not a stored count*, stands, and only
its operand is re-keyed. The Round-0 text that states the count form (§1,
§2) is the record at its pin. (2) **Invariant numbers:** this plan's
SI-19…23 stand; the `SHT-Q2` build took SI-24. (3) **Layout:** 17 went to
E6 slice 7 wave B and 18 to `SHT-Q2`, so commit 1's "layout 17" is the next
free layout when it cuts.

**Status:** OPEN — **implementing against §6: commits 1–5 landed (PR-a) as
of 2026-10-01; PR-b (commits 6–10) pre-flighted 2026-10-01 (§6.2), commit 6
next** (1–4 merged to `dev` in PR #914, with the `SHT-Q2` re-key
folded in at commit 4; **5** — the phase bodies, three sub-commits, then the
slash-grace ruling's three commits that closed 5c's rule-22 disclosure —
merged in PR #921, §6 row 5's as-landed text and §10's two 2026-09-30 rows).
Round 0 executed 2026-09-29 at `dev@cac2dadbe` (#889
merged; the slice-7 c3 tree). Findings `ARW-1…ARW-14` recorded (§5;
`ARW-15` added 2026-09-30 from the corpus, ruled the same day — the
settlement schedule is rule-set data);
**Round 1 RULED 2026-09-29 (maintainer, on PR #904)** — nine rulings, the
defaults held on all nine, with reasons recorded in §8 that are better than
the ones posed: `ARW-Q1` on slice 7's Q5 test (the validator computes the
folds anyway, so the delta is free to carry — E3's `root_after` arrangement
one lane over, the third application and so a precedent); `ARW-Q2` on ARW-2's
discriminator (a journal whose only job is reversal is a view of the undo
log); `ARW-Q3` and `ARW-Q9` as one principle with two dispositions;
`ARW-Q4` as the absence-as-value class caught mid-contradiction; `ARW-Q8` as
`SAR-Q2`'s reopening clause **firing on its own trigger**, not being
invoked. ARW-1 confirmed at the line (`blockchain.cpp:4734–4735`, a bare
`db_wtxn_guard` and `set_archival_serve_credit_bit` under the blockchain
lock, outside any block's write batch) and the corpus now says so where the
data is (§3.8). The E6 boundary ruled as §2.2 drew it. Implementation may
begin against §6 once this PR lands. Identifier families
**`ARW-`** (findings) and **`ARW-Q`** (questions), registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 with this file
(rule 94 §1; `check_index_prefix_uniqueness.py` branch (a): `ARW` and
`ARW-Q` distinct, clear of the 109 registered). Parent plan:
[`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) — the **DRS-E4** node of the
lane graph (`E1 → E2 → E3 → E4 → E5`), §3.4 rule 3 (*"design typed cursors
for retention; delete gather shell — not 'rehost ~3k / 77 methods'"*, E-7)
and §7.5 table 2 (CEN-L7 … L10, L14 ×4, L16 arrive here). The boundary
statement this document builds against is
[`DRS_E1_SARCH.md`](DRS_E1_SARCH.md) §0 / §2.2 / §2.3 — *E1 mints what E4
writes into; E4 does not get to choose a second shape for the same byte* —
which that file holds in `design/` "until E4's plan owns it"; this plan owns
it from §2 down, and that file archives when this increment lands (§9).
Template: the DRS-E3 pre-flight shape
([`DRS_E3_CURVE_WRITER.md`](DRS_E3_CURVE_WRITER.md), whose §3.7
fact-or-view test is applied here to every inherited archival table, §3.4).

**One sentence.** The daemon store's `connect` has two empty `[E4 hook]`
phases (5: attestation witness; 9: accrual, slash, epoch close) and three
archival vin arms that "write nothing here" (`store/connect.rs:29`, `:34`,
`:493–494`); the C++ funnel behind them is ~3,500 lines of `BlockchainLMDB`
that marshal LMDB rows into Rust folds and journal pre-images into six
per-family revert logs (`db_lmdb.cpp:4486–7960`, `:9085–9128`). E4 makes
the Rust stack **derive the archival state transition in the validator and
persist it in the store**: the verdict carries what a block does to bonds,
credits, claims, the close rows and the slashes; `connect` writes it through
the journaled handles S-CHAIN-W built, so `pop` is one mechanism (the undo
log) and the six C++ journals dissolve — except the one that is also
consensus history (§3.3). The §7.1.1 gate that has held this surface since
P0d is discharged inside the increment, not around it (§3.8).

**The line this document is written on.** We are building our own store in
Rust. The C++ is evidence about what the chain *requires*, not a
specification for how to store it (`DRS_E3_CURVE_WRITER.md`'s line, verbatim
because it is the same line). Where the C++ keeps a table to reverse a write
it could not journal, we have a journal; where it keeps a running total no
consumer reads, we have a sum; where it walks a retired registry to name the
shards a complete-tree bond holds, the shard universe is a function of the
chain. And where the C++ *decides* something consensus-visible inside its
storage class — which shard failed its challenge, what `r_market` is, whether
a claim is claimable — that decision moves to the authority over validity,
as E3 moved the root (`CTW-Q1`), because every one of those values
determines what the next block may contain.

---

## 0. Ground

Read at `dev@cac2dadbe`. Every citation below is against that tree unless it
says otherwise — re-read them, do not diff around them. Rulings this
document is downstream of and does not re-open: **`PDM-Q3`** (the residual
consensus read is the C++ serve-credit verifier's leaf read, and it dies
here — `ARCHIVAL_PRUNED_DAEMON_MODE.md:352–375`); **`PDM-Q6` item 4 row 1**
(the serve-credit preimage is re-keyed over `shard_id` and its range —
*was `(k·T, (k+1)·T)` at the pin; `SHT-Q2` 2026-09-29 → `[k·W, (k+1)·W)` by
archival length, §10's 2026-09-30 merge row* — landing site "E4 / S-ARCH
in `shekyl-chain-rules`", `:821`) and **item 5** (*was* "shards are
fixed-cardinality `T`; no length rows"; **SUPERSEDED by `SHT-Q2`**: shards
are cut by archival length, `txs_archival_len` is the row, and the
census-era fixed cardinality is history);
**`PDM-Q9`** (no archival serving state in the daemon, ever — §2.6);
**`PDM-Q12`** (the freeze pipeline retires; `LeafStore` is rebuilt, not
deleted, and its freeze half is a Rust deletion surface at E4, `:1376`);
**`SAR-Q1…Q7`** (`DRS_E1_SARCH.md` §9 — seven tables shaped, the record's
home, same-semantics codec, primitives only, the alt witness folded, `Option`
load-bearing, the slash-log port deferred *to this Round 0*); **C2-R8
principle 3** (*the store may persist a consensus fact computed by a
consensus-owned function inside the write transaction; it never computes
one*); **`CTW-Q1`** (the verdict derives what determines future validity);
**`SCW-7`** (pop-ability is "does `undo_log[h]` exist"); **`SO-D8` §5.1**
(the settlement writer cannot be live before the per-challenge admission
cutover, `ARCHIVAL_SETTLEMENT_WRITER.md:324–369`); **§7.1.1 / SAR-11** (no
archival apply in `shekyl-chain-store` until digest coverage or a
replacement KAT forces it to run).

---

## 1. Preconditions, as found at the pin

1. **Two hook phases and three vin arms, all empty, all named.**
   `store/connect.rs:29` `5. [E4 hook] attestation witness`; `:34` `9. [E4
   hook] accrual row, slash, epoch close`; `:380` and `:460` are the one-line
   comments; `:493–494` *"the archival vin arms — serve-credit bit, bond
   post, emission claim — are E4's hooks and write nothing here"*.
   `ConnectFacts` is documented as *"minus E4's `archival_budget_accrual`"*
   (`:163`) and is down to **one** passed-through field, `burned`, deleted
   by CEN-F17 / G11 in slice 7 wave B (`:165–200`). E4 lands bodies, not
   phases (`:38–39`).
2. **The C++ writer surface, read.** *Vin arms* in `add_transaction`
   (`blockchain_db.cpp:285–371`): serve-credit bit (`set_archival_serve_credit_bit`,
   keyed by the block it rides in, PC-D4); JoinMarket → `put_archival_bond_record`
   + `total_bonded_atomic += credit`; Release → `apply_archival_unbond`;
   Reinstate → `apply_archival_reinstate`; emission → `apply_archival_emission_claim`
   (the vin re-extracted through the Rust codec, `:354`). *Block hooks* in
   `add_block` (`:655–693`): the attestation witness row when non-empty
   (`:669–671`); the accrual row when non-zero, **before** the close so the
   epoch's last block is in its own budget (`:680–690`); then
   `process_archival_slash_at_height(prev_height + 1)` and
   `process_archival_epoch_close_at_height(prev_height + 1)` (`:692–693`).
   *Pop* mirrors it (`:744–790`, `:808`, `:923–948`) through five height-keyed
   revert logs and the vin (JoinMarket is deleted whole; Release / Reinstate
   restore from journals "because the vin carries the post-connect state",
   `:936–939`). Every applier is **marshal → Rust fold → put record →
   journal**: `release_connect` / `release_pop`, `reinstate_connect` /
   `reinstate_pop`, `claimed_epochs_check_and_set`,
   `slash_open_interval_to_append`, `epoch_close_compute`,
   `failure_window_slashable` are all `shekyl-archival-retention`'s
   (`bond_connect.rs:96`, `:177`, `:257`, `:335`, `:396`;
   `claimed_epochs.rs:139`; `consensus_state.rs:568`; `failure_window.rs:361`).
   The C++ *decides* in exactly three places: which shards to challenge
   (`db_lmdb.cpp:5720–5752`), whether a challenge failed
   (`archival_challenge_failed_at_height`, `:5459–5485`: the
   `slash_applied` dedup at `:5471`, `archival_baseline_observed_at_epoch`
   at `:5475` — the seal-block hash read, `:5301–5383` — then
   `archival_failure_window_slashable`, `:5384–5458`, which reads
   `archival_serve_credit_pass_count` per epoch of the window at `:5437`
   and hands the observations to the Rust fold at `:5451`), and which rows
   an epoch's gather sees (`:7521–7764`).
3. **The tables E4 writes into are typed; the ones it decides about are
   not.** Shaped by E1 S-ARCH at layout 11 (`schema.rs:488–556`):
   `archival_serve_credit` (`ServeCreditKey → Present`), `archival_bond`
   (`[u8; 32] → Coded<BondRecord>`), `archival_r_market`, `archival_sigma_work`,
   `archival_budget`, `archival_attestation_witness`; the
   `archival_last_slash_epoch` cell (`codec/property.rs:302–316`). Still
   `Unshaped` (ten of the twelve `Unshaped` rows in `tables.snap`):
   `archival_settlement`, `archival_shard_segment`, `archival_slash_applied`,
   `archival_slash_log`, `archival_emission_claim_log`,
   `archival_bond_unbond_log`, `archival_bond_holdings_update_log`,
   `archival_bond_reinstate_log`, `archival_epoch_close_log`,
   `archival_budget_accrual`. `total_bonded_atomic` has **no** typed cell
   (`property.rs:11` names it; nothing declares it). §3.4 disposes of each.
4. **The journaled write verbs exist, and the stub refusal is armed with no
   writer to refuse.** `open_insert_table` / `open_upsert_table`
   (`store/write.rs:442–498`) journal every write for `pop` (SCW-7);
   `admit()` (`:395–405`) refuses a write to an archival family the
   session's `ApplyPolicy` stubs — `StoreCannot::FamilyStubbed` — and the
   file-level `Provenance.stubbed` union exists to record a skipped apply
   (`provenance.rs:22–57`, `apply_policy.rs`). The family list is the LMDB
   X-macro's seventeen `archival_*` names (`apply_policy.rs:95–128`). Today
   nothing opens an archival table for writing, so the refusal has never
   fired and its caller-side semantics (skip-and-widen vs. abort) were never
   decided (ARW-9).
5. **The §7.1.1 gate is exactly as written, and the digest is tip-only.**
   `digest_v0.rs:23–31` is the named exclusion *without* a replacement KAT
   — *"do not claim archival parity from a v0 match"*. The E2 trace carries
   **one** checkpoint, at the covered tip, because the C++ has no as-of-height
   digest read (`DRS_E2_REPLAY_DRIVER.md:740–747`, RD-F18); the per-height
   oracle E3 enjoyed (`root_after` in every `block_info` row, CTW-5) has no
   archival analogue — LMDB holds current archival state, not per-height
   archival state, except in the height-keyed journals themselves.
6. **The corpus exercises four of the seventeen families, and one of them by
   a write no block made.** `bond-post` (109 blocks): one JoinMarket.
   `emission-claim` (1 026 blocks, `SEB = 512`, `regtest_e2e.rs:3193`): one
   JoinMarket, accrual rows, two epoch closes, one claim — and the serve
   credit its claim is priced on was **injected** through the regtest RPC
   `regtest_inject_archival_serve_credit` (`regtest_e2e.rs:3330` (*`:3325` at the pin; moved by this PR's own edit to the file*);
   `core_rpc_server.cpp:958`; `blockchain.cpp:4709`), a direct LMDB write
   outside any block (S-ARCH census #18, *"the writer and its test injector
   land together"*). No captured chain carries a serve-credit transaction, a
   Release, a Reinstate, a slash or a non-empty attestation witness. The
   attestation path has no producer at all (FOLLOWUPS `:139`), so phase 5's
   body has nothing to write on any chain that exists.
7. **The dependency graph already permits the shape §3.1 proposes.**
   `shekyl-chain-rules` depends on `shekyl-archival-retention`
   (`chain-rules/Cargo.toml:55`, slice 5's CT-balance edge), and
   `shekyl-chain-store` depends on `shekyl-chain-rules` (`chain-store/Cargo.toml:29`).
   So the retention crate is in the store's closure today — `DRS_E1_SARCH.md`
   §3.4's *"the daemon store cannot depend on `shekyl-archival-retention`"*
   described the direct edge and is no longer a graph fact (ARW-10). The
   folds stay where they are; what changes is who calls them.
8. **The accrual is half derived.** `blockchain.cpp:5890–5904`:
   `archival_budget_accrual = em_split.staker_emission + burn.staker_pool_amount`.
   The first term is on the verdict since slice 7 (`ValidatedBlock::emission().split.staker_emission`,
   `block.rs:349–353`, `rules/reward.rs:108–114`); the second is CEN-F17's,
   wave B, whose operand — `frozen_segment_count` — is the freeze-era count
   this increment re-keys (FOLLOWUPS `:727`; `rules/miner.rs:55`).
9. **The slash scheduler's complete-tree arm enumerates shards from the
   retired registry.** `db_lmdb.cpp:5720–5744` opens a cursor on
   `archival_shard_segment` to name the shards a `CompleteTree` bond is
   challenged on. `PDM-Q12` retired that table; under `PDM-Q6` item 5 the
   shard universe is `{k : (k+1)·W ≤ cumulative_archival_len}` (*as written at
   pre-flight: `(k+1)·T ≤ cumulative_tx_count`; corrected at commit 3 to the
   storage ids, re-keyed to `SHT-Q2`'s `W` at commit 4, §3.7*) — a function of
   the chain the store already holds. The C++ arm is dead on arrival and
   the Rust one reads a count (ARW-4).
10. **Slash burns.** `apply_archival_slash_one` adds the slashed amount to
    `total_burned` (`db_lmdb.cpp:5615–5618`) — the same cell `connect`'s
    phase 8 folds `burned` into (`connect.rs:440–458`, SI-8). Two writers of
    one cell inside one transaction; E4's slash body is the second (ARW-6).
11. **The close writes zero as absence, and the read was told not to.**
    `db_lmdb.cpp:7802–7805` skips `r_market[i] == 0`; A6 returns `None` for
    the absent row (SAR-8). The write side of the distinction S-ARCH pinned
    on the read side is this increment's to state (ARW-Q4).
12. **The epoch prune is not S-PRUNE's.** `prune_archival_epochs_before`
    (`db_lmdb.cpp:7084–7121`) runs inside the close, writes the
    `archival_prune_watermark_epoch` receipt and deletes serve-credit,
    settlement, r-market, Σwork, budget and accrual rows below an epoch;
    `pop_target_allowed` reads the receipt (`blockchain_db.cpp:705–736`).
    S-PRUNE discards shard **bodies** and retires undo rows below
    `tip − D_max` (`DRS_E1_SPRUNE.md` §4); it never touched an archival row
    and its pop floor is the undo floor (SI-6). Whether closed-epoch rows are
    pruned at all in redb, and by whom, is open (ARW-Q7).
13. **Consumers queued by name** (§7): CEN-L7…L10, L16 (census `:550–559`);
    the 4.J rows slice 8 adopts (`:484–519`, twenty-six); CEN-B4 (deferred
    from slice 1 "because bond pairs have no store table until E4",
    `rules/header.rs:8`, FOLLOWUPS `:139` item 3); the `archival_reorg_depth_blocks`
    split (`:153`); the bond-admission shard predicate's three questions
    (`:161`); `segment_leaf_count`'s exit from the JSON (`:157`,
    `DRS_E3_CURVE_WRITER.md` §3.9); F17's operand (`:727`); the
    daemon-uniformity sentence owed to the parent plan (`:176`, discharged by
    this PR — §2.6); `SAR-Q7`'s staged port (A2 + `holds_shard_at`).
14. **Two findings this writer inherits.** **CTW-2 / CTW-3**: a C++ pop that
    recomposes or replays a per-family journal is a second mechanism for
    what `undo_log` holds. **SAR-7**: one of the six journals is read
    *forward* as consensus history (the slash log, by `holds_shard`), and it
    carries a second row kind (epoch markers, `kArchivalSlashLogEpochMarkerSeq`,
    `shekyl_types.h:172`; `db_lmdb.cpp:5784–5812`). So "journals or
    `undo_log`" is the wrong question; "which of the six is history" is the
    right one (§3.3).

---

## 2. Scope

### 2.1 In

- **The archival transition on the verdict** (§3.1, `ARW-Q1`): `validate`
  derives, per block, the bond-record writes the vin arms imply, the
  serve-credit bits, the claim's record update, the slashes due at this
  height, the close rows if this height closes an epoch, and the accrual;
  `ChainValid` carries them as one typed delta; `connect` persists what it
  is handed and computes nothing (C2-R8 principle 3, CTW-Q1's reason).
- **The phase bodies** (§3.2): the vin arms inside phase 2's `record_tx`,
  phase 5 (witness), phase 9 (accrual, slash, close) — every write through a
  journaled handle bound to its SI row; `pop` unchanged (journal replay).
- **The journals decided** (§3.3, `ARW-Q2`): five revert logs dissolve into
  `undo_log`; the slash log is re-shaped as the history table it is
  (`(BlockHeight, JournalSeq) → Coded<SlashLogEntry>`), the epoch-marker row
  kind replaced by the `archival_last_slash_epoch` cell's own pre-image;
  `archival_slash_applied` typed as the set it is; A2 `slash_log_after` and
  `holds_shard_at` land (the `SAR-Q7` staged pair), CEN-L16's fold leaves
  the store layer.
- **The remaining `Unshaped` archival rows disposed** (§3.4): each is a
  fact, a view, a journal or retired — typed, dissolved, deleted or held
  with its blocker named. Layout bump; `tables.snap` moves.
- **`total_bonded_atomic`** as a view, not a cell (§3.4, `ARW-Q9`). **UPDATE 2026-10-01:** SI-20 is the absent-update belt (`ReplaceTable` / `BondRecordAbsent`), not a re-sum of the writes.
- **The §7.1.1 discharge** (§3.8, `ARW-Q5`): an archival digest family on
  both sides at the trace's tip checkpoint, the sufficiency stamp made
  real (a stubbed family reddens the run), and the injected serve credit
  modelled as what it is — an out-of-band event in the replay — so the
  `emission-claim` chain grades rather than diverges by construction.
- **The shard universe re-keyed** (§3.7, `ARW-Q6`): the complete-tree
  challenge set and CEN-F17's `n` become functions of `cumulative_tx_count`
  and `T`; `segment_leaf_count` leaves `consensus_constants.json`.
- **The C++ deletion surface** (§3.9): the archival appliers, reverters,
  gather shell, freeze pipeline, the serve-credit leaf-preimage verifier,
  the regtest injector's LMDB write, the six `Archival*RevertValue` codecs
  — and the Rust that existed only to be called from them (`release_pop`,
  `reinstate_pop`, `segment_freeze.rs`, the freeze half of `challenge.rs` /
  `path.rs`, their FFI exports).
- **The two FOLLOWUPS rows this document can close at pre-flight:** the
  daemon-uniformity sentence (`:176`, written into the parent plan by this
  PR, §2.6); `SAR-Q7`'s blocker line in `DRS_E1_SARCH.md` (its falsifier —
  *"E4 Round 0's journal ruling"* — fires when §8 is ruled, and the row
  says so).

### 2.2 Out (named, so it is not scope shed by omission)

- **The 4.J admission rules themselves** — CEN-J1…J26 (`CONSENSUS_RULE_CENSUS.md:484–519`),
  including the **re-keyed serve-credit verifier** (`PDM-Q6` item 4 row 1).
  Those are E6 slice 8's rows over the substrate this lands; E4 hands slice
  8 the typed state and the transition, not the verdict on a transaction
  (§2.3). The boundary is the one E3 drew with I15: the writer landed
  first, the rule judged what it wrote. **RULED 2026-09-29 (PR #904):**
  `PDM-Q6` item 4 row 1's *"E4 / S-ARCH in `shekyl-chain-rules`"* names a
  crate and a lane pairing, not which lane lands the admission rule — a
  crate assignment, read as a lane binding; E4 owns the typed state and the
  transition, slice 8 owns the 4.J rule that reads them (recorded on
  `ARW-Q1`'s row, §8).
- **The settlement writer** (`archival_settlement`, SO-D8) — blocked on the
  per-challenge admission cutover, `ARCHIVAL_SETTLEMENT_WRITER.md` §5.1;
  falsify by that cutover's PR. §3.4 says what the table does meanwhile.
- **The wallet-side store rebuild** (`PDM-Q12`, the wallet lane) and
  `p-fetch`'s sizing (`SF-D7`) — consumers of the shard re-key, not this
  increment's.
- **CEN-B4** (attestation verify in `validate`) — slice 1's deferral lifts
  when bond records are on `ChainView` (§2.3); the rule is E6's.
- **The attestation-record producer** (FOLLOWUPS `:139`) — the
  block-template writer's; phase 5 is written to what the C++ writes, and
  tested by a scenario that supplies a witness, since no corpus has one.
- **`archival_reorg_depth_blocks`' split** (FOLLOWUPS `:153`) — owed to E4
  by that row. **Deferred inside this plan, with the falsifier the row
  carries** (`git grep 'from_raw(ARCHIVAL_REORG_DEPTH_BLOCKS)' rust/` →
  two constants): it is pass admission's constant, not the writer's, and
  lands with the serve-credit rule in slice 8 — the FOLLOWUPS row's *Owed*
  and *Owner* lines now name slice 8 as the landing lane (edited in this PR,
  on review) and the disclosure is recorded here (rule 22).
- **A `Mock*` archival state** — not written (§5.2).

### 2.3 What E6 slice 8 gets

`ChainView` grows the archival reads the 4.J rows consume — `bond_record`,
`served_shards` / `last_served_epoch` / `pass_count`, `r_market` / `sigma_work`
/ `budget`, `last_settled_slash_epoch`, `slash_log_after` — as recorded
*state* (G13: no recorded *body* crosses the view; a bond record is state,
which is the class the view exists to carry). `BondRecord`'s home moves
under `SAR-Q2`'s reopening clause (`DRS_E1_SARCH.md` §3.4 as built: *reopens
if E6 slice 8 needs `BondRecord` on `ChainView`*) — it does, so the record
and its vocabulary go to `shekyl-types` (`ARW-Q8`). And slice 8 gets the
transition already derived: a bond post's admission (J14–J18) judges the
vin; what the admitted vin *does* to the record is this increment's fold,
so the rule and the write cannot disagree.

### 2.4 What E2 gets

The bar SAR-11 recorded lifts: an archival digest family a Rust writer
fills, compared at the tip of every captured chain, and a sufficiency stamp
that goes red when a family is stubbed. What E2 does **not** get — stated so
the landing is not read as broader than it is — is a per-height archival
oracle (§1 item 5) or any oracle at all for serve-credit transactions,
Releases, Reinstates or slashes (§1 item 6): those are Rust-first under
genesis-frozen rules the C++ never ran, and their witnesses are
scenario-driven.

### 2.5 What S-PRUNE, DRS-D3c and the wallet lane get

One definition of "shard" on `dev` (`DRS_E3_CURVE_WRITER.md` §6.1's
finding), **as built at commit 4 under the `SHT-Q2` re-key**: shard `k`
is `[k·W, (k+1)·W)` over **archival length**, and the shards closed at a
height are `shard_of(cumulative_archival_len)` at parent state
(`closed_shards_before`; §3.7, §10's 2026-09-30 merge row). ~~*Was* (pin
→ commit 3, SUPERSEDED 2026-09-29 by `SHT-Q2`): `k = ⌊tx_id / T⌋`,
`[k·T, (k+1)·T)`, closed iff `(k+1)·T ≤ storage_ids_through(cumulative_tx_count,
h)` — the ids issued, listed transactions *plus* one coinbase per block.~~
`segment_leaf_count`, `SEGMENT_LAYER_J`, `leaves_per_segment()` and
`frozen_segment_count` lose their last *Rust* consensus consumer here
(commit 3); their last C++ consumers are the freeze pipeline and the
coverage RPC, which the cutover deletes (§3.9), and they leave with those.
The wallet-side store's use is that lane's (`PDM-Q12`).

### 2.6 The constraint this surface enforces, written where the port reads it

**No archival serving state in the daemon, ever** (`PDM-Q9`, RULED
2026-09-18 on #775; decision log 2026-09-17). The daemon store holds
archival **consensus** state — bond records, serve-credit bits, close rows,
slashes, the claim set, the attestation witness — and nothing an archiver
would serve from: no shard bodies beyond S-PRUNE's uniform retention, no
`LeafStore`, no served frame, no per-node posture. An archiver-backed daemon
that behaves differently from a plain one fingerprints the Principal's
public address, so the archival fast path in the daemon is REJECTED at any
performance argument; the criterion is *persistent, posture-correlated*
state (forbidden) versus *episodic, universally available* actions
(allowed). This paragraph is also written into `DAEMON_REDB_STORE.md`'s
S-ARCH row by this PR, which is what FOLLOWUPS `:176` asked for; its
violation signal stands as a falsifier here: `rg -n 'serving|LeafStore|shard
bytes|ServedFrame' rust/shekyl-chain-store/src` returning a definition that
serves archival content.

---

## 3. The contract proposed for freezing (Round 1)

### 3.1 Who derives the archival transition — `ARW-Q1`, default: the verdict

Three facts decide the default before any preference does.

*First*, the values are consensus-visible with reach: `r_market(shard, E)`
prices the next bond post (J15); the claim set on a record refuses the next
claim (J25, L7); a slash removes a shard the next serve credit would be
credited on (J8). Under `CTW-Q1`'s reason — *a value with that reach is
carried by the authority over validity, backed by a judgment* — they are the
verdict's, not a store hook's.

*Second*, C2-R8 principle 3 already forbids the C++ shape. `db_lmdb.cpp:7765`
gathers, calls `shekyl_archival_epoch_close_compute` and writes, inside the
write transaction: that is the store computing a consensus fact through a
consensus-owned function, and the principle's second clause — *it never
computes one* — is what the "compute phase" comment names as a virtue.
The tempting Rust shape (a `close_epoch()` method on `WriteBatch` calling the
retention crate, which the closure now permits — §1 item 7) is that fusion
with a Rust accent.

*Third*, the folds are already the validator's neighbours: `shekyl-chain-rules`
depends on `shekyl-archival-retention` and calls `bond_ct_balance` from a
rule (slice 5). Calling `release_connect` from `validate` adds no edge.

So: **`validate` reads the archival state it needs off `ChainView` (§2.3),
runs the retention crate's folds, and `ChainValid` carries an
`ArchivalDelta`** — the record writes (`Vec<(PCanonicalId, BondRecord)>`
post-images, with the JoinMarket insert distinguished from an update), the
serve-credit keys, the claim's record update, `Vec<Slash>` for the epochs
whose deadline this height passes, `Option<EpochClose { epoch, r_market:
Vec<(ShardId, RMarket)>, sigma_work, budget }>`, the accrual, and the
attestation witness the candidate's sidecar carried (§3.2 phase 5). The store
writes each through its handle and checks what it can (§4). **The store
holds no archival arithmetic**: `connect` does not know what a slash is,
only that a record is replaced and a set gains a member.

*What this costs, said plainly:* the slash scan reads every bond record at
a deadline height, and the close reads the epoch's snapshot — reads that
today happen inside the write transaction and would move to the view. The
C++'s own scan-cost note (`db_lmdb.cpp:5708–5719`) says the cost is once per
epoch, not per block; B9 says measure it rather than assert it, and §6's
commit 5 does. **Measured 2026-09-30 (commit 5,
`slash_scan_bench_tests.rs`, `#[ignore]`d; release build on the workstation,
16 cores; `fakechain(fixed 7, SEB 100 / cap 50)`, 64 bonded personas,
every persona missing `M = 11` of `N = 13` passes so the epoch-11 deadline
slashes all 64).** *First run, grace fixed at 10 000 blocks, 11 200 blocks:*
an ordinary block's `validate` 3.77 ms and its `connect` 145 µs; the
slashing deadline (height 11 199) `validate` 12.59 ms and `connect` 1.67 ms
— **3.3×**. *Second run, after the §6 row 5 ruling derived the grace from
the epoch, 1 300 blocks built in 4.3 s (`last_block(12) = 1 299` slashes):*
ordinary `validate` 1.36 ms / `connect` 114 µs over heights 52..199; the
twelve deadline judges rise with the epoch, 1.92 ms (epoch 0) → 9.99 ms
(epoch 11, `connect` 1.74 ms with the 64 slashes written) — **7.3×**
(7.3–7.9 across two runs). The deadline side barely moved between the
regimes (12.6 → 10.0 ms); the ordinary side did (3.8 → 1.4 ms), an empty
block being cheaper to judge 9 000 blocks shallower — so the two ratios
are one measurement of the scan against two baselines, and the honest
reading is the deadline judge's own figure: ~10 ms for 64 records at a
full window, once per epoch, rising roughly linearly as the window fills
(the chain stops at the first slash, so whether it plateaus at `N` is not
measured here).
The bench reads the **ratio**, not the figures: both sides run the same
code on the same machine, and the floor device
(`76-device-provisioning-floor.mdc`) scales both. `ARW-Q1`'s reopening
clause (§8: the scan dominant on the floor **and** attributed to the view
boundary) does not fire; it is re-asked if a run on the floor device shows
the slashing connect dominating its block, which the bench exists to show.

*The alternative, named so the ruling is a choice:* the store applies the
folds itself under principle 3's first clause, as the C++ does. It is
rejected here for the reason above and one more — it would make the store
the only component that knows the challenge schedule, which is the
inversion CEN-L16 was minted to name.

### 3.2 The phase bodies

- **Phase 2, inside `record_tx`** (`connect.rs:493–494`): the three vin arms
  become writes of what the delta carries for this transaction — a
  serve-credit `Present` under `ServeCreditKey(p, shard, epoch, height)`
  (SI-15's persona check is the first belt); a JoinMarket record through
  `open_insert_table(ARCHIVAL_BOND, SI-19)` (insert-once: a second record
  for a persona is the writer's error, CEN-L14 site); Release / Reinstate /
  claim through `open_replace_table(ARCHIVAL_BOND, SI-20)`: a present
  row, its pre-image journaled, an absent persona refused before any
  journal entry. `total_bonded_atomic` is not written (§3.4: a view).
  **As landed (commit 5, 2026-09-30) — written once, after the loop, not
  inside `record_tx`.** The delta carries each persona's **final**
  post-image for the block with the slashes already folded in, so the
  records are written once after the transaction loop from those images
  (`archival_write.rs`). **UPDATE 2026-10-01:** SI-20 is that replace.
  A before/after sum of the same writes is the writes, so it is not
  armed. The credits are written in the same pass; SI-15 is
  the writer's read belt there (a bit for a persona with no record halts the
  connect), beneath CEN-L7's refusal at the input.
- **Phase 5**: `archival_attestation_witness[h] = witness` when the
  verdict's witness is non-empty (`blockchain_db.cpp:669–671`'s rule, A10's
  two absences kept). **Where the witness comes from (on review):** it is
  not in the block. In the C++ it is a **wire sidecar** —
  `block_complete_entry::attestation_witness`
  (`cryptonote_protocol_defs.h:71`, `KV_SERIALIZE_OPT`), carried beside the
  block bytes, handed to connect as `connect.attestation_witness`
  (`cryptonote_protocol_handler.inl:122`), judged by CEN-B4
  (`verify_block_attestation`, `blockchain.cpp:5300`) and only then stored.
  So `Candidate` (`chain-rules/src/block.rs:100–105`: a block and its
  bodies, nothing else) gains the sidecar as a third field,
  `attestation_witness: Option<AttestationWitnessBytes>`, `None` for an
  empty set; the verdict carries it to `connect` — ~~passed through with
  `Origin::PassedThrough` until CEN-B4 lands in `validate`~~ **UPDATE
  2026-09-29 (substrate moved before commit 1): `Fact`/`Origin` and
  `PassedThroughFacts` were deleted with `ConnectFacts` (`08a1e7d7d`), so
  the unjudged witness is recorded as a coverage gap — CEN-B4 in
  `Provenance`'s `rule_coverage_gaps` — until CEN-B4 lands in `validate`**
  (E6's row). This is the better claim, not a workaround, and commit 5's
  text says so: a coverage gap says *B4 is a row in force that the verdict
  did not evaluate* — a statement about **judgment**; `Origin::PassedThrough`
  said *this value came from elsewhere* — a statement about **plumbing**.
  The second was always the weaker claim about the same situation, and the
  scaffold's retirement forced the stronger one. The parity-evidence rule is
  unchanged in effect: a file whose witnesses were written unjudged is not
  evidence, because its coverage gaps are non-empty. The corpus reader
  fills the field `None` for every format-2 capture, which is true of them
  (§1 item 6). The corpus
  cannot carry a non-empty witness today for a second reason worth
  recording: the sidecar travels on the **sync wire** — the get-objects
  answer attaches the stored witness (`blockchain.cpp:2562`), and the Rust
  p2p already models the field (`shekyl-levin/src/payload/block.rs:73`) —
  but not across the **RPC edge** the corpus fetcher uses:
  `/get_blocks_by_height.bin` is Rust-served through the facts FFI since
  RK-4b, and `shekyl_rpc_block_entry` / `shekyl_rpc_types::BlockEntry`
  carry the block and its transactions and nothing else
  (`rpc_facts_ffi.h:216–222`, `bin_commands.rs:216–221`). So a capture with
  a real witness needs the field on both sides of that edge and the corpus
  format to carry it; all three wait on the producer and have their own
  FOLLOWUPS row (beneath the producer's, blocked on it), not built here.
  *(First written as "a one-line RPC marshal in the C++ handler; only the
  p2p handler at `cryptonote_core.cpp:1289` populates it" — corrected at
  source on review: that file no longer serves the endpoint, and that line
  is the core's relay site, empty until the template writer exists.)*
  Phase 5's witness is the scenario's.
- **Phase 9**, in the C++'s order (`:689–693`): the accrual (§3.5); then the
  slashes — each a record upsert plus `archival_slash_applied` insert plus a
  `archival_slash_log` append, and `total_burned += slashed` **through the
  same fold phase 8 uses**, so SI-8 sees one running total with two
  contributors, not two writers (ARW-6); then `archival_last_slash_epoch`
  upserted (its pre-image *is* the epoch marker, §3.3); then the close —
  `r_market` rows, the Σwork row, the budget row, each insert-once for
  `(shard, E)` / `E` (SI-21: the three arrive together or not at all).
- **The epoch-close log** dissolves: `undo_log[h]` holds the rows the close
  wrote, and pop restores them (CTW-2's argument; the C++ needed the log to
  *find* what to delete).

### 3.3 The journals — `ARW-Q2`, default: five dissolve, one is history

SAR-7's question, answered table by table.

| Journal | What the C++ reads it for | Fact, view, or journal | Default |
| --- | --- | --- | --- |
| `archival_emission_claim_log` | pop: restore the claimed set and `first_paying` (`db_lmdb.cpp:6080–6115`) | journal | **dissolved** — the record's pre-image is in `undo_log` |
| `archival_bond_unbond_log` | pop: `release_pop` reconstructs the pre-image (`:6198–6269`) | journal, plus a Rust *pop fold* | **dissolved**; `release_pop` deleted (its only caller was this revert) |
| `archival_bond_holdings_update_log` | nothing — HoldingsUpdate is REJECTED, the revert is a named no-op (`blockchain_db.cpp:773–776`; `db_lmdb.cpp:6270–6289`) | dead | **deleted** |
| `archival_bond_reinstate_log` | pop: `reinstate_pop` (`:6342–6400`) | journal + pop fold | **dissolved**; `reinstate_pop` deleted |
| `archival_epoch_close_log` | pop: which epoch this height closed, to delete its rows (`:7888–7920`) | journal | **dissolved** |
| `archival_slash_log` | pop (`:5823–6002`) **and** forward, as history: `holds_shard`'s *"not held at tip ⇒ held at `h` iff a logged slash strictly above `h` removed it"* (`:4804–4870`); the epoch-marker row records the first epoch a height folded, for the revert's span (`:5784–5812`) | **fact** — the only record of when a shard left a record | **kept and typed**: `(BlockHeight, JournalSeq) → Coded<SlashLogEntry>`; the marker row kind **deleted** — its job (rewind `last_slash_epoch` to the pre-fold value) is the cell's own `undo_log` pre-image |

`archival_slash_applied` (`(p, shard, E)` — *has this slash already been
applied*, read by `archival_challenge_failed_at_height` at `:5471`) is a
**fact** the scheduler needs and a set: typed `SlashAppliedKey → Present`.

*Why the slash log survives the test that killed the others:* delete a
journal and pop still works, because `undo_log` has the bytes; delete the
slash log and `holds_shard_at(h)` for a past `h` has no answer — the record
says what is held *now*. A view would have to be reconstructed from
`undo_log`, which is engine-local and retired at `tip − D_max`; the history
must outlive the reorg window because the read reaches back to `E_add`.
That is a fact, and it is kept. (`ARW-Q2`'s open half: whether **any**
consumer of as-of-height holdings survives `PDM-Q3`'s re-key of the
serve-credit rule. J8's operand is *held at `H_fire`*; if slice 8's
re-keyed J8 keeps that operand — the default — the history stays. If it
does not, the table dissolves with the fold and CEN-L16 moves to bucket 3.
Stated so the ruling is made against slice 8's rule, not this lane's
convenience.)

### 3.4 Fact, or a view of facts I already hold? — every inherited table

`DRS_E3_CURVE_WRITER.md` §3.7's test, applied to the seventeen.

| Table / cell | Verdict | Disposition |
| --- | --- | --- |
| `archival_bond` | **fact** | typed (E1); written at phase 2 and phase 9 |
| `archival_serve_credit` | **fact** (a pass bit keyed by the block it rode in) | typed (E1); written at phase 2 |
| `archival_r_market`, `archival_sigma_work`, `archival_budget` | **fact** per closed epoch — the fold's output over a snapshot that pop can change | typed (E1); written at phase 9, insert-once |
| `archival_attestation_witness` | **fact** (received evidence, unreproducible on a losing branch — `ARCHIVAL_SETTLEMENT_WRITER.md:529`) | typed (E1); written at phase 5 |
| `archival_last_slash_epoch` cell | **fact** — the scheduler's watermark | typed (E1); written at phase 9 |
| `archival_budget_accrual` | **view** of the emission split the verdict carries, read once — by the close's range-sum (§3.5) | **dissolved** into a per-epoch accumulator row (`ARW-Q3`) |
| `total_bonded_atomic` cell | **view** — `Σ bonded_total` over `archival_bond`; **no reader** outside the writers that maintain it (`blockchain_db.cpp:313`, `:943`; `db_lmdb.cpp:5610–5613`) | **not written**; a `total_bonded()` read sums the table (`ARW-Q9`: no cell). **UPDATE 2026-10-01:** SI-20 does not re-sum. An `Update` goes through `ReplaceTable`; an absent persona is `BondRecordAbsent` before any journal entry |
| `archival_slash_applied` | **fact** (a set) | typed `Present` |
| `archival_slash_log` | **fact** — history (§3.3) | typed |
| four revert logs + `archival_epoch_close_log` | journals | **dissolved / deleted** (§3.3); `NOT_PORTED` rows with the reason |
| `archival_shard_segment` | retired (`PDM-Q12`, SAR-5) | **deleted**; CEN-L10 → bucket 3 |
| `archival_settlement` | **fact** with no writer until SO-D8's cutover and no reader (`SO-D8` §5.1) | **held `Unshaped`, blocker named** — falsify by the cutover PR; not shaped (SAR-Q1's ground), not deleted (its production caller is a rule-22 hold, not an absence) |
| `archival_alt_attestation_witness` | folded into `alt_blocks` (S-ALT) | unchanged |

Net: three tables typed (`slash_log`, `slash_applied`, the accumulator), six
deleted (`shard_segment`, the four dead journals, `epoch_close_log`), one
dissolved (`budget_accrual`), one held; `tables.snap` moves by **−7 + 1**;
the `NOT_PORTED` register gains seven rows and `RUST_ONLY_TABLES` one; layout
~~16 → 17~~ **17 → 18** (as built: slice 7 wave B took 17 for the
`ConnectFacts` deletion before this increment started). The seven rows are
two relationships under one direction — five journals whose function
`undo_log` performs, two tables retired by ruling or re-keyed — and each
row's reason leads with which, because the gate reads them the same and a
reader looking for the data must not (found in `undo_log` vs. held nowhere).

**Which bijection direction each deletion is — decided here, not at the
gate (2026-09-29, on the maintainer's question).** "Dissolved into
`undo_log`" is **not** S-ALT's fourth direction (`FOLDED_INTO`: *the bytes
live as a field of the host's record*, `schema.rs:27–38`) and not a sixth —
it is the **fifth**, `NOT_PORTED` (`schema.rs:47–59`: *the job the table did
for LMDB is done here by a function, **by the undo journal**, or by a table
that already holds the facts*), minted by E3 for exactly this relationship
with `pending_tree_drain` and `block_pending_additions` as its precedent
rows (CTW-3). The distinction matters because a `FOLDED_INTO` row naming
`undo_log` as host would **pass the gate mechanically** — `UNDO_LOG` is a
definition in the file — while making a false claim: `undo_log` holds
pre-images of the *bond record*, not the `Archival*RevertValue` bytes; the
requirement (reversibility) is met by a mechanism, and the bytes are not the
same bytes. So: the four revert logs and `archival_epoch_close_log` →
`NOT_PORTED` (reason: the undo journal); `archival_budget_accrual` →
`NOT_PORTED` (reason: `archival_budget_accruing`, a `RUST_ONLY_TABLES` row —
E3's `pending_tree_leaves` / `curve_tree_leaf_counts` pair is the precedent
for a re-keyed job); `archival_shard_segment` → `NOT_PORTED` (reason:
retired, `PDM-Q12`; the register says of itself it is not a deletion
register and the C++ table lives until cutover). The slash log's marker row
kind is not a table and enters no register; its retirement is the codec's
doc (`SlashLogEntry` admits one kind). A sixth direction is not needed, and
would have been the widening the question warned against.

### 3.5 The accrual — `ARW-Q3`, default: one row per epoch, not one per height

The C++ writes a row per block and range-sums it once at the close
(`db_lmdb.cpp:7830–7864`), deleting the block's row on pop
(`blockchain_db.cpp:790`). Nothing reads a single height's accrual. The
dissolved shape: `archival_budget_accruing[E]` — one `Coded<AtomicUnits>`
row per open epoch, upserted every block with the pre-image journaled; the
close reads it, writes `archival_budget[E]`, and **deletes the accruing
row in the same transaction** (`ARW-Q3`'s second half, posed on review and
**RULED 2026-09-29** — the first half asked only per-height vs per-epoch): the
table then holds **at most one row, the open epoch's**, which is the
invariant SI-23 states and the digest's normalisation reads (§3.8 item 1);
leaving closed accumulators would be a second copy of `archival_budget[E]`
and the fact-or-view test refuses it. Pop of a block restores the
accumulator's pre-image; a pop across the close restores the budget row's
absence **and the accruing row the close deleted**, both from `undo_log`; a
re-close re-reads it. `ARCHIVAL_BUDGET_SCHEDULE.md` §3.2's KAT B3 (pop-and-re-close
reproduces the budget byte-identically) is the test, and it must pass on
the new shape before the old one is deleted.

The value written is the verdict's `staker_emission + staker_pool_amount`.
~~Until CEN-F17 lands (slice 7 wave B, on this increment's operand — §3.7),
the burn term is what `burned` already is: a `Fact` with
`Origin::PassedThrough`, one more row in `DELETED_BY` naming F17. Disclosed
here (rule 22): the accrual is half passed-through at landing, the file
says so in `passed_through_facts`, and the E2 grade is not archival parity
evidence until F17 derives the other half.~~ **UPDATE 2026-09-29 (substrate
moved before commit 1): CEN-F17 landed (slice 7 wave B, PR #907) and
`Fact`/`Origin` were deleted with `ConnectFacts` (`08a1e7d7d`), so the
accrual is fully derived at landing** — both halves of the sum are the
validator's own — and the disclosure above is discharged, not carried.
F17's operand was still leaf-based (`frozen_segment_count(leaf_count_at)`)
at commit 1; **commit 3 re-keyed it** to the closed shard count off
`cumulative_tx_count` and the height, and **commit 4's merge of the
`SHT-Q2` build re-keyed it again** to `shard_of(cumulative_archival_len)`
per `ARW-Q6` (§3.7).

### 3.6 The close's absences — `ARW-Q4`, default: write what the fold returns

`r_market[i] == 0` is skipped by the C++ (`db_lmdb.cpp:7804`); the budget row
is written unconditionally *because* a present-and-zero row means a closed
zero-budget epoch (`:7830–7833`). SAR-8 fixed the read: `None` ≠ 0. The
write side follows the read: **every `(shard, E)` in the close's snapshot is
written, zero included**, so A6's `None` means exactly "this epoch did not
close with this shard in it" and slice 8's `SAR-Q6` question is askable from
the rows, not only from the type. The archival digest (§3.8) projects
zero-rows out on both sides so the C++ tip still compares — the digest is
the parity oracle over what the C++ *has*; the belt over what the Rust
store *means* is SI-21.

### 3.7 The shard universe — `ARW-Q6`, default: closed shards, read off the chain

*Operand amended 2026-09-29 (`SHT-Q2`, the banner) and **built 2026-09-30
(commit 4, in the merge that brought the `SHT-Q2` build into this branch)**:
`closed_shards_before(view, connecting) = shard_of(C(parent))` over
`block_info.cumulative_archival_len`, through `shekyl_types::shard_of` — the
prune's cell and function, one definition — and a closed shard's age operand
is `shard_close_height(view, k, parent)`, the smallest `h ≤ parent` with
`C(h) ≥ shard_start(k + 1)`, a binary search over the same fold whose only
fault is `Corrupt::ShardCloseUnplaced` → SI-13 on the archival cell. **The
C++ validator does not follow.** LMDB keeps no archival fold, and rule 20
refuses adding one to the C++ — so `Blockchain::parent_frozen_segment_count`
stays on the frozen J-segment count, wrapped as `ClosedShardCount` at the one
FFI marshalling site (`economics_ffi.rs`), and commit 3's C++ half
(`parent_closed_shard_count`, `shekyl_archival_closed_shard_count`) is
deleted with the `T`-keyed frontier it read. That is CEN-L10's divergence,
already re-graded DIVERGENT-and-intended by the `SHT-Q2` build: bit-identical
while the escalation ships flat (asymptote = floor), closed by the cutover
that deletes the C++ path. The paragraphs below are the count-era statement
as ruled at commit 3 — SUPERSEDED 2026-09-30, kept as the record of the
coinbase-term defect and its lesson.*

Two consumers of the retired leaf partition sit on this surface: the
complete-tree slash arm (§1 item 9) and CEN-F17's `n` (§1 item 8,
FOLLOWUPS `:727`). Under `PDM-Q6` item 5 both become the closed shard count
at a height, read from `block_info` — a `ChainView` read that already exists
in substance (`cumulative_tx_count` is store-derived, `connect.rs:411–418`).
No table, no freeze, no `frozen_segment_count`.

**The formula, corrected at commit 3 (2026-09-30) — SUPERSEDED the same day
by the `W` re-key above; retained as record.** The pre-flight wrote
`⌊cumulative_tx_count(h) / T⌋`. That omits the coinbases: shards partition
**storage ids** (`consensus_constants.json` `_comment_archival_shard_tx_count`:
"dense over every recorded transaction (one coinbase per block plus the
listed ones)"; the C++ issues `tx_id = get_tx_count()` to the coinbase and
the listed alike, `db_lmdb.cpp:1082`), and `cumulative_tx_count` counts the
listed only. So

`closed_shards_through(h) = ⌊ storage_ids_through(cumulative_tx_count(h), h) / T ⌋ = ⌊ (cumulative_tx_count(h) + h + 1) / T ⌋`,

and it has **one home**, `shekyl_types::closed_shards` /
`closed_shards_through` — the same crate that owns `T` and
`storage_ids_through`, so the frontier cannot be re-derived at a call site
with the coinbase term dropped (the defect this round met three times under
three names; §10 2026-09-30). `shekyl_chain_rules::closed_shards_before`
reads it at parent state for F17; `prune.rs`'s slash scan and the C++
`parent_closed_shard_count` (`shekyl_archival_closed_shard_count(get_tx_count())`)
name the same function. The overflow of the id total is
`Corrupt::StorageIdsOverflow` → SI-8's class (`FoldOverflow`), a validator
belt on a store invariant, not a new row.

The defect was not new to the tree. S-PRUNE met it at build and recorded
the correction in a ratified charter (`DRS_E1_SPRUNE.md` SPR-1, 2026-09-25,
`first_tx_id(h) = storage_ids_through(cumulative_tx_count(h−1), h−1)`);
this pre-flight, four days later, read the C++ and the census and re-derived
the frontier without it. A recorded formula did not reach the next author;
a function every site must call does. Stated as the general form in
`05-system-thinking.mdc` ("A formula two lanes need is a function, not a
row"; "The C++ is a template, not a source").

**What commit 3 did not delete, and why (rule 22).** The §6 row scheduled
`segment_leaf_count` out of the JSON and the consensus-side
`leaves_per_segment` readers deleted. As landed, the Rust consensus closure
has no reader (`rg 'leaves_per_segment|SEGMENT_LAYER_J|frozen_segment_count'
rust/shekyl-chain-rules rust/shekyl-chain-store rust/shekyl-chain-ingest`
→ nothing; the E3 §6.1 falsifier now holds on the ingest crate too), but
`segment_freeze.rs`, `shekyl_archival_frozen_segment_count` and the JSON key
stay: their remaining callers are the C++ freeze pipeline and the coverage
RPC (`db_lmdb.cpp:7408–7490`, `src/rpc/archival_shard_coverage.cpp:34`,
`blockchain.cpp:4885–4950`), gated by `check_segment_freeze_sites.sh`, and
§3.9's timing rule is that the C++ deletes at cutover. Re-scheduled to the
cutover commit, blocked on that deletion — falsify by
`rg shekyl_archival_frozen_segment_count src/` returning nothing while the
Rust symbol still exists. `DRS_E3_CURVE_WRITER.md` §3.9's "scheduled here"
moves by the same one step. CEN-F17 has its operand; the rule stays E6's.

### 3.8 The §7.1.1 discharge — `ARW-Q5`, default: an archival digest family, tip-compared, plus the stamp

The gate names two acceptable forms: digest coverage over the archival
families, or a named exclusion with a **replacement KAT that forces
apply/revert to run**. This increment lands the first and makes the
existing mechanism for the second real:

1. **`digest_v1`** — v0's three families plus the archival state as
   *logical* sets: bond records (`p → canonical record`), serve-credit
   keys, `(shard, E) → r_market` with zero-rows projected out (§3.6),
   `E → Σwork`, `E → budget`, **the open epoch's accrued total** (on review:
   the accumulator is the input to the next close, and a missing or wrong
   accrual write would otherwise match at every pre-close tip — the C++
   side normalises its per-height rows over `[E_open·SEB, tip]` to the same
   one logical value, the redb side reads its one accruing row), `h →
   witness`, the slash log, `slash_applied`, `last_slash_epoch`. Computed by
   the C++ walker over LMDB
   (`BlockchainLMDB::logical_state_digest_v0`'s sibling, a marshal into the
   Rust hasher — rule 20's shim, no C++ hashing) and by `ReadSnapshot` over
   redb; format tag bumped; the trace's checkpoint carries both. Tip-only,
   because that is what the C++ can produce (§1 item 5).
2. **The sufficiency stamp armed**: with writers present, a session that
   stubs family X skips X's phase body and widens `Provenance.stubbed`
   (`ARW-9`'s default), and the run's digest goes **red** against the
   oracle — the test that proves the apply ran. **Its denominator, stated
   on review:** a stubbed family the run never writes leaves the digest
   unchanged, so "red once per family" is only a claim over families the
   run *exercises*. The test therefore has two halves, and the first is
   rule 47's: (a) **every retained writable family names its exercising
   witness** — `bond`, `r_market`, `sigma_work`, `budget` and the accruing
   row by the corpus (`bond-post`, `emission-claim`); `serve_credit`,
   `slash_log` / `slash_applied` and the `last_slash_epoch` cell, the
   Release / Reinstate arms of `bond`, and `attestation_witness` by the
   scenario driver (§2.4 — no capture carries them); a family with no
   witness fails the test before any stub is tried; (b) **for each, stub it
   and the run over its witness is red**. Families outside the denominator
   are named, not silent: `settlement` (held, SO-D8's blocker) and the
   seven `NOT_PORTED` rows (no writer exists to stub). **The witness list is
   derived from the family set, never maintained beside it** (the check the
   maintainer asked for, 2026-09-29): the test is an exhaustive `match` over
   `ArchivalFamily` — every arm returns `Witness::Corpus(shape)`,
   `Witness::Scenario(fn)`, `Held(blocker)` or `NotPorted` — so a family
   added to the X-macro without a witness arm is a **compile error**, not a
   quiet green; `ArchivalFamily::ALL` is the iteration and the `match` is the
   assertion. A parallel `const WITNESSES: [...]` would be the collapsed
   observable one step removed.
3. **The injected serve credit as an event**: the `emission-claim` chain's
   archival state includes a write no block made (§1 item 6). The corpus
   format gains an out-of-band event — `IngestEvent::Inject(ServeCredit
   { p, shard, epoch })` at its capture position (`source.rs:70`, the
   event model RD-Q13 built for reorgs; the exporter reads the injector's
   receipt) — and the store exposes the injector as what S-ARCH #18 said it
   would be: the writer's own test hook, the regtest-only door that writes a
   bit the rules did not admit, refused off Fakechain exactly as the C++
   refuses it (`blockchain.cpp:4715`). Without this, the one chain that
   exercises the close and the claim diverges at the tip by design and the
   digest family lands measuring nothing.

   **What the event must not become (ruled with `ARW-Q5`, 2026-09-29).** An
   `Inject` makes *one* un-replayable write replayable by recording it as a
   first-class event; the hazard is that it becomes a general door — any
   state the replay cannot reach gets an `Inject` instead of a question
   about why it cannot. So the variant carries a **stated scope**, in its
   type and its doc: **regtest-only** (refused under any other `ChainRules`),
   **one row kind** (the serve-credit bit; a second kind is a second variant
   with its own ruling, never a payload enum), **the injector its sole
   producer** (the exporter reads the injector's receipt; nothing else
   constructs one). And a check that it appears in **no captured chain but
   the one**: the manifest half landed with this pre-flight — every
   `manifest.json` now carries `out_of_band_writes`, `[]` for the five
   block-derived chains and the injected row for `emission-claim`, and
   `vectors_tests::only_the_named_chains_carry_out_of_band_writes` holds the
   list in both directions (the generator writes the field from the
   injection it made, `regtest_e2e.rs` `maybe_capture_chain_vector`); the
   trace half — an `Inject` present iff the manifest lists one — lands with
   commit 7. **Ordering (on review):** an `Inject` is a **pipeline barrier**,
   exactly as `Rewind` is (`IngestEvent::is_barrier`, `source.rs:70–98`;
   the sequencer drains formation around a barrier, `pipeline.rs`): every
   `Extend` before it commits first, the injection is applied in its own
   store transaction at the committed tip's height — the height it records
   — and formation of the `Extend`s after it waits, because the injected
   bit is state the later claim's admission and the close read. It is
   **not journaled**: the C++ injection is not pop-reversible either (a pop
   below the injection height leaves the bit; the generator keeps its pops
   above it, `regtest_e2e.rs:3323–3327`), and a `Rewind` in the same run
   to a height below an `Inject`'s is a `PipelineFault`, not a defined
   behaviour — the corpus cannot contain one, and the semantics of orphan
   state under a reorg are not something the replay should invent. The corpus travels, and the inference is drawn where the data
   is: a reader of `emission-claim/manifest.json` learns that one of its rows
   is not block-derived without opening this document.

*What the discharge does not claim:* parity on serve-credit transactions,
Releases, Reinstates, slashes (no corpus has them, §2.4) — those families'
witnesses are the scenario driver's, and the stamp is the only §7.1.1
instrument over them.

### 3.9 The deletion surface

C++ (`db_lmdb.cpp`): the appliers and reverters `:4486–4560` (accrual,
`total_bonded`), `:4737–4766` (serve credit), `:5111–5300` (bond record,
slash applied, slash log), `:5301–6002` (baseline, window, challenge,
`apply_archival_slash_one`, scheduler, revert), `:6003–6400` (claim, unbond,
holdings-update no-ops, reinstate), `:6658–7166` (the deletes, settlement,
epoch prune, watermark), `:7167–7520` (frozen count, freeze pipeline),
`:7521–7920` (gathers, close, revert), `:9085–9128` (witness);
`blockchain_db.cpp:285–371`, `:631–638`, `:655–693`, `:705–736`, `:744–790`,
`:808`, `:880–889`, `:923–948`, and the pure virtuals; `shekyl_types.h:594–1031`
(five `Archival*RevertValue` codecs) and the `ArchivalBondValue` v7 codec
(its corpus is captured — `codec/archival.rs:70`); the injector's LMDB write
(`blockchain.cpp:4709–4740`); the serve-credit verifier's leaf read
(`PDM-Q3`). Rust: `release_pop`, `reinstate_pop` (`bond_connect.rs:257`,
`:396`), `segment_freeze.rs`, the freeze half of `challenge.rs` / `path.rs`,
`shard_coverage.rs`'s freeze operand, and every `shekyl_archival_*` FFI
export whose only caller was the C++ above (`shekyl-ffi/src/archival_ffi/`).
**Timing**: the C++ deletes at cutover, when the Rust daemon is consensus
(`DRS_E1_SPRUNE.md` §13's rule); the Rust pop folds and the freeze half
delete **in this increment** (no caller survives the C++'s retirement, and
they are not reference implementations of anything).

---

## 4. Store invariants this increment builds or restates

| Row | Statement | Armed where |
| --- | --- | --- |
| SI-15 | serve-credit rows are keyed by a persona with a record | built (E1); the **writer's** check **landed at commit 4** — `archival::transition` refuses a credit for an unknown persona at its input (CEN-L7's first backstop), and the E1 read-side walk is the belt; **at commit 5** the writer reads `archival_bond` for every credit it writes (phase 2) and the regtest injector refuses a persona with no record (`InjectionForUnbondedPersona`) — a bit for a stranger would be this row at the next read |
| SI-19 (new) | **a persona has at most one record, and a JoinMarket is the only insert** — `archival_bond[p]` is insert-once; every later change replaces a present row and journals that pre-image | phase 2 (`open_insert_table` for JoinMarket, `open_replace_table` otherwise); CEN-L14 site 2 |
| SI-20 (new) | **an `Update` names a persona the table holds** — `ReplaceTable`; an absent persona is `BondRecordAbsent` before any journal entry. **UPDATE 2026-10-01:** the sum check ruled here was an identity (a scan of the writes just performed) and is not armed. `ARW-Q9`'s no-cell half stands: the total is the rows | phase 2, at the replace handle |
| SI-21 (new) | **an epoch closes whole**: `archival_sigma_work[E]` and `archival_budget[E]` exist together with every `(shard, E)` r-market row the snapshot named, or none does | phase 9 (insert-once on `E`; a second close of `E` is `StoreInvariant`, never a silent overwrite — CEN-L14's O-2 adversary) |
| SI-22 (new) | **the slash log is dense per height** — `(h, seq)` rows for `seq ∈ [0, n)` and no other (`SlashFault::NotDense`, display names `archival_slash_log`), and every row's `(p, shard, E)` is in `archival_slash_applied` (`SlashFault::AlreadyApplied` per key, display names `archival_slash_applied`). **UPDATE 2026-10-01** | phase 9 |
| SI-23 (new) | **the accruing table holds at most one row, the open epoch's** — the close deletes `archival_budget_accruing[E]` in the transaction that writes `archival_budget[E]` (§3.5); a second row is a close that did not finish or a re-key | phase 9 |
| SI-6 | pop-ability is `undo_log[h]` — restated: **no archival table is a second pop mechanism** | by construction (§3.3); falsifier: a `Restorable` impl that reads an `archival_*_log` |

Every one is a *store* property; whether a slash was due or a close was
correct is the validator's (§3.1).

---

## 5. Round-0 findings

| Finding | Statement |
| --- | --- |
| **ARW-1** | **The corpus's only closed-epoch chain is priced on a write no block made.** `emission-claim`'s serve credit is the regtest injector's direct LMDB write (`regtest_e2e.rs:3330` (`:3325` at the pin), `core_rpc_server.cpp:958`); a block-driven replay cannot reproduce it, so an archival tip digest over that chain diverges by construction unless the injection is an event in the trace (§3.8 item 3). Found by reading the generator, not by running the replay — which would have reported a red that looked like a writer bug. **Confirmed at the line 2026-09-29 (maintainer, PR #904): `blockchain.cpp:4734–4735`, a bare `db_wtxn_guard` and `set_archival_serve_credit_bit` under the blockchain lock, outside any block's write batch.** Its value is the misdiagnosis it prevents: the divergence would have appeared at exactly the height a writer bug would produce one, on the one chain that exercises a closed epoch, and the natural response would have been to hunt the writer. It also bounded a claim the corpus had been carrying — `captured_by_daemon_version` and `built_at_dev_sha` assert what tree produced a chain; nothing asserted every row in it was block-derived — so every manifest now carries `out_of_band_writes` (§3.8), for the same reason the epoch-0 caveat went into the manifest and not only into a plan. |
| **ARW-2** | **Five of the six revert logs are CTW-2/CTW-3's shape; the sixth is history.** `undo_log` holds every pre-image the C++ journals recompute or copy; `release_pop` and `reinstate_pop` exist only to reverse what a pre-image restores. The slash log alone is read forward (`holds_shard`), and its epoch-marker row kind exists only because the C++ had no pre-image of `last_slash_epoch` (§3.3). |
| **ARW-3** | **The C++ decides in its storage class in three places, not one.** CEN-L16 minted the holds-shard fold; the challenge-failure decision (`archival_challenge_failed_at_height`, `:5459`) and the shard-enumeration of the slash scan (`:5720–5752`) are the same class — consensus predicates evaluated by `BlockchainLMDB` with no R8 row. The sweep that minted L16 covered reads; these are writes' preconditions. One census question, not three (the FOLLOWUPS sweep-subject row `SAR-Q7` opened). |
| **ARW-4** | **The complete-tree slash arm walks the retired freeze registry.** `db_lmdb.cpp:5720–5744` enumerates `archival_shard_segment` to name a `CompleteTree` bond's shards; `PDM-Q12` retired the table. Under `PDM-Q6` item 5 the universe is the closed shards at a height — `shard_of(cumulative_archival_len)` since the `SHT-Q2` re-key at commit 4 (*was `⌊storage_ids / T⌋` at commit 3, the ids including the coinbases; pre-flight wrote `⌊cumulative_tx_count / T⌋`*; §3.7, §10) — a view the store already holds. |
| **ARW-5** | **The accrual table is a view read once.** Per-height rows, one consumer (the close's range-sum), one deleter (pop). A per-epoch accumulator is the fact (§3.5). |
| **ARW-6** | **Slash burns into the cell phase 8 owns.** `total_burned += slashed` (`db_lmdb.cpp:5615–5618`) inside the slash apply; `connect` folds `burned` into the same cell (`connect.rs:449–457`, SI-8). Two writers of one running total in one transaction is the SI-8 hazard; the slash contribution goes through the one fold. |
| **ARW-7** | **`total_bonded_atomic` has no reader.** Both `get_total_bonded_atomic` callers are the writers maintaining it (`blockchain_db.cpp:313`, `:943`; `db_lmdb.cpp:5610`). A running total nobody reads is a view with a corruption surface and no consumer; not written (§3.4). |
| **ARW-8** | **The close writes zero as absence.** `r_market == 0` skipped at `:7804` while the budget row is written *because* zero must be distinguishable (`:7830–7833`) — the same file, two conventions, one screen apart. SAR-8's read-side fix needs its write side (§3.6). |
| **ARW-9** | **The stub refusal has no caller-side semantics.** `admit()` returns `StoreCannot::FamilyStubbed` (`write.rs:395–405`); nothing catches it, because nothing writes. The mechanism's own doc says a stubbed apply is *skipped* and *widens the provenance*; the error today would abort the connect. E4's phase bodies decide: skip-and-widen (default — it is what makes the sufficiency red attributable) or abort. **RESOLVED at commit 5 (2026-09-30): skip-and-widen** — each phase body asks `ApplyPolicy::applies` before opening a family's table and the commit widens the file's provenance with the stubbed set; `archival_budget_accruing`, Rust-only, is governed by `ArchivalFamily::BudgetAccrual`; a belt that reads across families (SI-15 reads `archival_bond`) runs only when both apply (`archival_write.rs` module doc; witnessed in `archival_write_tests`). |
| **ARW-10** | **The graph argument in S-ARCH §3.4 has lapsed.** `shekyl-chain-rules` depends on `shekyl-archival-retention` (`Cargo.toml:55`) and the store on the rules crate, so the retention crate is in the store's closure. The conclusion (`BondRecord` in the store's codec) held on rule 18's *readers* test, not the graph; that test flips when slice 8 reads the record through `ChainView` (`ARW-Q8`). |
| **ARW-11** | **The epoch prune is nobody's.** `prune_archival_epochs_before` and its watermark (`db_lmdb.cpp:7084–7166`) are neither S-PRUNE's (bodies, undo rows) nor the close's in redb; the C++ watermark's one consumer is the pop floor `pop_target_allowed` (`blockchain_db.cpp:705–736`), which SI-6's undo floor already provides. Whether closed-epoch rows are pruned at all is `ARW-Q7`. |
| **ARW-12** | **Phase 5 has nothing to write on any chain that exists.** The attestation producer is unbuilt (FOLLOWUPS `:139`); every captured witness is empty; the body's only witness is a scenario that supplies one. Recorded so a phase that writes zero rows across the whole corpus is not read as verified. *Stands at commit 5:* the body writes a `Candidate.attestation_witness` (`shekyl_types::archival::AttestationWitness`, non-empty by type) that only `archival_write_tests` supplies; every capture carries `None`. |
| **ARW-13** | **The serve-credit rule the corpus was captured under is retired.** J8–J10 as the C++ runs them sign the leaf preimage `PDM-Q6` item 4 re-keyed; no chain the C++ daemon can capture carries a record the Rust rule will accept. Serve credits are Rust-first (§2.4) — the C++ is not an oracle for them, and this document does not pretend otherwise. |
| **ARW-14** | **HoldingsUpdate is dead in three places at once.** REJECTED 2026-09-20 (immutable bond); the appliers are no-ops (`db_lmdb.cpp:6270–6289`), the revert is a "named no-op so pop order stays explicit" (`blockchain_db.cpp:773–776`), the journal table is empty by construction, and CEN-J17 / J13's drop arm describe it as live. Deleted here; the census rows are slice 8's to re-key (rule 23: REJECTED keeps the name in the contract, marked). |
| **ARW-15** | **The archival schedule was consensus data the validator read off a process latch.** *(Found 2026-09-30 by the corpus, after round 0; ruled the same day.)* The transition needs the epoch geometry — `H_open`, `H_close`, the claim's `current_settled` — and the crate reached for `shekyl_archival_retention::effective_settlement_epoch_blocks()`, a process-wide latch the daemon arms from the environment on Fakechain, while the same `RuleSet` already carried the reorg cap as data (SPR-8) and refused a cap outside the epoch (SPR-9) against a *constant*. `emission-claim` was captured under `SEB 512 / cap 64`; a replay whose rule set could not name that schedule judged its claim for epoch 1 at height 1025 as *unsettled* (epoch 0 under 10 000) and refused the block at CEN-L7. **Ruled: the settlement schedule is rule-set data**, in rule 71's form — the same type on every network, a different value on Fakechain. `SettlementEpochBlocks` (`shekyl-types::archival`, `NonZeroU64`; the store's codec for it in `shekyl-store-codec`, where the orphan rule puts it) and `SettlementSchedule` (retention, the geometry as a value); `RuleSet.settlement_schedule`, read by the transition and by nothing through the latch; `FakechainSchedule` the validated `(SEB, cap)` pair — `fakechain(fixed, schedule)`, `fakechain(None, PRODUCTION) == GENESIS`; the store opens off the set (`Horizons::under`) and checks the pinned epoch at every `connect` (SCW-2's belt moved to where the set arrives, `SettlementEpochMismatch`); `ChainRules::Regtest` carries the pair and refuses it off regtest as it refuses `--fixed-difficulty` (`RegtestLeverRefused`); `shekyl-chain-replay` takes `--settlement-epoch-blocks`/`--reorg-cap` as one; the manifests move to `format_version 3` and record what the capture ran, so the replay judges under the schedule the chain was built under. The latch stays where the daemon, the FFI and the wallet read process configuration (`SettlementSchedule::effective()`, one arming site); the validator no longer reads it. **What the run also showed:** two refusals shared one locus — under the corrected schedule the same claim refuses again because the JoinMarket's record is derived on the verdict and not yet written (commit 5); a `Locus` alone could not tell them apart, and the debug that did is not a test. Noted for commit 8's oracle, not ruled here. |

### 5.1 Reproduced deviations on this surface (DRS §7.6 item 1)

None reproduced: nothing writes these tables yet. C++ behaviours **not**
carried, each with its reason: the five pop journals and the pop folds
(ARW-2), the epoch-marker row kind (§3.3), the per-height accrual rows
(ARW-5), the `total_bonded_atomic` cell (ARW-7), zero-as-absence at the
close (ARW-8), the registry walk (ARW-4), the epoch prune and its watermark
pending `ARW-Q7` (ARW-11), the HoldingsUpdate arms (ARW-14), the injector's
direct write in production (§3.8: a regtest door on the writer, refused off
Fakechain). None is a deviation to grade, because none is consensus; the
consensus content — which record, which bits, which close rows, which
slashes — is what the digest grades.

### 5.2 Things not done here, each with the instance that taught it

- **No `Mock*` archival state.** A bond record's witness is a bond post the
  driver mines or the corpus carries; `50-testing.mdc`'s line applies.
- **No shaping of a table with no writer and no reader** — `archival_settlement`
  stays `Unshaped` with SO-D8 named (SAR-Q1's ground).
- **No constant from a library, no consensus numeric in two idioms**
  (`CTW-Q7`, SPR-10): `T` stays in the JSON (it passes the
  nameable-differently test); `segment_leaf_count` leaves it.
- **No C++ deletion before cutover** (`DRS_E1_SPRUNE.md` §13); Rust callees
  with no surviving caller go now.
- **No deferral to an unscheduled owner.** Every row this document touches
  names a live doc or a slice.
- **No `REWRITE-NOTE` that instructs.** What the rewrite owes is §6.

---

## 6. Commit sequence and the expectation, written before the work (rule 90; one PR — or two, at the seam §6.1 names)

The signal: **past ten is the signal that the substrate was not as finished
as this table claims.** The substrate — journaled handles, typed reads, the
record codec, the retention folds, the replay driver with an event model —
is built. What E3 did not have and this lane does is a second half in
another crate's idiom (the C++ digest walker) and a corpus that needs a new
event kind; those are the two commits most likely to grow.

| # | Commit | Cost | What would make it larger |
| --- | --- | --- | --- |
| 1 | **Tables and types.** `archival_slash_log`, `archival_slash_applied` typed; `archival_budget_accruing` added (`RUST_ONLY_TABLES`); seven tables leave as `NOT_PORTED` rows — the fifth direction, not `FOLDED_INTO` (§3.4's last paragraph says why); `total_bonded_atomic` not minted; layout 18 (predicted 17; wave B took it); snapshots; SI-19…23 minted. `BondRecord` and its vocabulary to `shekyl-types` (`ARW-Q8`). | M | a hidden reader of a deleted table (falsify: `rg` each name outside `schema.rs` and `apply_policy.rs` before cutting) |
| 2 | **`ChainView` grows the archival reads** (§2.3) — trait, `BatchView`, `MockView` held to each other by the conformance test; A2 `slash_log_after` and `holds_shard_at` land (the `SAR-Q7` pair), with the LMDB as-of-height cases (`archival_substrate_lmdb.cpp:1674–1893`) as Rust tests. *As landed:* nine trait methods, no defaults; `MockView` answers honest empties only and the conformance test holds both views to the *same* empties over a bond-less chain; `PassCount` / `ServedShard` moved to `shekyl-types::archival` for the trait to name them; the fold in `shekyl-archival-retention::held_at_height` with five LMDB cases; the C++ fold stays live (CEN-L16 says both). | M | `MockView` needing archival state it cannot construct honestly — the signal that a `Mock*` is being built (§5.2) |
| 3 | **The shard universe** (§3.7): `closed_shards` on the view; CEN-F17's operand ruled; `segment_leaf_count` out of the JSON; the consensus-side `leaves_per_segment` readers deleted. *As landed (2026-09-30):* one owner of the closure frontier in `shekyl-types` (`closed_shards`, `closed_shards_through`), the formula corrected to count the coinbases; `closed_shards_before` / `closed_shards_through` on the view in `shekyl-chain-rules`, `Corrupt::StorageIdsOverflow` → SI-8; `ClosedShardCount` replaces `FrozenSegmentCount` through economics, block-template, ingest and the FFI; the C++ `parent_closed_shard_count` reads `get_tx_count()` through the new `shekyl_archival_closed_shard_count`, one change with the Rust. ***Re-keyed at commit 4 (2026-09-30, merging the `SHT-Q2` build):*** the `T`-keyed frontier, `Corrupt::StorageIdsOverflow` and the C++ half are deleted; the Rust `n` is `shard_of(cumulative_archival_len)` and the C++ reverts to `parent_frozen_segment_count` (CEN-L10, §3.7's amendment). **Re-scheduled to the cutover commit, disclosed here:** the JSON key, `segment_freeze.rs` and `shekyl_archival_frozen_segment_count` — their remaining callers are C++ the cutover deletes (§3.7's last paragraph names the falsifier). `knee_n`'s literal is carried, not converted (FOLLOWUPS' D2 row). | S | a wallet-side reader in the consensus closure (falsify: `cargo tree -i shekyl-fcmp -e features` shows the freeze module reached from `shekyl-chain-rules`) |
| 4 | **The transition on the verdict** (§3.1): `ArchivalDelta` derived in `validate` from the vin arms and the folds; the slash scan and the close as functions of the view; carried on `ChainValid`. Tests: each arm on a driven chain; the KAT B3 pop-and-re-close on the accumulator shape. *As landed (2026-09-30):* `shekyl-chain-rules::archival` — `transition` after the tree drain in `validate`, its delta on `ValidatedBlock::archival`; **`ArchivalDelta` is constructible only there** (private fields, private constructor, two `compile_fail` doctests as the pin — `ARW-Q1`'s "the store computes nothing" as a type, not a check). The vin arms are one `Rule`, **CEN-L7**, refusing at the input (§10); the close and the slash scan are derivations, so **CEN-L8 / L9 are `by_construction`** on the folds `accrue` / `apply_slash`, whose C++ aborts are `Corrupt` arms the store maps to SI-8 / SI-7. `shard_close_height` is a function on the view (one home for a formula the close needs; a search over the archival fold since the `SHT-Q2` merge, faulting `Corrupt::ShardCloseUnplaced` → SI-13). **Split, disclosed:** the arm tests run on an honest-empty chain (22, `archival_tests.rs`); the slash scan, the close, reinstate, the connected claim and the KAT B3 shape need a populated archival state, which §5.2 forbids mocking — they are **commit 5's** scenario driver over the production stack (falsify: `rg 'fn .*slash.*scan\|epoch_close' rust/shekyl-chain-rules/src/archival_tests.rs rust/shekyl-chain-store/src/store` → tests present after commit 5). The harness's serve-credit fixture, which carried an unparseable placeholder "for 4.J", became a parseable credit behind a `join_market` precedent — the sanity gate found it, as it was built to. **Interim refusal, pinned and disclosed:** from this commit until commit 5, the corpus gate `vectors_tests::every_captured_chain_replays_and_matches_the_daemons_digest` sees `emission-claim` refused at height 1025 — the JoinMarket's record is derived on the verdict and no writer persists it until the phase bodies, so the claim finds no record and L7 refuses at its input. That is the transition doing what it should against a store that does not yet write what it is handed; the fix is commit 5, not a softer L7. (The same locus first hid `ARW-15`, fixed in the commit preceding this one; §10.) The gate carries the refusal as a **pinned verdict** (`vectors_tests::interim_refusal`: exactly height 1025, CEN-L7, the claim's input, for that one chain) rather than as a red or an `#[ignore]` — a refusal anywhere else is a finding, and the chain replaying in full is commit 5 landing, which fails the pin until its row is deleted. Falsify: `rg interim_refusal rust/shekyl-chain-ingest/src/vectors_tests.rs` → the function has no rows, at commit 5. **DISCHARGED 2026-09-30 (commit 5b `e5115a061`): `interim_refusal` is deleted with its one row and `emission-claim` replays in full under the all-captures gate.** ***Amended (2026-09-30, after #914 merged the first cut):*** the "22 arm tests on an honest-empty chain" were a `MockChain` asserting a persona has no bond — a view with no archival state asserting a fact about a chain (rule 50's third job) — and CEN-L7 had been flipped to `implemented` on that alone. **The single-block arms now have their production witness** in `shekyl-chain-ingest::scenario_archival_tests`: personas from `derive_archival_p_keys`, posts from `shekyl-archival-bond-builder`, riding the driver's real coinbase spend (`Spender::spend_coinbase_posting`, H21-balanced with the post's terms, the bond slot I18-signed over its own payload), mined through `ChainStore::connect` on redb; the verdict's delta read off the connector's `Applied` (`Mined::archival`). Witnessed there: a compact and a complete-tree join's `Insert` field by field, a same-block credit's key, the accrual's post-image, and L7 at the input for a credit / release / reinstate / unknown kind / empty compact join against a persona with no record. **The cut, and why it is a pairing, not a deferral:** single-block arms need no persisted archival state, so they run today; multi-block shapes need the writer, so they are commit 5's witness for commit 5's code. **Two corrections the redb run made to the plan's own list:** (a) *join + release in one block* is not a single-block arm — **CEN-G10** (one bond post per `P` per block) refuses it at `Input{Listed(1), input 1}` before the transition runs, so a release / reinstate / second join only ever see a *persisted* record and their positive arms are commit 5's; pinned as `a_join_and_a_release_in_one_block_is_g10s_refusal_not_l7s`; (b) a compact holding with a repeated shard is refused by the wire decoder (`shekyl_wire::Holdings::read`) before any rule — L7's duplicate arm is a belt behind the decoder, so its case stays on the fixture as exemption 3. `archival_tests.rs` is pared to **12** cases, each labeled with its rule-50 exemption (1: the slash fold and the close search on constructed values; 3: L8 overflow, L9 not-held / underflow, the non-monotone fold, the duplicate shard) — plus an **INTERIM** pile of five same-block-record cases (second join, release ×2, reinstate, unsettled claim) whose premise G10 makes unreachable in production; blocked on commit 5, falsify by the redb scenario's `bond_record` read turning `Some`, at which point the pile is deleted with its redb replacement written. **The store does not yet write the delta** is now pinned in code, not only prose: the same scenario reads `bond_record` after an admitted join and asserts `None`, and mines the next block's credit into L7 — commit 5 flips both assertions. The `emission-claim` pin above is unchanged by this amendment; the gate ran red-as-pinned on the amended tree. **DISCHARGED 2026-09-30 (commit 5b): `bond_record` is `Some` after the join and the next block's credit connects (`scenario_archival_tests`); the INTERIM pile is deleted and its redb replacements written — a release's post-image reads back, a second join and a reinstate over a clean close are L7 at the post.** | **L** | the slash scan's view reads being the wrong shape (a scan over `archival_bond` needs a range read the view does not have — this is where it shows) |
| 5 | **The phase bodies** (§3.2) with SI-19…23 built; `Candidate.attestation_witness`, written unjudged under a CEN-B4 coverage gap until B4 lands in `validate` (§3.2's UPDATE: the judgment claim, not the plumbing one — the commit text says why); the stubbed-family skip-and-widen (`ARW-9`); the regtest injector on the store; **the slash scan measured** (B9: once per epoch on the floor, against the C++'s own note) — the accrual fully derived, F17 having landed (§3.5's UPDATE). *As landed (2026-09-30), three sub-commits:* **5a** `16e02e55e` — the substrate: the keyed delete verb (`RemoveTable` / `UndoEntry::Removed`, tag 4; `SCHEMA_VERSION` 19 → 20) that `ARW-Q3`'s second half needs and SI-19…23 as `StoreInvariant` variants; **5b** `e5115a061` — `archival_write.rs`, a body in every phase: records **written once after the transaction loop** from the delta's final post-images (SI-19 insert-once at the JoinMarket handle; SI-20 armed once, §3.2 / §4; **UPDATE 2026-10-01:** that sum was an identity — SI-20 is `BondRecordAbsent` on `ReplaceTable`, §4 / §10), credits with SI-15's read belt, the witness from `Candidate.attestation_witness` (`AttestationWitness`, non-empty by type), the slash burn through phase 8's one fold (ARW-6), `archival_budget_accruing[E]` upserted every connect and **removed at the close** (SI-23), the slash log / applied / watermark (SI-22), the three close rows insert-once on `E` (SI-21); the regtest injector `regtest_inject_serve_credit` under `Trust::UNANCHORED` only (`InjectionOffFakechain`), refusing a persona with no record (`InjectionForUnbondedPersona`), unjournaled (§3.8 item 3); `ARW-9` → skip-and-widen; **5c** this text. *Witnesses:* `archival_write_tests` (7: the rows read back and lifted by `pop`; the close's rows and the accruing row's removal, then pop-and-re-close byte-identical — KAT B3's shape; the witness at its height; the injector's three refusals; skip-and-widen; CEN-L7 on a *persisted* record through `assert_refused`, so the store names no verdict type — the conversion-ban gate's clause 2); `scenario_archival_tests` inverted (`bond_record` `Some` after a join, the next credit connects, a release reads back, a second join and a reinstate over a clean close are L7 at the post) and the INTERIM pile deleted; `vectors_tests::interim_refusal` deleted, `emission-claim` replays in full; `connect_tests` row counts 13 → 14 / 26 → 27 for the accrual upsert. **Disclosed (rule 22) at 5c, RESOLVED 2026-09-30 by the ruling (§10) — the 9b slash writes' only witness *was* the B9 bench, `#[ignore]`d.** The disclosure as written: a slash deadline sat at `last_block(E) + CHALLENGE_RESOLUTION_BLOCKS`, consensus data (`10 000`) not a Fakechain lever, so the shortest chain reaching one was ~11 200 connects, outside the unit lane. The ruling was the deletion, not a lever: `CHALLENGE_RESOLUTION_BLOCKS` and its JSON key are gone, the grace is `SLASH_GRACE_EPOCHS · SEB` with `k = 1` ratified (`SettlementSchedule::slash_grace_blocks`), and under the bench's `SEB 100` the slash — `M` epochs of misses settled by absence plus one epoch of grace — is `last_block(12) + 1 = 1 300` connects. `slash_writes_land_at_the_m_epoch_deadline` (`slash_scan_bench_tests.rs`, four personas, 33.7 s debug) is the 9b witness in the unit lane; the bench shares its chain and stays ignored for its persona count and `--release` reading. The FOLLOWUPS row is removed as resolved; its falsifier (a non-ignored slash test in chain-store) is true. No capture carries a slash (ARW-13) and commit 8's oracle still does not cover one — see row 8 for what that now costs. **Found, not this lane's:** CEN-H20 admits a serve credit with `prunable: None` and the store cannot hold one (the txid reconstruction mixes the null hash with `txs_prunable_hash = keccak256("")`, SI-7 at `tx_spendable_age`); `connect_fixtures::credited` builds the RF-D1 region, FOLLOWUPS' `SHT-9` row carries the UPDATE. | M | `pop` of a block that closed an epoch: the journal's restore of insert-once rows under a tuple key (the `Restorable` impl the table did not need until now) |
| 6 | **`digest_v1`** (§3.8): **the preimage specified first** (§3.8.1, byte layout and domain strings, before the hasher — rule 05; `ARW-24`); the Rust hasher over the archival families; the C++ walker's marshal; **the walker's output captured as committed data** (`ARW-23`, the I17 KAT shape: the C++ leg's capture mode over the LMDB fixture's state — every family, the slash and close included — writes a fixture holding the rows, the preimage and the digest *as the specification's output*, documented against §3.8.1 and not against the walker, the Rust leg holding `digest_v1` to it after the walker is gone); the trace format's checkpoint carries v1. **Two format numbers move in PR-b and neither is a falsifier** (§6.2 item 2): the trace's `TRACE_VERSION` `0x00 → 0x01` here — falsified by *every `0x02` record carrying two 32-byte digests*, which a reader of the old record length refuses — and the manifests' `format_version` `3 → 4` in commit 7, falsified by *the injection's `height` and `persona` on every `out_of_band_writes` row*. **`LMDB_WRITE_ATOMICITY_AUDIT.md` §10 moves in this commit, not in commit 10**: the sixteen archival journals' `Digest v0` state → `v1` and the §7.1.1 exclusion retired, so the document and the mechanism move together — that exclusion is load-bearing for what the digest is allowed not to cover, and a stale sentence there does real damage (ruled 2026-09-29). | M | the C++ walker: the only C++ this increment adds, and rule 20 holds it to a marshal — if it grows arithmetic, stop |
| 7 | **The injection event** (§3.8 item 3): `IngestEvent::Inject` with its stated scope (regtest-only, one row kind, the injector its sole producer), the exporter reading the injector's receipt, the connector applying it through the store's regtest door, the trace-half check (an `Inject` iff the manifest's `out_of_band_writes` names one); **re-capture of all six captured chains** (`CAPTURED_SHAPES`, `vectors_tests.rs` — the format moves for the whole corpus or the all-captures gate refuses the two left behind) under the corrected regtest table and the v1 checkpoint, the generator writing the injection's height and persona into the manifest. *Scope stated before it starts (pre-flight 2026-10-01, §6.2):* **this is six regtest generator runs, not "a re-capture"** — one per chain, each a daemon brought up, driven to its shape and exported, each of the order of the hour-plus a run has measured — on the critical path to 8 and the largest unestimated piece in PR-b. The six manifests move to **`format_version: 4`**, and the field that proves the run happened is the injection receipt: every manifest carries `out_of_band_writes[*].height` and `.persona` (the five block-derived chains an empty list, `emission-claim` its one row), written by the generator from the injection it made — the falsifier a manifest edit cannot satisfy (§6.1). | M | the exporter cannot see the injection (no receipt in LMDB) — then the generator writes one, and the re-capture waits on it |
| 8 | **The oracle** — the protected commit. Replay all six chains; the v1 digest at every tip; the sufficiency red for every family the run exercises (§3.8 item 2). A tip disagreement on `bond-post` or `emission-claim` **stops the PR** and is adjudicated against the spec (E2 §0), never toward the C++ — with one named exception: a divergence that traces to zero-as-absence (§3.6) is the projection's bug, not a finding. *UPDATE 2026-09-30 (the row 5 ruling):* a slash-bearing capture for the digest is now **optional and cheap** — with the grace derived from the epoch, a regtest generator run under `SEB 100` reaches a slash in ~1 300 blocks — and the order in which to reach for it is fixed here so the expensive form is not taken first: (1) the unit witness (row 5, landed) is the 9b coverage; (2) if commit 8 wants the slash families in the digest's exercised set, run the generator, do not hand-build a chain; (3) a lever on the grace is not an option — the ruling closed it. The capture's real shape is a **driver-capability** question, not a block-count one: eleven consecutive epochs whose observations settle as misses 2-of-3, which the B9 chain gets by absence (nobody serves) and a populated capture would need the scenario driver to produce. | S | a disagreement — which is what the commit exists to produce |
| 9 | **Rust deletions** (§3.9's Rust half). | S | — |
| 10 | **Docs** (§9). | S | — |

**Protect commit 8 from schedule pressure** — E3's sentence, with E3's
reason, and one more: this oracle is *weaker* than E3's (one tip, not every
height), so a red here localizes nothing and the instinct will be to sample
it away by stubbing the family that differs. The stamp is precisely what
makes that visible; use it to find the family, then read the rows.

### 6.1 The seam where this may be two PRs

Commits 1–5 are the store and the validator; 6–8 are E2's instrument and the
corpus. If the re-capture (commit 7) waits on the regtest generator, commits
1–5 land as **PR-a** with the family stubs *on* for the six chains and the
provenance widened — the file honestly not parity evidence — and 6–9 as
**PR-b**. That is a **split** (rule 22: re-scheduled inside the scope, both
PRs named here), not a deferral; PR-a's description says PR-b is owed and
what its falsifier is (`rg 'digest_v1' rust/shekyl-chain-store/src` →
present; ~~the six manifests at `format_version: 3`~~ **CORRECTED
2026-10-01 (§6.2, `ARW-16`):** every one of the six `manifest.json` files
carries `out_of_band_writes` whose rows each name `height` and `persona`,
at `format_version: 4` — the version alone was satisfied by `ARW-15`'s
`settlement_epoch_blocks` edit before PR-b began). PR-a landed as #914 +
#921 (2026-09-30 / 10-01); PR-b opens on commit 6.

### 6.2 PR-b pre-flight — 2026-10-01, at `dev@76bc64aa7` (#921 merged)

Executed in a fresh worktree off `dev` HEAD before commit 6's first line.
Five things the record takes from it, then the substrate findings
(`ARW-16…ARW-22`) and the questions commit 6 poses (`ARW-Q10…ARW-Q12`).

**1. Why E4 finishes before DRS-E6 opens — the recorded reason is the
stamp's hazard, not the dependency.** The maintainer's holding argument
was that commit 8 is the only work on either lane with a closing window
and that E6's slice 8 depends on E4's writer. The second half is true and
is not the reason of record. The reason is the one §3.8 item 2's stamp
makes checkable: **slice 8 would be reading families whose apply has never
been shown to fire.** "The writer is unverified" is a mood; "no test has
turned `RMarket`'s apply red" is a specific, checkable hazard — and the
failure it names is silent in the wrong direction: a rule that reads
`r_market` over a corpus where the budget phase matched by *absence* passes
for a reason that has nothing to do with the rule. Until the stamp is
green over the exercised families, every E6 slice-8 test over the archival
view is that test. (Maintainer, 2026-10-01: *"the sufficiency-stamp
framing is sharper than my dependency argument and it should replace it in
the record"*.)

**2. The PR-b falsifier was satisfied by the wrong change, and the class
is worth naming.** §6.1 named "the six manifests at `format_version: 3`"
as what would show PR-b landed. `ARW-15` moved all six manifests to v3 for
`settlement_epoch_blocks` on 2026-09-30 — by edit, not by capture: every
manifest's `built_at_dev_sha` is still `1e8d14dc9` or `8c3e443cf`, E2-era
pins — so the check reported PR-b done before PR-b began, with no
re-capture run and no injection receipt recorded. The defect is the
falsifier's **shape**, not its number. A *state-shaped* falsifier ("the
files are at v3") goes green when **anything** reaches that state, and a
format version is reached by any writer with a reason to bump it. A
*field-shaped* falsifier ("every manifest carries the injection's `height`
and `persona`") can be satisfied only by the change it is about, because
only that change produces the field. The repair here is v4 with the field
named (§6.1 as corrected). The lesson is recorded in rule 22's falsifier
section, beside the "restatement of the blocker" anti-shape: **a version
number is a poor falsifier; name the fields.**

**3. Commit 6 before anything else — the only ordering where the digest
means anything.** The C++ walker is the half of `digest_v1` that
disappears at cutover (§3.9: the C++ deletes when the Rust daemon is
consensus). Its comparison against the redb hasher is live **only while
LMDB is consensus** — the same window as commit 8's oracle, and upstream
of it: the oracle is a *v1* comparison, so nothing in commit 8 can run
until commit 6 has given it a v1 to compare. Commit 7's six runs export a
checkpoint in the format commit 6 defines; capturing them at v0 and
re-capturing at v1 would be twelve runs. So: 6, then 7, then 8 — not as a
preference but as the dependency chain's one topological order. **Rule 20
holds at 6** (row 6's risk column): the walker is a marshal; the arithmetic
the C++ performs today where the Rust side keeps a value (`ARW-18`) moves
to Rust, not into the walker.

**The walker's output is captured as committed data before it goes**
(maintainer, 2026-10-01). A comparison between the walker and the Rust
hasher is meaningful only while both exist; the day the C++ is deleted it
would compare Rust against itself and pass forever for no reason — the
exact reasoning that produced I17's KAT (`shekyl-wire/tests/
pqc_signing_preimage_kat.rs`, captured from `get_transaction_signed_payload`
before E6 slice 6 commit 7 deleted it). So commit 6 captures: the C++ leg
(`tests/unit_tests/archival_digest_v1_kat.cpp`), in its capture mode, drives
the LMDB fixture through the C++ appliers of record — bonds, credits, the
close, a slash, the witness, the accrual — walks the result and writes a
fixture holding **the rows the walker yielded, the §3.8.1 preimage those
rows define, and the v1 digest**. The fixture is **documented against what
`digest_v1` is specified to be, not against what the walker produced**: its
`specification` is §3.8.1, its `description` states what the preimage is for
these rows, and the walker appears only in `captured_by`. The Rust leg
(`shekyl-chain-store/tests/archival_digest_v1_kat.rs`) builds the leaf sets
from the fixture's rows and holds `digest_v1` to the pinned bytes; the C++
leg holds the walker to the same bytes while the walker exists, and is
deleted with it (§3.9). Two things the KAT gives that the corpus cannot:
the **slash and close families are in it** (no captured chain has a slash,
§2.4 — the LMDB fixture reaches one through `apply_archival_slash_one`),
and a tip disagreement in commit 8 localises to a **family**, by diffing
rows, where the checkpoint's 32 bytes localise to nothing. What it does not
give: parity on the *writers* — the fixture's rows came from the C++
appliers, so the Rust writer producing the same rows from the same events
is the stamp's and the oracle's claim, not the KAT's.

**4. Row 7 is six generator runs, not "a re-capture".** Stated in the row
itself before the work starts, because the estimate is written from the
row. The trace checkpoint format moves for the whole corpus or the
all-captures gate refuses (`vectors_tests.rs`), so every one of the six
chains is regenerated: six daemons brought up, driven to shape, exported.
Each is of the order of the hour-plus a run has measured; the figure is
re-measured and written into PR-b's description at the first run. This is
on the critical path to 8 and the largest unestimated piece in PR-b.
Commit 7 is a **hard precondition** for 8 in a second sense: `emission-claim`
is the only captured chain that crosses an epoch and the only one with an
injected serve credit; `IngestEvent::Inject` is what makes that credit
replayable. If 7 slips, 8 runs on five chains and the sixth — the only one
with a closed epoch, a budget, an `r_market` and a claim — is the one it
does not have.

**5. The slash-bearing capture is held; commit 8's stamp decides.** Row
8's 2026-09-30 update made a slash capture cheap (`SEB 100`, ~1 300
blocks) and fixed the order in which to reach for it. The pre-flight adds
the deciding rule: **do not run it before commit 8 reports.** If the stamp
is red for the slash families (`SlashLog`, `SlashApplied`, the
`last_slash_epoch` cell) over the six chains — their apply never fires on
this corpus — that red *is* the evidence a seventh capture is for, and the
capture is commit 8's response to its own finding. If the stamp is green
without it, a seventh chain is an hour of generator for no finding. Letting
the oracle choose is the same discipline as choosing the weights read
after the bench rather than before it.

#### 6.2.1 Substrate findings for commit 6

| Id | Finding |
| --- | --- |
| **ARW-16** | **The PR-b falsifier was state-shaped and pre-satisfied.** Six manifests at `format_version: 3` with `built_at_dev_sha ∈ {1e8d14dc9, 8c3e443cf}`: v3 arrived by `ARW-15`'s edit, not by capture. Repaired to v4 and the injection receipt's fields (§6.1, row 7). The class is named in rule 22. |
| **ARW-17** | **The C++ has no full-table enumeration for any archival table the digest covers.** Every public reader on `BlockchainDB` is a point lookup — `get_archival_bond_value(p)`, `get_archival_r_market(shard, E)`, `get_archival_sigma_work_milli(E)`, `get_archival_budget(E)`, `get_archival_budget_accrual(h)`, `get_archival_last_slash_epoch()`, `get_archival_attestation_witness_at_height(h)` — and the three enumerators (`fold_archival_market_bonded_counts`, `archival_bond_all_last_served_epochs`, `gather_archival_emission_*`) fold rather than yield. `logical_state_digest_v0` (`logical_state_digest.cpp`, 105 lines) walks nothing archival. So the walker is **new `MDB_cursor` walks** over `m_archival_bond`, `m_archival_serve_credit`, `m_archival_r_market`, `m_archival_sigma_work`, `m_archival_budget`, `m_archival_budget_accrual` (open-epoch range only), `m_archival_attestation_witness`, `m_archival_slash_log`, `m_archival_slash_applied`, plus the `last_slash_epoch` property — one `block_rtxn_start()` snapshot as v0 takes, each yielding its rows to Rust. The marshal is bounded by the table count, not by logic; a walk that filters or sums is past rule 20's line. |
| **ARW-18** | **Two values the C++ computes where redb keeps a row — the arithmetic is Rust's.** (a) *The accruing total*: the C++ close sums per-height `archival_budget_accrual` rows over `[open(E), (E+1)·SEB)` with a checked add (`db_lmdb.cpp:7836–7858`); redb holds one `archival_budget_accruing[E]` row (`archival_write.rs` phase 9a) and deletes it at close. The walker yields the open epoch's per-height rows; the Rust digest sums them with the same checked add and hashes the total — the C++ never sums for the digest. (b) *`r_market` zero rows*: §3.6's projection (a present-and-zero LMDB row is absence on the Rust side) is applied by the Rust hasher to the yielded rows, so the walker yields zeros and the projection has one home. |
| **ARW-19** | **The slash-log leaf is the Rust type's canonical encoding, and the amount is projected out by ruling already taken.** `ArchivalSlashRevertValue` v3 (`shekyl_types.h:594`) carries `p_id, shard, epoch, slashed_amount, holdings_pre_kind, slashed_shard_add_epoch`; `SlashLogEntry` (`shekyl-types/src/archival/slash.rs:53`) carries `persona, shard, epoch, holding: SlashedHolding::{Shard { add_epoch }, CompleteTree}` — the amount deliberately absent (*"reopens with a named reader"*, rule 21, `ARW-Q2`). The digest is over the Rust type: the walker yields the v3 row's fields, Rust builds `SlashLogEntry` (the `pre_kind` byte and the zero-when-unused add-epoch fold into the one sum) and encodes it. The C++'s epoch-marker row kind is not a leaf (its job is the `archival_last_slash_epoch` cell's, which *is* a leaf). No corpus has a slash (§2.4); this family's parity rests on the stamp until one does (item 5). |
| **ARW-20** | **The bond leaf is `Canonical::encode(BondRecord)`, and the v7 cross-check is already the bridge.** `codec/archival.rs` encodes `BondRecord` (same semantics as `ArchivalBondValue` v7, its own bytes, `SAR-Q3`); `ARCHIVAL_BOND_RECORD_V7.json` holds v7 blobs with the fields the C++ decoder read. The field sets align (`first_paying_emission_height` 0 ↔ `None`; `bad_intervals.end_exclusive == UINT64_MAX` ↔ the open interval — the second to be asserted in the mapping's test, not assumed). How the fields cross the FFI is `ARW-Q10`. |
| **ARW-21** | **No sufficiency test exists; its two halves are in the tree.** `ApplyPolicy::stubbed(&[ArchivalFamily])` (`apply_policy.rs:160`), `Provenance.stubbed: FamilySet` (`provenance.rs:60`) and `ArchivalFamily::ALL` exist; `shekyl-chain-replay` constructs `ApplyPolicy::default()` with no stub path (`:296`), and `rg 'stubbed' rust/shekyl-chain-ingest/src` finds nothing outside the store. The stamp (§3.8 item 2) is therefore new test code in `shekyl-chain-ingest/tests/`, where both the corpus and the scenario driver are reachable: the exhaustive `match` over `ArchivalFamily` naming each family's witness, then one pipeline run per family under `ApplyPolicy::stubbed(&[f])` asserting a v1 tip disagreement. The replay binary gains no stub flag — stubbing is the test's instrument, not an operator's. |
| **ARW-22** | **The checkpoint carrier is a trace version bump, not a new tag.** `TRACE_VERSION = 0x00` (`trace.rs:81`); checkpoint `0x02 ‖ height ‖ digest[32]`, one at the covered tip (`shekyl_e2_trace_export.cpp:200`); `0x03` reserved for Verdict (`RESERVED_VERDICT`). §3.8 says the checkpoint "carries both". Default (`ARW-Q12`): `TRACE_VERSION → 0x01`, record `0x02` widened to `height ‖ v0[32] ‖ v1[32]`, a v0 reader refusing the file by version (loud, the existing `TraceError` arm); `0x03` stays reserved. The six captures move with it — which is why they are six runs (item 4). |
| **ARW-23** | **The KAT's capture instrument is the LMDB unit fixture, not the corpus.** The six captured chains commit traces and manifests, no LMDB state, so the walker has nothing committed to walk; and no chain has a slash (§2.4). `tests/unit_tests/archival_substrate_lmdb.cpp` drives every archival writer through the C++ appliers of record — `apply_archival_slash_one` (`:1598`, `:1655`, `:1712`, `:1806`), `process_archival_epoch_close_at_height` (`:565`, `:921`), the accrual/burn partition (`:965`), the witness (`:1096`), bond records and serve credits — so a capture-mode leg over that fixture's state covers **every** family `digest_v1` names, the two the corpus cannot reach included. Fixture home `rust/shekyl-chain-store/tests/fixtures/archival_digest_v1_kat.json` (I17's placement: beside the Rust leg that holds the derivation of record), one file carrying several states — at least: empty archival state; one bond and credits in an open epoch; a closed epoch with `r_market`/`Σwork`/budget rows and a zero `r_market` row (§3.6's projection exercised); a slash applied. Each state carries its rows per family, the preimage, the digest, and the `captured_by` daemon version. **Cardinality is what gives the KAT its power** (maintainer, 2026-10-01): the fixture's writer calls loop over epochs, shards, sequence numbers and intervals (fifteen such loops), so the instrument writes **multi-row families**, and the KAT must too — a digest over one row per family cannot see a defect that two rows expose (an ordered fold's ordering, a count's encoding, the zero-row projection applied among non-zero rows). So the coverage is **stated in the fixture's own `description`, per family, at each cardinality** — *empty*, *one*, *several*, and **at the frozen cap where one exists** (`MAX_HOLDINGS_SHARDS` held shards, `MAX_BOND_BAD_INTERVALS`, `MAX_CLAIMED_EPOCH_ENTRIES` on a bond leaf; `MAX_ATTESTATION_RECORDS` on a witness leaf) — the discipline of `the_record_round_trips_at_every_cap` (`codec/archival_tests.rs:62`), which is why the `BondRecord` move could claim its bytes held *at the boundaries* rather than at whatever the fixtures happened to hold. A digest fixture that does not say its cardinalities invites the next reader to assume more coverage than it has. **The empty case is the load-bearing one**: the stamp's whole job is telling *the phase ran and wrote nothing* from *the phase never ran*, and it can only assert that against a **pinned** `digest_v1` over an empty family; unpinned, an empty family's digest is whatever the implementation produces and both sides agree by accident. Every family's empty value is in the fixture. |
| **ARW-24** | **`digest_v0`'s preimage is specified nowhere but its own doc comment.** `digest_v0.rs` carries the 113-byte layout and the three domain strings; `DAEMON_REDB_STORE.md` §7.1 names the digest's existence and read set, not its bytes. For v1 the hasher cannot be written against a comment: §3.8.1 (new, commit 6's first edit) specifies the per-family leaf encodings, the per-family accumulators, the outer preimage and the domain strings (`shekyl/chain-digest/v1`, `/v1/<family>`), and the KAT's `specification` field cites it. **§3.8.1 carries v0 as well, as a records-was specification** (settled 2026-10-01, ahead of `ARW-Q13`): v0's specification currently retires with `digest_v0.rs`, and the E2 comparator's whole history — every checkpoint in every captured trace, every `digest_identical` in every graded run — is denominated in v0 digests. If the section carried only v1, then when v0 went the record of what those 32 bytes *meant* would go with it. So the v0 half is lifted from the comment and **verified against the code** (the 113-byte preimage, the three domain strings, `PINNED_FIXTURE`), with its era stated in-line; it is a records-was claim that stays true when the function is deleted, not documentation tidiness, and it is cheaper to write in the same edit than to reconstruct from `git log -S` later. |

#### 6.2.2 Questions posed for commit 6 (defaults stated; ruled on the PR)

| Id | Question | Default |
| --- | --- | --- |
| **ARW-Q10** | **How the walker hands a bond record across.** (a) The C++ decodes v7 with its own `ArchivalBondValue::decode` and the FFI carries a flat field struct Rust maps onto `BondRecord`; (b) the FFI carries the raw v7 bytes and Rust gains a v7 decoder. | **(a).** The C++ decoder exists and dies with the walker; a Rust v7 decoder would be new code for a format that has no Rust writer and no future, and rule 20's marshal is "call the decoder the table's owner already has, copy the fields". The v7 corpus test is the belt on the mapping. |
| **ARW-Q11** | **Which `last_slash_epoch` the digest hashes when none has settled.** The C++ cell carries a sentinel for "never"; `ReadSnapshot::last_settled_slash_epoch()` is `Option<SettlementEpoch>` (SAR A9). | **The `Option`'s canonical encoding** (`u8 present ‖ u64`), the walker yielding the C++ sentinel and Rust mapping it to `None` — the digest never sees the sentinel, same as `first_paying_emission_height` 0 ↔ `None` in `ARW-20`. |
| **ARW-Q12** | **How the trace carries v1** (`ARW-22`): version bump with a widened `0x02`, or a fourth tag for a v1 checkpoint beside the v0 one. | **Version bump, widened `0x02`.** One checkpoint record per tip keeps "the digest at the covered tip" one thing with two components, and a disagreement localises to core (v0) or archival (v1) by which half differs — the exact localisation §6's "a red here localizes nothing" warns the oracle lacks. A fourth tag would let a trace carry one without the other, which is a trace that is not a v1 trace. |
| **ARW-Q13** | **Where the digest preimage specification lives** (`ARW-24`): §3.8.1 of this document, or a contract document (`CHAIN_DIGEST.md`, LIVING CONTRACT), as `FCMP_SPEND_SIGNING_PREIMAGE.md` is for I17's KAT. *Narrowed 2026-10-01:* §3.8.1 carries **both** v0 and v1 from its first edit (`ARW-24`), so the question is only the section's home, not its content. | **§3.8.1 for commit 6; the contract document is commit 10's decision** (§9). The KAT cites §3.8.1 now; promotion is a `git mv`-shaped move of a section already complete, written at commit 10 if §9 takes it, with the KAT's `specification` field re-pointed in the same commit, or named in FOLLOWUPS with this document as owner if not. |
| **ARW-Q14** | **The per-family accumulator's shape** — the decision §3.8.1 must make before the hasher, and the one that decides *which* defects `ARW-23`'s cardinality catches. (a) v0's shape: `count ‖ XOR of leaf hashes`, leaf = `cSHAKE256(family domain, canonical key ‖ canonical value)` — order-independent by construction (`digest_v0.rs:158`, `spent_accumulator_is_order_independent`); (b) an ordered fold over a canonical key order the specification defines. | **(a), v0's shape — posed, not ruled; the maintainer's framing presumes (b), and the hasher waits on this cell.** *Premise corrected 2026-10-01, same day:* the first draft of this cell claimed the two sides' iteration orders need not coincide; they do, by construction — every archival table's redb key type is chosen so its `Ord` **is** the LMDB packed-key order (`schema.rs:547–608`, per-table: the `([u8; 32], u64, u64, u64)` tuple "orders component-wise — exactly the packed key's lexicographic order"; `lmdb_order` carries the one order that differs, `compare_hash32`, and no archival table uses it). So (b) needs no sort and no sort-key specification; both sides fold in the order their store already yields. What separates the options is therefore not cost but **which job the digest does.** (b) makes the digest a sequence hash: a walker that iterates one table in a different order than `ReadSnapshot` — the accumulator-ordering defect the maintainer named — goes red in the KAT, and multi-row coverage is what arms it. (a) makes the digest a set hash: that defect cannot register, because the digest does not depend on order; key-order conformance stays the schema's and `lmdb_order`'s job (one mechanism, one job), and a mismatch there surfaces in its own gate rather than as an unexplained digest divergence. Under (a) the multi-row coverage tests the leaf encoding at every cardinality, the count, the §3.6 projection among non-zero rows and the cap boundaries; under (b) it tests those *and* order. v0 chose per family — ordered for the chain (height is the semantics), set-shaped for spent keys (`:20`) — so the precedent supports either for keyed tables. The default stays (a) because the keyed archival tables are sets by meaning (a bond table has no first persona), and a digest that depends on an order the semantics do not carry fails on a storage fact. **Ruling owed before the hasher: §3.8.1 is written with (a) and the accumulator clause is one paragraph to swap.** |

**What the pre-flight did not do:** no code; no change to `digest_v0`'s
preimage or domain strings (v1 is a new function with new domain strings,
and v0 keeps its `PINNED_FIXTURE`); no decision on the seventh capture
(item 5); no index row change (the status is unchanged — commits 1–5
landed — and the index gains its update when 6 lands).

---

## 7. What E4 unblocks, and the measurable

| Waiting | Falsifier |
| --- | --- |
| E6 slice 8 (4.J, 26 rows) | `rg 'fn bond_record\|fn slash_log_after' rust/shekyl-chain-rules/src/view.rs` → the trait methods with `BatchView` impls |
| CEN-L16 | `rg 'fn holds_shard_at' rust/shekyl-archival-retention/src` → present; `rg 'archival_bond_holds_shard_of' src/blockchain_db` → still present until cutover, and the census row says both |
| CEN-F17's operand | `rg 'fn closed_shards' rust/shekyl-chain-rules/src/view.rs`; `rg segment_leaf_count config/consensus_constants.json` → nothing; `closed_shards` reads `cumulative_archival_len` through `shekyl_types::shard_of` and never `cumulative_tx_count` (`SHT-Q2`; the retired `T` would re-enter here) |
| E2's S-ARCH bar (SAR-11) | `rg 'digest_v1' rust/shekyl-chain-store/src` → present; each manifest's checkpoint at v1; the sufficiency test red for each **exercised** family, with rule 47's half first — every retained writable family names a witness through an exhaustive `match` over `ArchivalFamily` (falsify by adding a variant to the X-macro: the test must fail to compile, not pass; `cargo test -p shekyl-chain-ingest stubbed_family_reddens`; §3.8 item 2) |
| The injected credit modelled | `rg 'Inject' rust/shekyl-chain-ingest/src/source.rs` → a variant; `emission-claim`'s trace carries one; **the manifest half HOLDS 2026-09-29**: `rg out_of_band_writes rust/shekyl-chain-ingest/tests/vectors/*/manifest.json` → six hits, one non-empty, and `vectors_tests::only_the_named_chains_carry_out_of_band_writes` green |
| `SAR-Q7`'s staged pair | `rg 'fn slash_log_after' rust/shekyl-chain-store/src/store/archival_reads.rs` → present |
| The daemon-uniformity sentence (FOLLOWUPS `:176`) | `rg -n 'no archival serving state' docs/design/DAEMON_REDB_STORE.md` → hits — **HOLDS 2026-09-29** (written by this PR) |
| One shard definition on `dev` | `rg 'leaves_per_segment\|SEGMENT_LAYER_J\|frozen_segment_count' rust/shekyl-chain-rules rust/shekyl-chain-store rust/shekyl-archival-retention/src` → nothing on the consensus side |

Denominator at the pin: `cargo test -p shekyl-chain-store --lib` 375,
`-p shekyl-chain-rules --lib` 262, `-p shekyl-chain-ingest` 89,
`-p shekyl-archival-retention` (unchanged in count until commit 9 deletes
the pop folds' tests); `check_redb_schema_bijection.py` /
`check_redb_schema_key_types.py` (six out, one in, `NOT_PORTED` +6,
`RUST_ONLY_TABLES` +1); `check_store_invariant_register.py` (SI-19…23);
`check_lmdb_schema_coverage.py` **unchanged until cutover** (no C++ table
dies here); the chain-rules coverage gate — written here as **unchanged**
("the transition is an operand, not a row, as growth was"), **corrected at
commit 4**: the *delta* is an operand, but the vin arms are the C++'s
connect-writer refusals, which the census already names — CEN-L7
`implemented`, CEN-L8 / L9 `by_construction` (`implemented 96`,
`by-construction 16`; `-p shekyl-chain-rules --lib` 330, `--doc` 17); the
doc gates. **Denominator at commit 5 (2026-09-30, the 5b tree):**
`-p shekyl-chain-store --lib` **404** (+2 `#[ignore]`d: the B9 bench and
one inherited; **405** after the slash-grace ruling added the 9b witness,
same two ignored), `-p shekyl-chain-rules --lib` **316** (the INTERIM pile and
the `MockChain` arms gone; `--doc` 17), `-p shekyl-chain-ingest` **93**
lib (+2 ignored) and the 4 integration cases, `-p shekyl-archival-retention
--lib` 283; the coverage gate unchanged from commit 4 (`implemented 96`,
`by-construction 16`); `check_store_error_conversion_ban.py` clause 2
clean with the writer's tests naming no verdict type. Extended: the E2
conformance run with `digest_v1` on (commit 8).

---

## 8. Round-1 questions — RULED 2026-09-29 (maintainer, PR #904); each row line-local

| Q | Question | Ruling | Why — the reason of record, where it differs from the one posed |
| --- | --- | --- | --- |
| **ARW-Q1** | Who derives the archival transition — the verdict (`validate` runs the folds over `ChainView`; `ChainValid` carries `ArchivalDelta`), or the store under principle 3's first clause (a `WriteBatch` method calling the retention crate inside the transaction, as the C++ does)? | **RULED: the verdict** | Slice 7's Q5 test: *a value belongs in the verdict iff the validator must compute it to reach the verdict.* The archival folds are read by the 4.J admission rules, so the validator computes them anyway — that makes `ArchivalDelta` free to carry and the store's "computes nothing" literal rather than aspirational. E3's `root_after` arrangement one lane over: the third application, so a precedent now rather than a case. (Posed on `CTW-Q1`'s reach argument and principle 3; those stand as corollaries.) **The E6 boundary, recorded here:** `PDM-Q6` item 4 row 1's *"E4 / S-ARCH in `shekyl-chain-rules`"* was a crate assignment, not a lane binding — E4 owns the typed state and the transition, slice 8 the admission rule that reads them (§2.2). Reopens if commit 5's measurement shows the deadline-height scan through the view is the connect's dominant cost on the floor **and** profiling attributes it to the view boundary rather than the fold (B9). |
| **ARW-Q2** | The six journals: dissolve all six into `undo_log`, or keep the slash log as history? And does any consumer of as-of-height holdings survive `PDM-Q3`'s re-key? | **RULED: five dissolve; the slash log is kept and typed** (§3.3); the epoch-marker row kind is deleted | ARW-2's discriminator, applied as the ruling: `undo_log` holds every pre-image, so a journal whose only job is reversal is a **materialised view of the undo log**; the slash log is read forward by `holds_shard`, which makes it a fact. The marker's retirement follows from the same cut — its job is the `last_slash_epoch` cell's own pre-image, so it dissolves with the other five. Reopens if slice 8's re-keyed J8 drops the as-of-height operand — then the table and the fold go, and CEN-L16 → bucket 3. |
| **ARW-Q3** | The accrual: per-height rows range-summed at the close (the C++), or one accumulator row per epoch? | **RULED: one row per epoch; and — second half, posed on review and RULED the same day (2026-09-29) — the accruing row is deleted at close**, in the transaction that writes `archival_budget[E]`. | §3.5: nothing reads a single height's accrual; pop-symmetry through the pre-image; KAT B3 is the test. **Second half's reason of record:** the accumulator's job ends when the epoch closes — after the close the row is a second copy of a value that now has its permanent home, and *the one nobody reads is the one that drifts*. SI-23 (*at most one row, the open epoch's*) is what makes the deletion structural rather than a habit: a stale accumulator becomes a store-invariant violation, not a silently wrong operand — CEN-L1's belt-beneath-a-rule shape, and the same reason it is an invariant and not a comment. It also closes the one reading under which Q3 and Q9 could have been muddled: had the closed epoch's row survived beside its budget row, the accumulator would have become a per-epoch history nobody asked for, and someone would eventually have read it. **Q3 and Q9 are one question with opposite answers** — the fact-or-view test: per-height rows collapse to one per epoch because nothing reads a single height; `total_bonded_atomic` becomes a sum because nothing reads it but its own maintainers. One principle, two dispositions; SI-20's delta check is what makes the second safe. |
| **ARW-Q4** | The close's zero rows: skip (the C++), or write `RMarket(0)` for every shard in the snapshot? | **RULED: write them**; the digest projects zero-rows out on both sides | §3.6, and the reason is the better half of the ruling: zero must be distinguishable from absent, and the C++ skipping `r_market == 0` on the same screen that writes a zero budget row *because* zero must be distinguishable is the **absence-as-value class caught mid-contradiction**. |
| **ARW-Q5** | The §7.1.1 discharge: an archival digest family tip-compared plus the stamp, or a replacement KAT only (stub-reddens, no digest)? | **RULED: both** — `digest_v1` and the stamp; `IngestEvent::Inject` with the scope §3.8 states (regtest-only, one row kind, the injector its sole producer, present in no captured chain but the one) | the gate's own text names either; a digest without the stamp cannot attribute a red to a family, and a stamp without a digest never compares content. Neither alone is the gate's intent. |
| **ARW-Q6** | The shard universe for the complete-tree challenge set and F17's `n`: closed shards on the view, or a stored count? | **RULED: the view** — landed commit 4 as `shard_of(cumulative_archival_len)` at parent state (`closed_shards_before`), with the close's age operand `shard_close_height` a search over the same fold; *commit 3's `T`-keyed frontier over the storage ids was re-keyed to `SHT-Q2`'s `W` in the merge that brought that build in* (§3.7) | §3.7: a function of a fact the store holds; a stored count is `curve_tree_meta`'s shape with no C1-style one-row read to justify it. |
| **ARW-Q7** | Closed-epoch rows: pruned (at what horizon, by whom — S-PRUNE's boundary batch, or the close), or kept? | **RULED: kept; no epoch prune in this increment** | `ARW-11`: the C++ prune's only consumer was a pop floor SI-6 already provides; rows per closed epoch are `O(shards held)` and claims reach back `W = 26` epochs. Reopens on a measured size argument (B9) — then it is a phase of S-PRUNE's boundary batch, inside the same transaction, and the horizon is derived from `W`, not chosen. |
| **ARW-Q8** | `BondRecord`'s home: stays in `shekyl-chain-store::codec::archival` with `ChainView` re-spelling it, or moves to `shekyl-types` under `SAR-Q2`'s reopening clause? | **RULED: moves** — the clause is **satisfied, not invoked** | `SAR-Q2` kept `BondRecord` in the store because no second consumer existed; slice 8's `ChainView` need is that consumer — the clause firing on its own trigger, the third time this month a deferral has closed the way it was written to (beside RTN-7's, `docs/completed/RTN_7_WIRE_HASH_TYPES.md`, and the S-ARCH §5 gate that had lifted eighteen days before anyone re-read it). S-ARCH §3.4 as built: *reopens if slice 8 needs `BondRecord` on `ChainView`*; it does. The `AtomicUnits` objection (shekyl-units is shekyl-types' sibling) is answered by carrying `bonded_total` as `AtomicUnits` from `shekyl-units`, which `shekyl-types` may already reach or the record type lives beside `shekyl_types::archival` in whichever crate rule 18 names when both readers exist — commit 1 decides the crate by `cargo tree`, not by preference, and says which. |
| **ARW-Q9** | `total_bonded_atomic`: a typed cell maintained on every bond write (the C++), or a sum over `archival_bond` with SI-20 checking the delta? | **RULED: no cell.** **UPDATE 2026-10-01:** the sum-check half was an identity and is not armed. SI-20 is `BondRecordAbsent` on `ReplaceTable`. Reopens for an O(1) reader, as a cell, not as a second scan | `ARW-7`: no reader; a running total is a view — Q3's principle, the other disposition (see Q3's row). Reopens with a production reader that needs `O(1)` (the RPC's `get_info`?) — then it is a cell. SI-20 stays the absent-update belt; it does not become a scan of the cell. |

---

## 9. Documentation owed by the increment (rule 91)

`DAEMON_REDB_STORE.md` (the two `[E4 hook]` phase texts; the S-ARCH row →
LANDED with the write half; §7.5 table 2's E4 rows flipped; the lane graph's
E4 node; §7.1.1 re-read against the tree — the gate discharged, how);
`DRS_E1_SARCH.md` → `docs/completed/` (its §0/§2.2/§2.3 boundary statement
is owned here from landing); `STORE_INVARIANT_REGISTER.md` (SI-19…23;
SI-15's writer check; SI-6's restatement); `CONSENSUS_RULE_CENSUS.md`
(CEN-L10 → bucket 3 at cutover — **not here**, the C++ is live;
L7/L8/L9/L14/L16's store sites re-cited; `ARW-3`'s two siblings minted or
folded into L16's row as the sweep-subject row rules);
`CONSENSUS_STORE_RECONCILIATION.md` (the L rows' verdicts as built);
`CHAIN_RULES_CRATE.md` (`ArchivalDelta` on the verdict; the `ChainView`
archival reads; §13's F29 property re-held); `LMDB_WRITE_ATOMICITY_AUDIT.md`
§10 (the sixteen archival journals' `Digest v0` state → `v1`, the exclusion
retired) — **in commit 6 with the digest, not here** (§6; ruled 2026-09-29:
the exclusion is load-bearing for what the digest may not cover, and the
document moves with the mechanism); `ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md` → `docs/completed/` when the
Rust freeze half is deleted (RETIRED-in-code); FOLLOWUPS: `:176` **closed by
this PR**, `:727` narrowed to E6's half, `:157` closed when the JSON key
leaves, `:153` re-owned to slice 8 (disclosed §2.2), `:161`'s owner gains
this document, `SAR-Q7`'s staged row closed; `IMPLEMENTATION_INDEX.md`
(`ARW-`, `ARW-Q`, this document, `DRS_E1_SARCH.md`'s status, the stamp);
`CHANGELOG.md` (layout bump; the archival writers; the deleted tables;
`digest_v1`); this file's banner → LANDED, staying in `design/` while slice
8 cites §2.3 and §3.1.

---

## 10. Decision log

| Date | Entry |
| --- | --- |
| 2026-10-01 | **The KAT's coverage is stated, the empty case is pinned, and §3.8.1 carries v0 as records-was (maintainer, on the KAT direction).** The LMDB fixture writes multi-row families (writer calls in fifteen loops over epochs, shards, sequences, intervals), so the KAT does too, and says so: its `description` names each family's cardinality — empty, one, several, at the frozen cap where one exists — the `the_record_round_trips_at_every_cap` discipline (`ARW-23`). The empty case is the load-bearing one: the stamp tells *ran and wrote nothing* from *never ran* only against a pinned empty-family digest. The accumulator's shape is posed as `ARW-Q14` with v0's order-independent `count ‖ XOR` as default — ordering eliminated by construction rather than tested (its first draft claimed LMDB and redb iterate the tuple keys in different orders; they coincide, `schema.rs:547–608`, corrected the same day — the question is which job the digest does, not what a sort would cost, and the ruling is owed before the hasher). And §3.8.1 carries **v0 verified against `digest_v0.rs`** beside v1, because the E2 comparator's history is denominated in v0 and v0's specification would otherwise retire with the file; `ARW-Q13` narrows to the section's home. |
| 2026-10-01 | **Two directions carried into commit 6 (maintainer, on the pre-flight).** (1) **The walker's output is captured as committed data before the cutover deletes it** — the I17 KAT shape: a C++ leg in capture mode over the LMDB unit fixture's state (the corpus commits no LMDB and has no slash; the fixture reaches every family, `ARW-23`), writing rows, preimage and digest *as the specification's output* — documented against §3.8.1, what `digest_v1` is specified to be, not against what the walker produced; the Rust leg holds `digest_v1` to it after the C++ is gone. This requires the preimage to be specified before the hasher (`ARW-24`; §3.8.1 is commit 6's first edit; its promotion to a contract document is `ARW-Q13`, commit 10's). (2) **The format tag bump is v4, and neither format number is a falsifier.** The manifests move `3 → 4` in commit 7 and the trace `0x00 → 0x01` in commit 6; v3 already demonstrated that a version is satisfiable by any writer, so each is falsified by the *fields* it introduces — the injection's `height` and `persona` on every `out_of_band_writes` row; two 32-byte digests in every `0x02` record — never by the number (row 6, §6.2 item 2, rule 22). |
| 2026-10-01 | **PR-b pre-flighted (§6.2) at `dev@76bc64aa7`; DRS-E6 held until E4 closes, for the stamp's reason.** The record replaces the dependency argument ("slice 8 needs the writer") with the checkable hazard: slice 8 would read families whose apply has never been shown to fire, and a rule reading `r_market` on a corpus where the budget phase matched by absence passes for a reason unrelated to the rule. Three corrections to §6: the PR-b falsifier was **state-shaped and pre-satisfied** (`ARW-16` — six manifests at v3 by `ARW-15`'s edit, every `built_at_dev_sha` an E2-era pin; repaired to v4 with the injection receipt's fields named, the class recorded in rule 22); **commit 6 first** is the dependency chain's only order (the walker's comparison is live only while LMDB is consensus, upstream of commit 8's oracle; capturing at v0 then v1 would be twelve runs); **row 7 is six generator runs**, each the hour-plus a run has measured, named as such so the estimate carries the cost. The slash capture is held for commit 8's stamp to decide. Seven substrate findings (`ARW-17…ARW-22`: no C++ archival enumerators exist — the walker is new cursor walks; the accrual sum and the zero-row projection are Rust's; the slash leaf is `SlashLogEntry` with the amount already projected out; the bond leaf is `Canonical(BondRecord)` over the v7 bridge; no sufficiency test exists and its halves do; the carrier is a trace version bump) and three questions (`ARW-Q10…Q12`: decoded fields over the FFI; the `Option` encoding for the never-slashed cell; widened `0x02` under `TRACE_VERSION 0x01`). No code. |
| 2026-10-01 | **A non-total debit on a persisted release is L7.** Against an already-persisted bond record, a release whose debit is `bonded_total + 1` is `CenRow::L7` at `Locus::Input { slot: Listed(0), input: 1 }`, before the valid full release connects at the same height. A same-block join and release cannot reach `DebitNotRecordTotal`: CEN-G10 refuses the second post first. |
| 2026-10-01 | **A sub-divisor epoch has no W₂.** `challenge_response_blocks` was `SEB / 20` as a `u64`. An epoch below the divisor yielded `0`, and `SLASH_GRACE_EPOCHS · W2_EPOCH_DIVISOR ≥ 1` stayed true while the division had deleted the window; the lever test treated `grace ≥ 0` as the coupling. The method now returns `Option<NonZeroU64>` (`None` below the divisor; `SEB` 2 and 7 in the test). The production pin stays `CHALLENGE_RESPONSE_BLOCKS = 500` via a const match on `GENESIS`. `SettlementSchedule::new` still accepts `SEB ≥ 2` — only the W₂ method fails. |
| 2026-10-01 | **SI-20 is the absent update.** The `Σ bonded_total` check summed `archival_bond` before the block's writes and again after them. The second scan sees the uncommitted writes, so it equals the first plus exactly those writes: an `Update` of an absent persona upserts, journals `prior: None`, and both sides grow by the post-image. `BondedTotalDisagrees` could not fire. The no-cell half of `ARW-Q9` stands — the total is the rows. The belt is a fourth keyed verb, `ReplaceTable`, the dual of remove: overwrite of a present key only, fatal if absent, journaling `Replaced { prior: Some(_) }` and never `prior: None`. The absence returns before any journal entry. SI-20 is `StoreInvariant::BondRecordAbsent` (the number stays 20). Upsert remains the creating overwrite (accrual, the regtest credit). A duplicate `archival_slash_applied` key is `SlashFault::AlreadyApplied` on SI-22 (the display names that table); density stays `SlashFault::NotDense`. The accrual ends are read through the upsert handle, so admission runs. |
| 2026-09-30 | **RULED (maintainer, PR #921): the slash grace is one settlement epoch *as a multiple*, and `CHALLENGE_RESOLUTION_BLOCKS` is deleted — the ruling is the deletion, not the lever.** The 5c disclosure posed two exits for the 9b witness (a validated grace lever in `FakechainSchedule`, or a slash-bearing capture); the record settled on neither. Gate 6 and the free-rider round both read the grace as *"a full settlement epoch"*; it was carried as a second `10_000`, and a second number can be levered alone. So the key leaves `consensus_constants.json` (no generator read it; the digest re-pinned with a dated paragraph), the deadline becomes `last_block(E) + SEB` — `SettlementSchedule::slash_grace_blocks() = SEB · SLASH_GRACE_EPOCHS`, `k = 1` ratified, so the one-epoch **meaning** is what the code preserves rather than the number — and `SEB`'s existing lever carries it; no new lever. **The reason of record is a live incoherence, not a testing obstacle.** Slashing is `M = 11` of `N = 13` settled 2-of-3: the grace gates *when* the deadline scan runs, the predicate gates *whether* it writes. At the bench's `SEB 100` with the grace fixed, the eleven epochs of misses cost 1 100 blocks and the deadline sat 10 000 past them (~11 100 connects); with the grace derived, 1 100 + 100 (~1 200; the first slash lands at 1 300) — a **9×** cut, not the 50× first implied, and the correction matters because the arithmetic *is* the incoherence in one line: **the grace alone was nine times the eleven epochs the predicate needs — the settling window dwarfing the observation history it settles.** Not a scaled-down regime but a malformed one; a fixed grace against a levered epoch made the configuration a different system, and the L16 pin (`RELEASE_COOLDOWN_EPOCHS × SEB > grace`) inverted under it. Derived, both terms scale with `SEB`, the slash lifecycle compresses together, and a regtest regime stays proportionally faithful. **What this does not change:** the production schedule's figures (one epoch, ~13.9 d); `SLASH_SETTLEMENT_TIP_LAG_EPOCHS = 1 + k`; `journal_horizon_under` now `(k + n)·SEB + cap`. **What landed:** three commits on #921 — the derivation across retention / chain-rules / FFI (export `shekyl_archival_challenge_resolution_blocks`, zero callers, deleted) / sims / JSON+digest; the unit witness `slash_writes_land_at_the_m_epoch_deadline` sharing the bench's chain (`SlashedChain`), chain-store 405; this text. **For the capture (row 8):** optional now, a generator run, and the ordering is written in the row so the expensive form is not reached for first. The witness's real shape is eleven consecutive epochs of observations settling as misses — a driver-capability question, not a block count; B9 gets it by absence. **The second half, found by the maintainer reading the first:** W₂ (`CHALLENGE_RESPONSE_BLOCKS`) was already a ratio, `SETTLEMENT_EPOCH_BLOCKS / W2_EPOCH_DIVISOR` — so the observation was not "a pinned number" but something sharper: **the grace/W₂ const-assert held between two values drawn from different sources**, the grace now schedule-derived and W₂ still const-derived from the production pin. On the production schedule both read `SEB = 10 000` and one epoch dominates W₂ twenty-fold, as the W₂ ruling wrote it; under a levered `SEB = 100` the schedule's grace is 100 and the const's W₂ is still 500 — **the grace the assert requires to dominate W₂ was a fifth of it: the inequality inverted, not merely tightened**, a hundred-fold swing in the margin from 20× slack to 5× violation, which is why a const-assert that read as comfortably satisfied could invert at all — invisible only because W₂ has no consumer yet. Closed the same night, the way the grace went: `SettlementSchedule::challenge_response_blocks() = SEB / 20`, `CHALLENGE_RESPONSE_BLOCKS` is that method on `GENESIS`, and the coupling assert is `SLASH_GRACE_EPOCHS · W2_EPOCH_DIVISOR ≥ 1` — both sides from one epoch, so the relationship cannot invert on any schedule (witness: `slash_grace_dominates_w2_on_every_schedule`, levered rows included). **Not a reopening of W₂'s ruled band** — `constants.rs` warns that attaching a question to W₂ "dragged it back open twice"; the band stays `1/20`, ratified, and what moved is which epoch the fraction is taken of. The const says so beside the warning so the next reader does not conclude the move was the thing it warns against. |
| 2026-09-30 | **Commit 5 landed — the phase bodies, in three sub-commits (5a `16e02e55e` substrate, 5b `e5115a061` bodies, 5c docs), and four things the build decided that the plan had not.** **(1) The records are written once, after the transaction loop.** §3.2 placed the three vin arms inside `record_tx`, one write per archival vin, with SI-20 checked after phase 2 and again after phase 9. The delta the validator hands over carries each persona's **final** post-image for the block, slashes folded in — so a per-vin write would have been the store re-deriving intermediate states the verdict had already collapsed, which is principle 3's second clause with a smaller accent. The writer takes the post-images as they are, writes them once, and SI-20 is armed once over the result; the plan's second check had nothing left to see (§3.2, §4). **(2) `ARW-9` resolves to skip-and-widen**, exactly as the mechanism's own doc described and nothing had implemented: `ApplyPolicy::applies` is asked before a family's table is opened, the stubbed set widens the provenance, and a cross-family belt (SI-15) runs only when both families apply. **(3) The injector refuses a stranger.** `regtest_inject_serve_credit` is the C++ door (`blockchain.cpp:4708`) on the writer — `Trust::UNANCHORED` only, unjournaled, attributed to the tip — with one addition the C++ did not have: a persona with no record is refused at the door (`InjectionForUnbondedPersona`), because the bit it would write is SI-15 at the next read, and a regtest lever that plants a store-invariant violation is not a lever. **(4) B9 is measured and `ARW-Q1` does not reopen** (§3.1: the slashing deadline's judge is 3.3× an ordinary block's, once per epoch; the bench reads the ratio, so the floor device scales both sides). **Disclosed, rule 22 (RESOLVED the same day — the row above):** the 9b slash writes' only witness was that bench, `#[ignore]`d, because a deadline was 10 000 blocks past an epoch's last block and that grace was consensus data, not a Fakechain lever — FOLLOWUPS row, owner this document, blocked on a ruling (a validated lever in `FakechainSchedule`, or a slash-bearing capture; the ruling took neither). **Found by the writer, owned elsewhere:** CEN-H20 admits a `prunable: None` serve credit the store cannot reconstruct (SI-7 at `tx_spendable_age`, reproduced at 10 → 20); FOLLOWUPS `SHT-9` carries it with a falsifier, the closing fix is H20's. **Discharged in place:** §6 row 4's two falsifiers (the INTERIM pile; `interim_refusal`), both now true. **The T-keyed text the pruning lane flagged** (§0 `PDM-Q6` items 4–5, §2.5, ARW-4) carries its *was → `SHT-Q2`* marker in the grep-visible line; that lane did not edit this file (rule 94 §6) and said so in its PR. |
| 2026-09-30 | **The vin→wire map is one function.** `shekyl_archival_bond_builder::bond_post_input` maps every `BondKind` — JoinMarket copies its key and endpoint, Reinstate and Release are `Other` of `BondKind::tag` — from `ArchivalBondPostVin` onto `Input::BondPost`. The wallet's `wire_bond_post_input` is the producer policy over that function: JoinMarket and Release assemble, Reinstate stays staged (verify and connect live, no wallet producer). The scenario driver calls the builder. The FOLLOWUPS row that recorded the two copies is closed. Retention stays free of `shekyl-wire`; `shekyl-tx-builder` stays free of the bond vocabulary. |
| 2026-09-30 | **Commit 4 amended — the transition's single-block arms get their production witness, and the plan's arm list gets two corrections from running it.** The first cut's 22 arm tests ran on a `MockChain` with no archival state, and CEN-L7 was flipped to `implemented` on that: a view that holds no bonds "asserting" a persona has none is the shape rule 50's third job names, and the maintainer's reading (*"a rule whose only fixture is mock-served state is untested for parity"*) is adopted as the ruling. The witness now lives where the store does — `shekyl-chain-ingest::scenario_archival_tests` behind `pipeline` (the rules crate cannot depend on the store) — with real personas, builder-made posts riding the driver's real spend, and the delta read off the connector's `Applied` (`Clone` on `ArchivalDelta` has that one caller, named on the type). **Correction (a):** join + release in one block, which §6 row 4's first draft counted single-block, is **CEN-G10**'s refusal (one bond post per `P` per block, `body.rs` `bond_post_block_unique`) at the second post, *before* the transition runs — so the release, reinstate and second-join arms only ever see a persisted record, and their witnesses are commit 5's; the five fixture cases that reached them through a same-block join are kept as a labeled INTERIM pile (blocker: the writer; falsifier: the redb scenario's `bond_record` turning `Some`). **Correction (b):** `shekyl_wire::Holdings::read` refuses a repeated shard before validation; L7's duplicate-shard arm is a belt behind the decoder, exemption 3, and stays on the fixture. **Pinned in code:** the store does not write the delta at this commit (`bond_record` → `None` after an admitted join; the next block's credit → L7), so commit 5's landing turns a passing assertion red rather than a paragraph stale. **Unchanged:** the `emission-claim` pin at 1025 — the amendment ran the gate and it held as pinned; nothing was loosened to make it green. **Formula finding:** `scenario_archival::bond_post_input` restates engine-core's `pub(crate) wire_bond_post_input` (builder vin → wire `Input`); two lanes need it now, so it is a function owed a shared home — FOLLOWUPS row (`Owner:` this document), not a third copy. |
| 2026-09-30 | **`dev` merged (PR #910, the `SHT-Q2` build): the shard universe is re-keyed from `T` to `W`, and the C++ operand reverts.** Commit 3 built the closure frontier over storage ids (`⌊(listed + coinbases) / T⌋`) with one home in `shekyl-types` and one atomic C++/Rust change; `SHT-Q2` landed on `dev` the day before, cutting shards by archival length and deleting `SHARD_TX_COUNT`. The merge is therefore a semantic conflict, not a textual one, and it was resolved by design rather than by side-pick: **(1)** the Rust validator's `n` is `shard_of(parent.cumulative_archival_len)` (`closed_shards_before`), and the close's age operand `shard_close_height` is a binary search over the same fold for `shard_start(k + 1)`; `RecordedBlock` carries `cumulative_archival_len` for both. **(2)** The `T`-keyed frontier (`shekyl_types::closed_shards` / `closed_shards_through`, the FFI `shekyl_archival_closed_shard_count`, `Corrupt::StorageIdsOverflow`) is deleted — no half-built second definition survives beside `shard_of` (rule 23). `storage_ids_through` stays: the prune's descent still needs a tx id's height. **(3)** The C++ validator goes **back** to `parent_frozen_segment_count`: LMDB records no archival fold, and building one into the C++ to keep the two validators nominally equal is exactly the thickening rule 20 refuses for a template the cutover deletes. The two validators now compute `n` from different partitions — CEN-L10's divergence, which the `SHT-Q2` build already re-graded DIVERGENT-and-intended — and the burn split stays bit-identical because the escalation ships flat; the digest at every captured tip is the check that it does. The FFI parameters keep the name `frozen_segment_count`, which is what the C++ passes, and wrap into `ClosedShardCount` at the one marshalling site. **(4)** `shard_close_height`'s fault is one variant, `Corrupt::ShardCloseUnplaced { shard, at }` → SI-13 on the archival cell, replacing the two count-era arms; the `T`-keyed tests are rewritten against `SHARD_LENGTH`, with the unclosed-shard and non-monotone-fold refusals added. Layout 19 (dev took 18); `tables.snap` regenerated. §3.7, §6 row 3, ARW-Q6 and the CHANGELOG entry carry the same account; commit 3's row and formula paragraph are marked SUPERSEDED in place. |
| 2026-09-30 | **`ARW-15` ruled — the settlement schedule is rule-set data** (§5). The transition's first run over the corpus refused `emission-claim` at height 1025 (CEN-L7, `Input { slot: Listed(0), input: 2 }`, the claim): the validator read the epoch off the retention crate's process latch, which the replay never arms, so a chain captured under `SEB 512` was judged under `10 000` and epoch 1 was not yet settled. The cap was already rule-set data (SPR-8); the epoch it is validated against (SPR-9) was a constant — one half of one schedule in the set, the other half in a `static`. Landed as one change across the types, retention, rules, store, ingest and capture crates: `RuleSet::fakechain(fixed, schedule)` over a validated `FakechainSchedule` pair, `RuleSet::settlement_schedule()` the only thing the transition reads, `Horizons::under(&RuleSet)` so a store opens off the set it will connect under, the SCW-2 pin checked at every `connect`, the corpus manifests at `format_version 3` naming the schedule each chain ran. **Not** a widening of the latch: the daemon, the FFI and the wallet keep reading process configuration through `SettlementSchedule::effective()`, and the validator is no longer among them. **Falsifier, two-sided:** the replay of `emission-claim` under `fakechain(None, FakechainSchedule::new(512, 64))` no longer refuses on the epoch (it now reaches the record read — commit 5's), and a replay of the same chain under `PRODUCTION` refuses at 1025 as before. **The diagnostic lesson:** the first diagnosis of that red — "the latch" — was right and incomplete; two causes shared one `Locus`, and only a print inside the fold separated them. A refusal that names its reason is a question for commit 8's oracle, where a red must localize (§6). |
| 2026-09-30 | **Commit 4 landed — the transition on the verdict, and the question Q1 implied: a delta the validator did not produce is unrepresentable.** `ArchivalDelta` has private fields and a private constructor; `archival::transition` is its only producer and two `compile_fail` doctests hold that (a struct literal, a call to `new`). The store will write what it is handed and cannot make one. Five rulings taken building it, each from the design and not the C++: **(1) The count operand.** The C++ hooks take `prev_height + 1` — the block *count* once this block connects, `connecting + 1` — and every schedule comparison ("count > deadline", "close due at", the close's `close_block_height`) is written against it; the port names that once (`Transition::count`) and every site reads it — the boundary the two close heights sat on (commit 2) is exactly where a `height`/`count` slip would hide. **(2) Refusal, not abort — and which is which.** L7's C++ text is "fatal verify-backstops"; here a post, credit or claim the folds cannot apply **refuses the block at its input** (`Locus::Input`), because a block the validator will not connect is not a store fault. What *is* a store fault is a record already in the view that the folds cannot take (floor broken, ordering, log cap, counter range, a slash on a shard not held, a bonded underflow): `Corrupt::BondRecordInvariant { persona, which }` → SI-7, `Corrupt::AccrualOverflow` → SI-8. The C++ conflated the two into one abort; the type separates them. **(3) An unparseable archival vin is L7's refusal, not G7's skip.** G7 skips a vin it cannot key because CEN-J1 owns the parse refusal and is pending; L7 is the writer's backstop and cannot write what it cannot read, so it refuses — J1, when it lands in `tx_against`, refuses earlier and L7's arm becomes the belt. Likewise a credit for a persona with no record: SI-15 named this "the writer's first check"; it is L7's, and SI-15's read-side walk is the belt beneath it. **(4) L8 and L9 dissolve into by-construction folds.** The close and the slash scan are derivations the transition performs at the heights they are due; nothing per block is *checked*, so there is no rule type — `accrue` and `apply_slash` return the aborts as `Corrupt` by type, and the C++'s "interval-decision failure" cannot occur (`slash_open_interval_to_append` returns an `Option`). The census rows flip to `by_construction` with the fold tests as falsifiers; the plan's §7 sentence "the coverage gate unchanged" was wrong about the arms and is corrected in place. **(5) A credit beyond the closed universe is `has_segment: false`, not an error.** `epoch_close_compute`'s `CreditIndexOutOfRange` is unreachable from the transition because every credited shard the snapshot knows is appended to the shard list; a persona credited on a shard that has not closed earns nothing for it, which is what the fold already says. And one the gate found rather than the author: the harness's serve-credit fixture carried a 33-byte placeholder "for 4.J" and connected only because nothing read it; L7 read it. It is now a parseable credit for a persona whose `join_market` precedes it in the block (`TxShape::precedents`), the balance test's bond post is the join (the one post that connects with no record), and the emission's *connect* — which needs a settled epoch no unit-test chain carries — moves to commit 5's driver with the rest of the populated-state cases (§6 row 4, disclosed). |
| 2026-09-30 | **Commit 3 landed — CEN-F17's `n` is the closed transaction-shard count, and the closure frontier has one home.** The pre-flight's formula (`⌊cumulative_tx_count / T⌋`, §3.7, §1 item 9, ARW-4, ARW-Q6) dropped the coinbase term: shards partition storage ids, which the C++ issues to coinbases and listed transactions alike, and `cumulative_tx_count` is the listed only. The correction is the same defect commit 2 met as the two close heights and commit 1 met as `storage_ids_through` — a quantity with two near-identical readings, re-derived at each site — so the ruling is the same as the evening before: **make it unrepresentable, do not document it.** `shekyl_types::closed_shards(storage_ids)` and `closed_shards_through(listed, h)` are the frontier's only home, beside `T` and `storage_ids_through`; the validator (`closed_shards_before`), the slash scan and the C++ (`shekyl_archival_closed_shard_count(get_tx_count())`) all call it, and no site divides by `T` for a frontier again. The re-key is atomic C++/Rust as FOLLOWUPS' D2 row requires and behaviour-neutral while the escalation is flat; `knee_n = 100 000` is the J-segment-era literal carried unchanged for the Stage-2 sweep to re-derive in the new unit. The freeze module, its FFI and the JSON key stay one more step, for the C++ the cutover deletes (§3.7's rule-22 paragraph). Row 8's `FoldOverflow` gained a second arm rather than a new invariant: an id total that overflows is the same store fact observed by the validator. |
| 2026-09-30 | **Commit 2 landed.** One finding worth its own line: the tree has **two "close height" notions** and the fold's tests briefly conflated them. `shekyl_archival_epoch_close_height(E)` — the FFI the LMDB fixture calls at `archival_substrate_lmdb.cpp:1780` — is the epoch's *last block*, `(E+1)·SEB − 1`; `consensus_state::epoch_close_height(E)` is the close-*processing* height, `(E+1)·SEB`, the open of `E+1`. A test helper written from the second name against a fixture built on the first put the added-shard case one block into the next epoch, where the shard is legitimately held, and the port read as wrong when the helper was. The fold is unchanged; the helper is `last(e)` and says which of the two it is. Rule 16's corollary in miniature: same word, two values, and the one that was convenient to reach for was the wrong one. **Ruled the same evening (maintainer): rename, do not document.** The case that caught it sat exactly on the one-block boundary; any other case agrees under both readings and a passing test measures the helper's reading of a name against a fixture built on the other. Commits 4–5 write the close path, which is entirely that boundary. So the last-block pair is `shekyl_archival_epoch_last_block` / `schedule::settlement_epoch_last_block`, and `epoch_close_height` is the processing height alone — the collision is unrepresentable, and the four "never the lookalike" comments it had cost become plain statements. |
| 2026-09-29 | **Review round on PR #904 (Copilot, eight findings — all validated at source, none copied, two changing the plan): the witness is a wire sidecar and `Candidate` carries it passed-through until CEN-B4; the stamp's denominator is stated with rule 47's half first; `digest_v1` includes the accruing total; `Inject` is a barrier and unjournaled; six chains, not four; two retained "commit 1" texts and a FOLLOWUPS owner aligned.** Then the maintainer's rulings on the round: **ARW-Q3's second half RULED — delete at close** (the row is a second copy once the budget has its permanent home; SI-23 makes the deletion structural, CEN-L1's shape; it closes the one reading that could muddle Q3 and Q9). **The `/get_blocks_by_height.bin` gap** — no capture can carry a real witness because only the p2p handler populates the sidecar — recorded as a FOLLOWUPS row with the producer as its blocker, so the one-line marshal is not remembered as "we should do that" at commit 8. **The stamp's witness list is derived, not maintained beside the family set:** an exhaustive `match` over `ArchivalFamily`, so a new family without a witness arm fails to compile (§3.8 item 2, §7). |
| 2026-09-29 | **Round 1 RULED (maintainer, PR #904) — defaults held on all nine, reasons of record replacing the ones posed (§8).** Q1 on slice 7's Q5 test (the validator computes the folds for 4.J anyway; the delta is free to carry; the third application of E3's arrangement, so a precedent). Q2 on ARW-2's discriminator (a reversal-only journal is a view of the undo log; the marker dissolves with the five). Q3 and Q9 named as one principle with two dispositions, SI-20 making the second safe. Q4 as the absence-as-value class caught mid-contradiction. Q8 as `SAR-Q2`'s clause firing on its own trigger — satisfied, not invoked. **ARW-1 confirmed at `blockchain.cpp:4734–4735`** and its value stated: the misdiagnosis it prevents (a divergence at exactly a writer bug's height, on the one closed-epoch chain). **The corpus now says which rows no block produced:** `out_of_band_writes` in every manifest, written by the generator from the injection it made, `[]` for five chains and the injected serve credit for `emission-claim`; `vectors_tests::only_the_named_chains_carry_out_of_band_writes` holds the list both ways (§3.8, §7). **`IngestEvent::Inject`'s scope stated** so it cannot become a general door (regtest-only, one row kind, the injector its sole producer, in no captured chain but the one). **The E6 boundary ruled as §2.2 drew it** — `PDM-Q6` item 4 row 1 was a crate assignment, not a lane binding. **`LMDB_WRITE_ATOMICITY_AUDIT.md` §10 moves into commit 6** with the digest. CEN-L10 → bucket 3 *at cutover, not here* confirmed as the L1 lesson: a census row tracks the implementation's state, not the plan's intent. **Two smaller records from the same round.** (i) The maintainer's ARW-1 pin read `:4735–4736`; the tree shows `:4734–4735` — the symbol pair was right and the range was read off a `sed` window rather than derived from the matched lines, which is how an off-by-one enters a citation that is otherwise correct; cite the lines the match returned. (ii) Commit 1's deletions land in `NOT_PORTED`, the bijection gate's fifth direction, not `FOLDED_INTO` — decided at pre-flight rather than at the gate, because a `FOLDED_INTO` row naming `undo_log` would pass mechanically while claiming the wrong relationship (§3.4). Implementation may begin against §6 once this PR lands. |
| 2026-09-29 | **Round 0 executed** at `dev@cac2dadbe` in a fresh worktree off `dev` HEAD (#889 merged). Fourteen findings (ARW-1 … ARW-14); nine questions posed with defaults (ARW-Q1 … Q9). The surface's C++ writers map to one verdict-borne delta and eight phase-body writes; five of six journals dissolve into the undo log and one is history; the slash scan's shard enumeration walks a retired table; the accrual and `total_bonded` are views; the corpus's one closed-epoch chain depends on an injected write the replay must model as an event, and no captured chain carries the transaction kinds slice 8's rules will judge — the C++ is an oracle for bonds, accrual, closes and claims only. The §7.1.1 gate is re-read and its discharge is inside the increment (commits 6–8), with the seam at which the PR may split named (§6.1). Families registered at birth. FOLLOWUPS `:176` discharged by writing the constraint into the parent plan (§2.6). No code. |
