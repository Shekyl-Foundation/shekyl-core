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

**Status:** CLOSED-as-record — **archived 2026-10-02 (DRS-E4 commit 10, the
last of PR-b)**; owns no open residue, each piece named where it now lives:
the one open question, `ARW-Q19`, is **re-homed** as `SLK-Q1` / `SLK-Q2` in
[`DRS_E4_SLASH_LOG_ROUND.md`](../design/DRS_E4_SLASH_LOG_ROUND.md) (the
round that owns it carries it from its start — a document kept live for one
question becomes the place that question hides); the C++ path and the Rust
that exists only to be marshalled from it are `DEL-008`
([`DAEMON_REDB_STORE.md`](../design/DAEMON_REDB_STORE.md) §12, with §12.1's
cutover-day list); SI-19…23 are
[`STORE_INVARIANT_REGISTER.md`](../design/STORE_INVARIANT_REGISTER.md)'s; the
E1/E4 boundary statement (§2.2, §2.3) is a records-was from landing, and
slice 8's pass admission is [`ARCHIVAL_SHARD_FETCH.md`](../design/ARCHIVAL_SHARD_FETCH.md)
`SF-D8`'s; `ARW-Q18` (a slash-bearing corpus capture) is RULED 2026-10-02 —
refused, with the one gap it would have closed discharged by the `0x04`
slash-family pin in the slash witness (§8). The writers are
`store/archival_write.rs`, the reads `store/archival_reads.rs`, the oracle
`shekyl-chain-ingest`'s `0x04` snapshot and the sufficiency stamp. History
follows. **Was: OPEN — implementing against §6: commits 1–5 landed (PR-a) as
of 2026-10-01; PR-b (commits 6–10) pre-flighted 2026-10-01 (§6.2); commits
6–9 landed 2026-10-01/02 on the PR-b branch** (1–4 merged to `dev` in PR #914, with the `SHT-Q2` re-key
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
[`IMPLEMENTATION_INDEX.md`](../design/IMPLEMENTATION_INDEX.md) §2 with this file
(rule 94 §1; `check_index_prefix_uniqueness.py` branch (a): `ARW` and
`ARW-Q` distinct, clear of the 109 registered). Parent plan:
[`DAEMON_REDB_STORE.md`](../design/DAEMON_REDB_STORE.md) — the **DRS-E4** node of the
lane graph (`E1 → E2 → E3 → E4 → E5`), §3.4 rule 3 (*"design typed cursors
for retention; delete gather shell — not 'rehost ~3k / 77 methods'"*, E-7)
and §7.5 table 2 (CEN-L7 … L10, L14 ×4, L16 arrive here). The boundary
statement this document builds against is
[`DRS_E1_SARCH.md`](DRS_E1_SARCH.md) §0 / §2.2 / §2.3 — *E1 mints what E4
writes into; E4 does not get to choose a second shape for the same byte* —
which that file held in `design/` "until E4's plan owns it"; this plan owned
it from §2 down, and that file archived beside this one when the increment
landed (§9; both in `completed/` from 2026-10-02).
Template: the DRS-E3 pre-flight shape
([`DRS_E3_CURVE_WRITER.md`](../design/DRS_E3_CURVE_WRITER.md), whose §3.7
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
  `path.rs`, their FFI exports). *Corrected at commit 9:* the whole surface
  deletes at the cutover, not half of it here (§3.9's timing; `DEL-008`),
  and "only" is not exact — the economics sim reads the freeze half too
  (`SHT-8`).
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
| `archival_bond_unbond_log` | pop: `release_pop` reconstructs the pre-image (`:6198–6269`) | journal, plus a Rust *pop fold* | **dissolved**; `release_pop` deletes with this revert at the cutover (`DEL-008`; §3.9's corrected timing — its only caller is this revert, and this revert is live until then) |
| `archival_bond_holdings_update_log` | nothing — HoldingsUpdate is REJECTED, the revert is a named no-op (`blockchain_db.cpp:773–776`; `db_lmdb.cpp:6270–6289`) | dead | **deleted** |
| `archival_bond_reinstate_log` | pop: `reinstate_pop` (`:6342–6400`) | journal + pop fold | **dissolved**; `reinstate_pop` deletes with this revert at the cutover (`DEL-008`) |
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
cutover commit (registered as `DEL-008` at commit 9, with the pop folds —
§3.9's corrected timing), blocked on that deletion — falsify by
`rg shekyl_archival_frozen_segment_count src/` returning nothing while the
Rust symbol still exists. `DRS_E3_CURVE_WRITER.md` §3.9's "scheduled here"
moves by the same one step. CEN-F17 has its operand; the rule stays E6's.

### 3.8 The §7.1.1 discharge — `ARW-Q5`, default: an archival digest family, tip-compared, plus the stamp

The gate names two acceptable forms: digest coverage over the archival
families, or a named exclusion with a **replacement KAT that forces
apply/revert to run**. This increment lands the first and makes the
existing mechanism for the second real:

1. **The archival snapshot** (*re-shaped 2026-10-01, `ARW-25`: this item
   was `digest_v1`, a 32-byte hash over the same families; at one
   checkpoint per chain a hash buys nothing a diff does not and costs the
   localisation, so the archival state travels as rows and the grader
   diffs — §3.8.1*) — the archival state as
   *logical* sets: bond records (`p → canonical record`), serve-credit
   keys, `(shard, E) → r_market` with zero-rows projected out (§3.6),
   `E → Σwork`, `E → budget`, **the open epoch's accrued total** (on review:
   the accumulator is the input to the next close, and a missing or wrong
   accrual write would otherwise match at every pre-close tip — the C++
   side normalises its per-height rows over `[E_open·SEB, tip]` to the same
   one logical value, the redb side reads its one accruing row), `h →
   witness`, the slash log, `slash_applied`, `last_slash_epoch`. Emitted by
   the C++ walker over LMDB
   (`BlockchainLMDB::logical_state_digest_v0`'s sibling, a marshal of
   decoded rows across the FFI into the Rust trace writer — rule 20's
   shim, no C++ encoding) and by `ReadSnapshot` over redb; the trace
   carries it as its own record beside the v0 checkpoint, which is
   unchanged. Tip-only, because that is what the C++ can produce (§1
   item 5).
2. **The sufficiency stamp armed**: with writers present, a session that
   stubs family X skips X's phase body and widens `Provenance.stubbed`
   (`ARW-9`'s default), and the run's snapshot goes **red** against the
   oracle *at family X* — the test that proves the apply ran, and names
   which. **Its denominator, stated on review:** a stubbed family the run
   never writes leaves the snapshot unchanged, so "red once per family" is
   only a claim over families the run *exercises* — and with the oracle
   as rows the denominator is **readable off the corpus**: a family with
   zero rows in every captured `0x04` record has no corpus witness, which
   is half (a) below made mechanical (`ARW-25`). The test therefore has
   two halves, and the first is
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
   commit 7. **Landed 2026-10-01 (commit 7), with two amendments taken at the
   code:** *(i)* the event is in the **corpus**, not the trace — the
   `inject` record, format v3, tag `0x03` (`corpus.rs`; `check_inject`:
   Fakechain only, a tip required, `at == tip`), because the corpus is what
   the replay *consumes* and the trace is what it is *judged against*; the
   "trace half" check is `vectors_tests::…_and_the_corpus_carries_exactly_those`:
   the corpus's `Inject`s equal the manifest's `out_of_band_writes`, and the
   replay's `RunReport::injected` equals them again after the run. *(ii)* the
   manifest row is one **receipt string** rather than `height` + `persona`
   fields — `Injection { at: BlockHeight, credit: ServeCredit }` has exactly
   one spelling, `<persona-hex>:<shard>:<epoch>@<height>` (`FromStr` /
   `Display` / serde, `source.rs`), and that spelling is the `--inject` flag,
   the report and the manifest, so the three cannot drift; the generator
   writes it from the RPC's `height` receipt (`regtest_inject_archival_serve_credit`
   now returns the attributed height, C++ and RPC). The falsifier §6.1 names
   is unchanged in substance — a manifest edit cannot produce a receipt the
   corpus and the trace both agree with. *Typed under `ARW-Q16` (a):* the
   receipt's `at` is a `BlockHeight` and the scenario test pins the
   `ARW-26` distinction at the door — the receipt is the committed tip, and
   `at + 1` is the connecting height, two names for two quantities.
   **Ordering (on review):** an `Inject` is a **pipeline barrier**,
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

### 3.8.1 The checkpoint's two encodings — the v0 digest as records-was, the archival snapshot's rows as specified (`ARW-24`, `ARW-25`; written 2026-10-01, before any code)

This section is the specification both legs of the checkpoint are written
against. It carries two things. **The v0 digest, as records-was:** v0's
specification lived only in `digest_v0.rs`'s doc comment and retires with
that file when the C++ walker does (§3.9), while every E2 checkpoint
captured to date — and every graded `digest_identical` in the comparator's
history — is denominated in v0. The v0 half is lifted from that comment
and **verified against the code at `dev@76bc64aa7`** (`canonical_preimage`,
the three constants, `PINNED_FIXTURE`); it is a records-was claim and
stays true when the function is gone. **The archival snapshot's row
encodings, as the serialization both sides emit** (`ARW-25`): the archival
state at the covered tip travels in the trace as canonical rows, not as a
hash of them, and the grader diffs. Whether this section is later promoted
to a contract document is `ARW-Q13`.

*Struck the same day it was written (2026-10-01, `ARW-25`; the text is at
`b728a8c81`):* a `digest_v1` — eight per-family cSHAKE accumulators under
`shekyl/chain-digest/v1/<family>`, two presence-tagged singletons, a
459-byte outer preimage under `shekyl/chain-digest/v1`, format tag `0x01`.
The row encodings it was to hash are the ones below, unchanged; what went
was the hash layer over them, for the reason `ARW-25` gives. `ARW-Q14`'s
ruling on the accumulator's shape is kept beside that strike as the record
the reversion clause would reopen into.

**Conventions.** Every integer in a row is **little-endian** — including
key components the stores hold big-endian, because the snapshot is
layout-independent by charter and the stored key form is the store's
business (`lmdb_order`). Values use the store codec's `Canonical` encoding
(`shekyl-store-codec`): the stored form *is* the comparison input, by that
crate's charter, so both legs encode in Rust — the C++ walker marshals
decoded fields over the FFI (`ARW-Q10` (a)) and the trace writer encodes.
For the v0 digest, the hash is cSHAKE256 with a 32-byte output
(`shekyl-crypto-hash::cshake256_32`; SP 800-185), one customization string
per context (SA-R-2); a counted sequence hashes its count, and an empty
sequence hashes the 8-byte zero count, never the empty string
(`empty_chain_is_not_the_empty_cshake`).

#### v0 — DRS-P0d, format tag `0x00`, the chain / spent-set / curve-root checkpoint; in force from DRS-P0d until the C++ walker is deleted; the only digest in every checkpoint captured to date — RECORDS-WAS

Outer preimage, **113** bytes, hashed under `shekyl/chain-digest/v0`:

| Offset | Width | Field |
|---|---|---|
| 0 | 1 | `0x00` |
| 1 | 8 | `n_blocks` — `BlockchainLMDB::height()` |
| 9 | 8 | `n_spent` — cardinality of `spent_keys` |
| 17 | 32 | chain component — `cSHAKE256("shekyl/chain-digest/v0/chain", u64(n) ‖ hash_0 ‖ … ‖ hash_{n−1})`, height order |
| 49 | 32 | spent accumulator — `⊕_ki cSHAKE256("shekyl/chain-digest/v0/spent-elem", ki)` |
| 81 | 32 | live curve-tree root (`get_curve_tree_root`; empty tree → Selene `hash_init`) |

Self-pinned tripwire (not a KAT): `digest_v0([0x11^32], [0x22^32, 0x33^32],
0x44^32) = a6990c0f feae0e0f fe437977 62928a3c 55bfc995 2bfcbf81 00e97665
e061def2`. Deliberately excluded: every archival family, the txpool,
alt-chain, txs, outputs, root history, `hf_versions` — which is why
`DAEMON_REDB_STORE.md` §7.1.1 forbade S-ARCH's extraction on a v0 match and
this increment exists.

#### The archival snapshot — this increment, trace record `0x04` under `TRACE_VERSION 0x01` (`ARW-25`)

The archival state at the covered tip, as the logical rows §3.8 item 1
names — emitted by the C++ walker over LMDB and by `ReadSnapshot` over
redb in the same encoding, compared by the grader **row by row**. The v0
digest is untouched: it remains the chain / spent-set / curve-root
checkpoint, and the `0x02` record keeps its 32 bytes. The snapshot is a
separate record for a separate state, and the trace version is what says
both are present.

*Tag corrected 2026-10-01, at the code reading before commit 6:* this
section was first written with the snapshot as record `0x03`. **`0x03`
is E2's RESERVED Verdict tag** (`DRS_E2_REPLAY_DRIVER.md` §3.9;
`trace.rs` `tag::RESERVED_VERDICT`, refused by the reader as
`ReservedTag`) — the mutation family landed with verdicts as code and
the byte stayed reserved so it would not be re-minted, which is exactly
what the first draft did (rule 23). The snapshot is `0x04`; `0x03` stays
reserved, and E2 §3.9's record table gains the `0x04` row in commit 6.

**Row encodings.** One row per logical entry, `key ‖ value`, little-endian
throughout; values `Canonical`.

| Family | Row (`key ‖ value`, LE) | Projection / exclusion |
|---|---|---|
| `archival_bond` | `p[32] ‖ Canonical(BondRecord)` (`bond_record`) | — |
| `archival_serve_credit` | `p[32] ‖ u64 shard ‖ u64 epoch ‖ u64 height` | set table — no value |
| `archival_r_market` | `u64 shard ‖ u64 epoch ‖ u64 r` | rows with `r = 0` are **not emitted** (§3.6 — the C++ writes them, the redb close does not; the snapshot is the logical non-zero set) |
| `archival_sigma_work` | `u64 E ‖ u64 Σwork_milli` | — |
| `archival_budget` | `u64 E ‖ u64 budget` | — |
| `archival_attestation_witness` | `u64 h ‖ witness bytes` (`1 ≤ len ≤ MAX_ATTESTATION_WITNESS_BYTES`) | an empty attestation set is **no row** on both sides |
| `archival_slash_log` | `u64 height ‖ u32 seq ‖ Canonical(SlashLogEntry)` (`slash_log_entry`) | the C++ epoch-marker rows (`kArchivalSlashLogEpochMarkerSeq`) are **not emitted**; the C++ row's slashed amount is **projected out** (`ARW-Q2`) |
| `archival_slash_applied` | `p[32] ‖ u64 shard ‖ u64 epoch` | set table — no value |
| open epoch's accrued total | `u64 E_open ‖ u64 total` — **zero or one row** | redb: the one `archival_budget_accruing` row; C++: `Σ` of `archival_budget_accrual[h]` over `h ∈ [E_open·SEB, tip]` with checked addition (`archival_snapshot.cpp`, the walker's one arithmetic). **Present iff the tip did not close its epoch** — *corrected 2026-10-01 at the walker, from "no row when the range holds none":* the redb writer upserts the row on **every** connect inside `E` (phase 9a) and removes it in the connect that closes `E` (SI-23), so after a zero-inflow block the redb side holds `E → 0` and the C++ side, which writes no row for a zero inflow (`blockchain_db.cpp`, the §3.1 burn-row convention), must read the sum of none as **a row of zero**, not an absence; and when the tip is `(E+1)·SEB − 1` neither side has a row. Code on `dev` wins over this table's first reading (rule 95). |
| `archival_last_slash_epoch` | `u64 E` — **zero or one row** | redb: the chain-state cell, `Option`; C++: the key, with its `UINT64_MAX` sentinel (`db_lmdb.cpp:5217`) read as **no row** (`ARW-Q11`) |

The two singletons are families of cardinality `≤ 1`, not presence-tagged
fields: one framing for everything the snapshot carries, and "absent" is
the same zero-row shape everywhere.

**Record framing.** `0x04 ‖ height u64`, then for each family in the
table's order (ten families, fixed by this section — the family tag is
positional, not a byte): `n_rows u64`, then each row as `len u32 ‖ bytes`.
Rows are emitted in the family's key order — both stores yield it
natively (`schema.rs:547–608`; `ARW-Q14`'s corrected premise) — and the
grader compares **as sets keyed by the row's key**, not as sequences, so
an emission-order difference is not a divergence (the state carries no
order) and a key present on one side only is reported *as that key*.
Exactly one `0x04` record per trace, at the covered tip, iff
`TRACE_VERSION ≥ 0x01` **and the trace carries a checkpoint** (*amended
2026-10-01 at the writer:* the `0x02` and `0x04` records are one
checkpoint's two encodings, so under `0x01` they are present together or
not at all — the writer refuses `finish()` holding one without the other
(`TraceFault::MissingSnapshot`), the reader refuses a file with one and not
the other, and a trace exported below the tip, which carries no checkpoint
(RD-F18), carries no snapshot either); its presence — not the version byte
— is what distinguishes a version-`0x01` trace from a `0x00` one (rule 22's
falsifier class, §6.2 item 2). An empty archival state is a `0x04` record
of ten zero counts, 88 bytes after the tag (`8 + 10 × 8`); it is never
omitted. The reader kept both arms through commit 6 — the six committed
corpus traces were `0x00` and had to stay readable until commit 7
re-captured them — and a `0x00` trace's run reported the snapshot as
**not compared**, never as identical. **Commit 7 (2026-10-01) deleted the
`0x00` arm with the re-capture** (§6 rows 6–7): the reader accepts
`TRACE_VERSION` alone (`0x00` is `UnsupportedVersion`), every trace with a
checkpoint carries its snapshot by construction, and `RunReport::archival`
is therefore always present when a checkpoint is — the "not compared"
state no longer exists to be reported.

**What the grader reports.** For each family: rows on both sides and equal;
rows on both sides and unequal (the key, both values); keys on one side
only (which side, the key). The comparison is its own oracle in
`Observations` beside the root oracle (`RootOracle`), **not** a clause of
the per-CEN-row `ComponentEvidence` — a snapshot divergence is a fact
about the run's end state, not about a row's verdict, and it fails
`GradedRun::passes()` the way a root divergence does (*corrected
2026-10-01 from "`ComponentEvidence` gains the snapshot clause", at the
code reading: `ComponentEvidence` grades one CEN row's exercise*). A run
is `DIVERGE` on any inequality, and the record names the family and the
key — which is the whole reason the snapshot is rows (`ARW-25`).

**Not in the snapshot, by name:** `archival_settlement` (held, SO-D8), the
seven `NOT_PORTED` rows (no state to compare), `archival_alt_attestation_witness`
(alt-chain, excluded as v0 excludes alt-chain), the txpool. The snapshot is
**tip-only** (§1 item 5). A v0 match says nothing about any family in the
row table; a snapshot match over a run whose `Provenance.stubbed` is
non-empty is a regression instrument, not correctness evidence (CSR-3).

**Falsifiers the implementation carries.** The row table above reproduced
as an exhaustive `match` over `ArchivalFamily` plus the two singletons —
an arm per retained family returns its row encoder; `Settlement`, the
journals and `AltAttestationWitness` return the named exclusion — so a
family added to the X-macro without a snapshot disposition is a compile
error; the record's family count asserted equal to the table's; a reader
of a `0x00` trace refusing a `0x04` record and a reader of a `0x01` trace
refusing its absence; and the six corpus traces, re-captured in commit 7,
whose `0x04` records are the C++ reading of the archival state **committed
as data** before the walker is deleted — the I17 shape, with the fixture
being the rows themselves (`ARW-23`, re-pointed).

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
**Timing — corrected at commit 9 (2026-10-02).** As posed: *"the C++
deletes at cutover, when the Rust daemon is consensus (`DRS_E1_SPRUNE.md`
§13's rule); the Rust pop folds and the freeze half delete in this
increment (no caller survives the C++'s retirement, and they are not
reference implementations of anything)."* The parenthetical is true of the
state **after** the cutover and was read as the state **at** commit 9 — a
future-perfect premise taken in the present tense, the mood variant
`16-architectural-inheritance.mdc` records for `RANDOMX_V2_RUST.md` §9.
The C++ has not retired: `release_pop` and `reinstate_pop` are called by
`shekyl_archival_release_pop` / `shekyl_archival_reinstate_pop`
(`shekyl-ffi/src/archival_ffi/bond.rs:613`, `:825`), which the C++ pop
path calls at `db_lmdb.cpp:6237` and `:6369` — inside this section's own
`:6003–6400`, which deletes at cutover — and the C++ daemon is consensus
until then, so its pop must still revert a Release and a Reinstate.
`segment_freeze.rs` was already re-scheduled to the cutover by commit 3
(§3.7, with its falsifier) without this sentence being amended; the pop
folds have the same shape and were never examined. **So the whole surface
— C++ and Rust — deletes at the cutover, registered as `DEL-008`
(`DAEMON_REDB_STORE.md` §12); falsify by
`rg 'shekyl_archival_(release|reinstate)_pop|shekyl_archival_frozen_segment_count' src/`
returning nothing while a Rust symbol still exists.** The survey that found
this (every `extern "C" fn shekyl_*` under `archival_ffi/`, 60 exports,
against `src/` and `tests/`): 59 have a C++ caller — two of them only in
`tests/unit_tests/archival_credit_wire.cpp` (`shekyl_archival_attestation_header_bytes`,
`shekyl_archival_max_attestation_records`, the attestation path's rows in
FOLLOWUPS) — and **one has none**: `shekyl_archival_settlement_epoch_overridden`,
declared in `shekyl_ffi.h` and never called (the daemon's startup gate reads
`…_override_present` and arms; the "loud fakechain warning" its doc named
was never written). It and its only backing,
`shekyl_archival_retention::settlement_epoch_blocks_overridden`, are
deleted in commit 9 — the one item of this half whose deletion no caller
blocks. Two further readers of the freeze half were **not the C++ at all**:
the retention crate's serve-credit mirror (`serve_credit_decisions.rs:396`
at the survey, the leaf-preimage gate — **deleted 2026-10-02, commit 10d**:
this sentence had deferred it to "`PDM-Q6` item 4's re-key, `ARW-13`", a
blocker that was itself an unscheduled ruling, so the deferral was void
under rule 22 and the mirror, its equivalence KAT, fixture, C++ leg and two
fuzz targets went outright — nothing called them, and they implemented the
retired preimage) and `shekyl-economics-sim`
(`frozen_segment_count`, `SEGMENT_LEAF_COUNT` in `burden.rs`, `swing.rs`,
`calibration.rs`, `stage2.rs` — the segment-era literals `SHT-8`'s FOLLOWUPS
row owns, still a reader); §2.1's *"the Rust that existed only to be called
from them"* is narrowed by the same finding. The pop folds' tests
(`bond_connect_tests.rs:178–262`, `:432–447`) stay with the folds.

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
| 6 | **The archival snapshot** (§3.8; *re-shaped 2026-10-01 from `digest_v1`, `ARW-25`*): **the row encodings and the record framing specified first** (§3.8.1, before any code — rule 05; `ARW-24`); the redb side's `ReadSnapshot::archival_snapshot()` emitting §3.8.1's rows; the C++ walker's marshal of decoded rows across the FFI into the trace writer (`ARW-Q10` (a)); the trace's `0x04` record (*`0x04`, not the `0x03` first written here: `0x03` is E2's RESERVED Verdict tag — §3.8.1*) and `TRACE_VERSION 0x00 → 0x01`, the `0x02` record unchanged (`ARW-Q12`, re-ruled); the reader keeping its `0x00` arm so the six committed corpus traces stay readable until commit 7 re-captures them, a `0x00` run reporting the snapshot *not compared*; the grader's row-by-row comparison naming family and key, as its own oracle beside the root oracle (§3.8.1, corrected). **The LMDB-fixture capture lands here too** (`ARW-Q15`, ruled): the walker in capture mode over the unit fixture's slash-and-close state, writing the rows **and the named inputs the Rust side must reproduce** as committed data beside the scenario driver, consumer commit 8. **No hasher, no domain strings, no KAT fixture**: the C++ reading of the archival state is committed as data by commit 7's six `0x04` records, which *are* the rows (`ARW-23`, re-pointed). **Two format numbers move in PR-b and neither is a falsifier** (§6.2 item 2): the trace's `TRACE_VERSION` `0x00 → 0x01` here — falsified by *exactly one `0x04` record at the covered tip*, which a reader of the old version refuses and a reader of the new one requires — and the manifests' `format_version` `3 → 4` in commit 7, falsified by *the injection's `height` and `persona` on every `out_of_band_writes` row*. **`LMDB_WRITE_ATOMICITY_AUDIT.md` §10 moves in this commit, not in commit 10**: the sixteen archival journals' `Digest v0` state → *in the archival snapshot* / *dissolved* and the §7.1.1 exclusion retired, so the document and the mechanism move together — that exclusion is load-bearing for what the checkpoint is allowed not to cover, and a stale sentence there does real damage (ruled 2026-09-29). **Reversion clause** (rule 21, `ARW-25`): the snapshot is the right instrument at one checkpoint per chain; if the cadence ever becomes per-block (RD-F18 lifted — a spent set reconstructible at a past height) the trade flips and a hash re-enters, under `ARW-Q14`'s ruling as recorded. *As landed (2026-10-01):* `shekyl-chain-store::archival_snapshot` (ten positional families, an exhaustive `Disposition` over `ArchivalFamily`, the body codec, the set-keyed diff) and `ReadSnapshot::archival_snapshot()`; `trace.rs` tag `0x04`, `TRACE_VERSION 0x01`, both reader arms, the five new `TraceFault` arms; the snapshot oracle in `Observations` / `RunReport.archival` / `Disagreement::ArchivalDiverged` (`shekyl_e2_grade_v3`); the FFI's `ShekylE2ArchivalSnapshot` builder (eleven row pushers, `push_archival_snapshot`, `write_json`, `ERR_ROW`); the C++ walker `src/blockchain_db/lmdb/archival_snapshot.cpp` — one read txn, one cursor per family, **its one arithmetic the accruing checked sum** — and the exporter pushing it after the checkpoint; the `ARW-Q15` capture as `rust/shekyl-chain-ingest/fixtures/archival_fixture_slash_m_of_n.{inputs,rows}.json` with `snapshot_json` as its reader and a test holding the pair to each other. **Two §3.8.1 amendments taken at the code, disclosed here:** (i) the `0x02` and `0x04` records are one checkpoint's two encodings — present together or not at all (`MissingSnapshot`); (ii) the accruing row is *present iff the tip did not close its epoch*, zero included, because the redb writer upserts it on every connect and the C++ writes no accrual row for a zero inflow — the plan's "no row when the range holds none" was wrong against the code on `dev`. **One finding, not adjudicated: `ARW-26`** — the two writers key `archival_slash_log` by heights one apart (C++ the count, Rust the connecting height), surfaced by the capture's consistency test; commit 8's. | M | the C++ walker: the only C++ this increment adds, and rule 20 holds it to a marshal — if it grows arithmetic, stop |
| 7 | **The injection event** (§3.8 item 3): `IngestEvent::Inject` with its stated scope (regtest-only, one row kind, the injector its sole producer), the exporter reading the injector's receipt, the connector applying it through the store's regtest door, the trace-half check (an `Inject` iff the manifest's `out_of_band_writes` names one); **re-capture of all six captured chains** (`CAPTURED_SHAPES`, `vectors_tests.rs` — the format moves for the whole corpus or the all-captures gate refuses the two left behind) under the corrected regtest table and the v1 checkpoint, the generator writing the injection's height and persona into the manifest; **the trace reader's `0x00` arm is deleted with the re-capture** — scaffold commit 6 keeps for the six `0x00` traces, with no reader left once they are `0x01`. *Scope stated before it starts (pre-flight 2026-10-01, §6.2):* **this is six regtest generator runs, not "a re-capture"** — one per chain, each a daemon brought up, driven to its shape and exported, each of the order of the hour-plus a run has measured — on the critical path to 8 and the largest unestimated piece in PR-b. The six manifests move to **`format_version: 4`**, and the field that proves the run happened is the injection receipt: every manifest carries `out_of_band_writes[*].height` and `.persona` (the five block-derived chains an empty list, `emission-claim` its one row), written by the generator from the injection it made — the falsifier a manifest edit cannot satisfy (§6.1). *Preceded (2026-10-01, disclosed here per rule 22 — not in the §6 plan) by one commit outside the numbered ten:* **the `ARW-Q16` (c) gate** (`check_inland_height_u64.py`, grandfathered at 174), landed before this commit so that the trace, manifest and generator code it writes cannot mint a bare-`u64` height — commits 7–9 run under it. *As landed (2026-10-01):* **the event is in the corpus, not the trace** — `IngestEvent::Inject(ServeCredit)` beside `Extend` / `Rewind`, the corpus moving `v2 → v3` with an `inject` record (tag `0x03`: `at ‖ persona ‖ shard ‖ epoch`), `check_inject` refusing it off Fakechain, on an empty chain and anywhere but the tip (`InjectOffFakechain` / `InjectOnEmpty` / `InjectNotAtTip`); the pipeline applies it as a `Barrier::Inject` through `ChainStore::regtest_inject_serve_credit`, unjournaled, and refuses a later rewind below it (`PipelineFault::RewindBelowInjection`) — so the trace-half check the plan put on the trace is `vectors_tests::only_the_named_chains_carry_out_of_band_writes_and_the_corpus_carries_exactly_those`, holding the manifest's rows and the corpus's `inject` records to each other, per chain. **One spelling for the receipt** — `Injection { at: BlockHeight, credit: ServeCredit }`, `<persona-hex>:<shard>:<epoch>@<height>` (`FromStr` / `Display` / serde string) — read by the fetcher's `--inject`, reported in `RunReport::injected`, and written by the generator as the manifest's `out_of_band_writes[*].receipt`; the C++ injector gained its receipt out-parameter (`regtest_inject_archival_serve_credit(…, attributed_height)`) and the RPC answers `height`, which is the committed tip the credit was keyed at (`at + 1` is the connecting height — `ARW-26`'s pair; posed in commit 8 as `ARW-Q17`, there being no spec to adjudicate it against, and **ruled** the same day from the reader's predicate: the connecting height). Typed under `ARW-Q16` (a): no new bare-`u64` height in the five crates; the gate's record is unchanged at 174. **The `0x00` arm is deleted with the re-capture**: `TraceFault::UnexpectedSnapshot` with it (one `shekyl-ffi` code arm), a `0x00` header is `UnsupportedVersion`, and `RunReport::archival` is `Some` whenever a checkpoint is. **Six re-captures at `05fe1a3a9`**, all `format_version: 4`; the five block-derived chains an empty `out_of_band_writes`, `emission-claim` its one `receipt` (`…:0:1@115`); every chain replays to `digest MATCH` with its archival rows `MATCH` (bond-post 2, spend-1in-2out 1, spend-depth3 1, emission-claim 9, limit-full 1, median-full 1) — the archival oracle green on the corpus from this commit on, with `ARW-26` not yet exercised (no capture carries a slash, `ARW-13`). **Found running them, recorded for the next re-capture:** the six generators are **one process each** — the emission-claim generator arms the settlement-epoch lever process-wide (`OnceLock`, `ArmedTooLate`) *and* sets it in the process environment, which a sibling generator's spawned exporter inherits and refuses (`SHEKYL_SETTLEMENT_EPOCH_BLOCKS=512` against a 10 000-epoch data dir); and three concurrent daemons were enough for `generateblocks` to time out at 180 s on the two full-block shapes, which were then captured alone against a `Release` daemon. The manifests record that: four carry the `Debug` daemon's version string (`3.1.0-50fa03d2f` — the tag is CMake's configure-time cache, `cmake/Version.cmake` `VERSIONTAG … CACHE … FORCE`, so it names the HEAD the build directory was *configured* at, not the tree it compiled), two the `Release`'s (`3.1.0-05fe1a3a9`); both binaries were built from this commit's working tree, and `built_at_dev_sha` is `05fe1a3a9` on all six. The RPC response's new field moved `CORE_RPC_VERSION` `3.38 → 3.39` per the `core_rpc_server_commands_defs.h` convention (re-minted `3.40 → 3.41` at the `dev` merge of 2026-10-02: 3.39 and 3.40 had been taken by `archival_len` and `target_height` while the branch was open). The AFC-1 register's one later `blockchain.cpp` anchor moved a line with the out-parameter and was re-resolved. | M | the exporter cannot see the injection (no receipt in LMDB) — then the generator writes one, and the re-capture waits on it |
| 8 | **The oracle** — the protected commit. Replay all six chains; the v1 digest at every tip; the sufficiency red for every family the run exercises (§3.8 item 2). A tip disagreement on `bond-post` or `emission-claim` **stops the PR** and is adjudicated against the spec (E2 §0), never toward the C++ — with one named exception: a divergence that traces to zero-as-absence (§3.6) is the projection's bug, not a finding. *UPDATE 2026-09-30 (the row 5 ruling):* a slash-bearing capture for the digest is now **optional and cheap** — with the grace derived from the epoch, a regtest generator run under `SEB 100` reaches a slash in ~1 300 blocks — and the order in which to reach for it is fixed here so the expensive form is not taken first: (1) the unit witness (row 5, landed) is the 9b coverage; (2) if commit 8 wants the slash families in the digest's exercised set, run the generator, do not hand-build a chain; (3) a lever on the grace is not an option — the ruling closed it. The capture's real shape is a **driver-capability** question, not a block-count one: eleven consecutive epochs whose observations settle as misses 2-of-3, which the B9 chain gets by absence (nobody serves) and a populated capture would need the scenario driver to produce. *UPDATE 2026-10-01 (commit 6):* the `ARW-Q15` fixture capture is committed (`archival_fixture_slash_m_of_n.{inputs,rows}.json`) and arrives with its first disagreement already on the table — **`ARW-26`**, the slash log's height operand. *Corrected 2026-10-02, before this commit ran:* there is nothing to adjudicate it **against** — no spec names the key (`LMDB_SCHEMA.md:681–710` gives the table's shape and its readers, not what the row's height means), so `ARW-26` is a **new ruling, posed** (`ARW-Q17`), not a reading of the spec, and the capture's role here is to say the two sides disagree and exactly how, not to settle which is right. The posing lands **typed at the site it changes** (`ARW-Q16` (a): the key is built from a `BlockHeight` or a `ChainCount` through a named bridge with its `compile_fail`, not from a `u64` that could be either). *Pre-declared 2026-10-02, written before the stamp ran so neither reads as a defect:* (1) **the slash and close families have no corpus witness.** The census predicted from the six committed `0x04` records (row counts in commit 7's replay logs: bond-post 2, emission-claim 9, the other four 1): `budget_accruing` on all six (the open epoch's one row); `bond` on `bond-post` and `emission-claim`; `serve_credit`, `r_market`, `sigma_work` and `budget` on `emission-claim` only (SEB 512, the one chain that crosses an epoch); `slash_log`, `slash_applied` and `last_slash_epoch` on **none** (`ARW-13`: no capture slashes). The census test asserts that table in both directions. (2) The `0x04` snapshot's slash rows are therefore **empty across all six**, and the stamp's stub half cannot go red for the slash families on this corpus: they are reported as *no corpus witness* — the declared red — by the exhaustive match, not silently green. That red is §6.2 item 5's decision point, posed as `ARW-Q18`, not taken here. *The census run refuted one third of (1), same day:* `last_slash_epoch` **is** on `emission-claim`. The watermark is the deadline scan's *progress*, moved when an epoch's slash deadline passes whether or not anything was slashed — a cell both writers advance with no slash behind it, which the pre-declaration had filed with the slash rows. The slash rows are empty on all six as declared; `attestation_witness` is on none (also predicted). Consequence, measured rather than declared: the `SlashLog` **gate** has a stub witness — stubbing it on `emission-claim` goes red on the watermark cell and nothing else (`stubbing_the_slash_log_is_noticed_through_the_watermark_alone`) — while the slash **rows** have none. Stub outcomes (`stubbing_each_witnessed_family_is_noticed`): `Bond`/`bond-post`, `RMarket`, `SigmaWork`, `Budget`/`emission-claim`, `BudgetAccrual`/`spend-1in-2out` each diverge on exactly their own family; `ServeCredit`/`emission-claim` **cascades** — the injected credit's write refuses under the stub (`Cannot(FamilyStubbed(ServeCredit))`) before the tip, so the oracle never compares. Recorded as the outcome, not hidden: the stub is noticed, by the store rather than the comparator. *As landed (2026-10-02) — the `ARW-Q15` consumer:* **the fixture's state has a constructed path**, so the fixture stays (the ruling's deletion clause does not fire). `archival_fixture_replica_tests` rebuilds it through the production stack under a levered regtest schedule (`SEB 100`, cap 50 — the smallest the shape fits: both joins must land in epoch 0, and a coinbase first spends 71 blocks after its height): two real bond posts, eleven injected passes, 1 301 blocks to one past epoch 11's deadline — 76 s in the default lane, no `#[ignore]`. The comparison is **role-mapped** (persona by role, epoch by epoch, height through each side's own schedule) and **structural per family**, with what differs by construction *asserted* rather than skipped: the schedules; the pass height (the C++ chose 1 000, the injector attributes to its tip); the seeded two-floor bond against the join's pinned one (the *burn* compares — one floor from the slashed persona, nothing from the served); seeded identity bytes against derived keys. Everything the inputs name as state compares equal: holdings, bad intervals, join epoch, claims, first paying height, the eleven `(persona, shard, epoch)` passes, the applied set, the watermark, the close families' key sets (`budget` `0..=12`, `budget_accruing` `{13}`, `r_market` empty on both — bits, not responses), the fixture's accruals zero as its minimal blocks imply. **The one disagreement is the slash-log key, exactly as `ARW-26` said:** one row each, equal on every field of the entry, the fixture's at `slash_deadline_height(11) + 1` (the fold count), the replica's at `slash_deadline_height(11)` (the connecting height) — both equations pinned, so either writer moving fails the test; which name the row carries is `ARW-Q17`'s to rule — **ruled, same day: the connecting height**, from the fold predicate the log exists for, and the C++ side of the pin is `ARW-27`'s live off-by-one, not a second denomination of the same answer. What this does **not** do: make the slash families corpus-exercised. The stamp's census still finds zero slash rows on all six chains, and that red — with this finding attached — is `ARW-Q18`. What it also does not do, by decision: re-key the log by its query or retire it at F19's horizon — both posed as **`ARW-Q19`** for a short round after PR-b, the horizon being a condition the writer's landing fired (FOLLOWUPS' journal-horizon row). | S | a disagreement — which is what the commit exists to produce |
| 9 | **Rust deletions** (§3.9's Rust half). **As built (2026-10-02):** the survey the row required found the half cannot delete here — every item is called by the live C++ through the FFI (the pop folds at `db_lmdb.cpp:6237`, `:6369`; the freeze half by the freeze pipeline, the coverage RPC and the serve-credit verifier) and the C++ is consensus until the cutover; the row's premise was the post-cutover state read as the present (§3.9's corrected timing). Deleted: the one dead archival export, `shekyl_archival_settlement_epoch_overridden`, and its backing `settlement_epoch_blocks_overridden`. The rest is registered as `DEL-008` with the C++ half it belongs to; §2.1, §4's table and §7's denominator note corrected to match. | S | — |
| 10 | **Docs** (§9). *As landed (2026-10-02), three commits, one scope each:* **10a** — rule 91 gains the refuted-premise bullet (a finding that refutes a premise edits the premise's own text in the same commit, not only a findings register; the three instances in this lane named); **10b** — `DAEMON_REDB_STORE.md` §12.1, the cutover-day list anchored on `DEL-008` (the register is of deletion decisions; the list of what goes red or stale on the day is now one table, each entry with its disposition — retire, re-classify, re-baseline — and the rule for the day: never clear a gate, retire its subject); **10c** — this document and `DRS_E1_SARCH.md` archived as record, `ARW-Q19` re-homed to a new round (`DRS_E4_SLASH_LOG_ROUND.md`, `SLK-Q1`/`SLK-Q2`) that owns it from its start, the S-ARCH row's write half LANDED, the two FOLLOWUPS owners re-pointed, and the fired premise *"the journals have no Rust writer yet"* edited at its two live sites (`reorg.rs`, `DRS_E1_SPRUNE.md` §3) under 10a's bullet. §9's remaining items discharged per line (see §9). *Two more landed after the archive, in the same lane, under maintainer rulings:* **10d** — the serve-credit mirror (`serve_credit_decisions.rs`), its equivalence KAT, fixture, C++ leg and two fuzz targets deleted (§3.9's deferral of it was void: its blocker was an unscheduled ruling); **10e** — `ARW-Q18` ruled, the witness pins the `0x04` snapshot's slash families at non-empty against the production writer; **10f** — rule 08's reporting habit. | S | six docs/deletion commits |

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
what its falsifier is (~~`rg 'digest_v1' rust/shekyl-chain-store/src` →
present~~ **re-pointed 2026-10-01, `ARW-25`:** `rg 'fn archival_snapshot'
rust/shekyl-chain-store/src` → present, and each vector's trace carries one
`0x04` record; ~~the six manifests at `format_version: 3`~~ **CORRECTED
2026-10-01 (§6.2, `ARW-16`):** every one of the six `manifest.json` files
carries `out_of_band_writes` whose rows each name `height` and `persona`,
at `format_version: 4` — the version alone was satisfied by `ARW-15`'s
`settlement_epoch_blocks` edit before PR-b began; *landed at commit 7 as
one `receipt` string per row carrying persona, shard, epoch **and** height
in `Injection`'s one spelling — the same fields, one encoding, §3.8 item 3's
amendment (ii)*). PR-a landed as #914 + #921 (2026-09-30 / 10-01); PR-b
opens on commit 6.

### 6.2 PR-b pre-flight — 2026-10-01, at `dev@76bc64aa7` (#921 merged)

Executed in a fresh worktree off `dev` HEAD before commit 6's first line.
Five things the record takes from it, then the substrate findings
(`ARW-16…ARW-25`) and the questions commit 6 poses (`ARW-Q10…ARW-Q15`).
*Amended the same day:* `ARW-25` re-shaped commit 6 from a `digest_v1`
hash to an archival **snapshot** of rows; items 2 and 3 below are read
with that re-pointing where they say "hasher", "KAT" or "v1 digest".

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
(maintainer, 2026-10-01). *Re-pointed the same day under `ARW-25`: the
principle stands and the carrier changed — with the checkpoint carrying
rows, commit 7's six re-captured traces **are** the committed C++ reading
of the archival state, and the separate KAT fixture and both of its legs
below are not built. The paragraph is kept as the reasoning; the
LMDB-fixture capture for the families the corpus does not reach is
`ARW-Q15`.* A comparison between the walker and the Rust
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
after the bench rather than before it. *UPDATE 2026-10-02 (commit 8
reported):* the stamp is **red as pre-declared** — zero slash rows on all
six, the `SlashLog` gate noticed only through the watermark cell. The
capture this item held is therefore live, and it is **posed as
`ARW-Q18`**, not run here: the replica (row 8) now evidences what the
C++ slash writer writes and exactly where the Rust one disagrees, which
is the evidence a seventh capture was for — what it would add is a slash
*on a captured chain*, exercising the Rust writer under the corpus
oracle rather than under a role map. Whether that is owed before
genesis, and the driver question it carries (eleven epochs of misses the
scenario driver would have to settle 2-of-3), is the maintainer's call.
*UPDATE 2026-10-02 (ruled):* **refused** — `ARW-Q18`'s default taken, and
the one thing a seventh chain would have added (the `0x04` record's slash
families serialized at non-empty) pinned instead in the slash witness, from
the production writer's state, in a test that already runs. See the row.

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
| **ARW-23** | **The KAT's capture instrument is the LMDB unit fixture, not the corpus.** The six captured chains commit traces and manifests, no LMDB state, so the walker has nothing committed to walk; and no chain has a slash (§2.4). `tests/unit_tests/archival_substrate_lmdb.cpp` drives every archival writer through the C++ appliers of record — `apply_archival_slash_one` (`:1598`, `:1655`, `:1712`, `:1806`), `process_archival_epoch_close_at_height` (`:565`, `:921`), the accrual/burn partition (`:965`), the witness (`:1096`), bond records and serve credits — so a capture-mode leg over that fixture's state covers **every** family `digest_v1` names, the two the corpus cannot reach included. Fixture home `rust/shekyl-chain-store/tests/fixtures/archival_digest_v1_kat.json` (I17's placement: beside the Rust leg that holds the derivation of record), one file carrying several states — at least: empty archival state; one bond and credits in an open epoch; a closed epoch with `r_market`/`Σwork`/budget rows and a zero `r_market` row (§3.6's projection exercised); a slash applied. Each state carries its rows per family, the preimage, the digest, and the `captured_by` daemon version. **Cardinality is what gives the KAT its power** (maintainer, 2026-10-01): the fixture's writer calls loop over epochs, shards, sequence numbers and intervals (fifteen such loops), so the instrument writes **multi-row families**, and the KAT must too — a digest over one row per family cannot see a defect that two rows expose (an ordered fold's ordering, a count's encoding, the zero-row projection applied among non-zero rows). So the coverage is **stated in the fixture's own `description`, per family, at each cardinality** — *empty*, *one*, *several*, and **at the frozen cap where one exists** (`MAX_HOLDINGS_SHARDS` held shards, `MAX_BOND_BAD_INTERVALS`, `MAX_CLAIMED_EPOCH_ENTRIES` on a bond leaf; `MAX_ATTESTATION_RECORDS` on a witness leaf) — the discipline of `the_record_round_trips_at_every_cap` (`codec/archival_tests.rs:62`), which is why the `BondRecord` move could claim its bytes held *at the boundaries* rather than at whatever the fixtures happened to hold. A digest fixture that does not say its cardinalities invites the next reader to assume more coverage than it has. **The empty case is the load-bearing one**: the stamp's whole job is telling *the phase ran and wrote nothing* from *the phase never ran*, and it can only assert that against a **pinned** `digest_v1` over an empty family; unpinned, an empty family's digest is whatever the implementation produces and both sides agree by accident. Every family's empty value is in the fixture. **Re-pointed 2026-10-01 under `ARW-25`** (same day): with the checkpoint carrying rows there is no hash to pin and no KAT fixture — the six re-captured traces' `0x04` records are the committed C++ reading, and the cardinality discipline moves to **what the corpus is checked to contain**: a test over the captured traces asserting, per family, which chains carry it at which cardinality (the `emission-claim` close rows at *several*; the `bond-post` bonds at *several*; every chain's slash families at *empty*), so coverage is stated in the repository rather than assumed. Two corrections this row owed: (i) **ordering** — under `ARW-Q14` (a), and now under a set-compared snapshot, cardinality cannot catch an order defect and the row no longer claims it; what it tests is the row encoding at each count, the §3.6 projection among non-zero rows, the cap boundaries, and the count itself. (ii) **The empty case** — state alone cannot tell *ran and wrote nothing* from *never ran*: both are zero rows on both sides, and a pinned empty digest would have been `0^32` either way. What tells them apart is `Provenance.stubbed` on the Rust side and, for the denominator, the oracle's **non-empty** rows — which is why the snapshot makes half (a) of the stamp mechanical (§3.8 item 2). The empty case is still asserted (a `0x04` record of ten zero counts is emitted, never omitted — §3.8.1), but as a framing fact, not a pinned hash. |
| **ARW-24** | **`digest_v0`'s preimage is specified nowhere but its own doc comment.** `digest_v0.rs` carries the 113-byte layout and the three domain strings; `DAEMON_REDB_STORE.md` §7.1 names the digest's existence and read set, not its bytes. For v1 the hasher cannot be written against a comment: §3.8.1 (new, commit 6's first edit) specifies the per-family leaf encodings, the per-family accumulators, the outer preimage and the domain strings (`shekyl/chain-digest/v1`, `/v1/<family>`), and the KAT's `specification` field cites it. **§3.8.1 carries v0 as well, as a records-was specification** (settled 2026-10-01, ahead of `ARW-Q13`): v0's specification currently retires with `digest_v0.rs`, and the E2 comparator's whole history — every checkpoint in every captured trace, every `digest_identical` in every graded run — is denominated in v0 digests. If the section carried only v1, then when v0 went the record of what those 32 bytes *meant* would go with it. So the v0 half is lifted from the comment and **verified against the code** (the 113-byte preimage, the three domain strings, `PINNED_FIXTURE`), with its era stated in-line; it is a records-was claim that stays true when the function is deleted, not documentation tidiness, and it is cheaper to write in the same edit than to reconstruct from `git log -S` later. *Under `ARW-25` (same day) the v1 half of §3.8.1 became the snapshot's row encodings and record framing — still written before any code, still what the trace's `0x04` record is held to — and the v0 half stands as written; v0 no longer retires at commit 9 but with the walker, which does not change the records-was argument.* |
| **ARW-25** | **At one checkpoint per chain, a hash is the wrong instrument; the archival state travels as rows and the grader diffs** (maintainer, 2026-10-01; premise verified at `trace.rs:22–27`: at most one checkpoint, at the covered tip, because LMDB's spent set is tip-only, RD-F18 — six checkpoints across the corpus, tips 81…1025, traces 8–100 KB). A hash buys one thing: cheap equality across many points. At six points that is nothing, and it costs the thing a comparator exists for — when it disagrees, a digest says *the state differs at height 1025* and a row diff says *persona X's bond record differs in `first_paying_emission_height`*. For an instrument whose job is finding writer defects before the oracle disappears, that is the whole value. The archival state at the six tips is kilobytes. **What it dissolves:** the `digest_v1` hasher, eight domain strings, the 459-byte preimage, the presence-tagged singletons, the accumulator question (`ARW-Q14`, ruled and then moot), and the KAT fixture whose purpose was to pin a hash — because the fixture *is* the rows (`ARW-23`, re-pointed). **What it keeps:** §3.8.1's row encodings, now the serialization both sides emit; the C++ walker as a marshal (emitting rows is a smaller change than folding them); the trace version bump, now falsified by the `0x04` record (*`0x04`: the first draft wrote `0x03`, which `ARW-22` itself records as reserved for Verdict — caught at the code reading, §3.8.1*). **The inheritance, named honestly:** nothing here is inherited code — Monero has no state digest; v0 was minted for this cutover — but the *reflex* is inherited: a 32-byte commitment is how this codebase thinks about state because consensus roots are everywhere in it, and a consensus root and a test comparator have opposite requirements (a root is published, so compact and non-leaking; a comparator is read by one developer once and should leak everything it can). **And it is scaffold with a scheduled end:** the comparator exists to hold redb to LMDB and goes when the C++ goes (§3.9); four hundred lines, a marshal, a KAT and a specification section is permanent-feeling structure for an instrument whose last use is already dated. **Reversion clause (rule 21):** the condition is the cadence, not the choice — if checkpoints ever become per-block (a finer bisect; requires RD-F18 lifted, a spent set reconstructible at a past height), the trade flips and a hash re-enters under `ARW-Q14`'s ruling as recorded. Written into §6 row 6. |
| **ARW-26** | **The two writers key `archival_slash_log` by different heights — found by the capture's own consistency test, two commits before the oracle** (commit 6, 2026-10-01). The `ARW-Q15` capture names the fixture's deadline heights (`shekyl_archival_epoch_slash_deadline_height(E)`), and the test that holds the committed rows to the committed inputs expected epoch 11's slash row at its deadline, `129 999`; the C++ row is at **`130 000`**. Read at both sides: the C++ hooks take `prev_height + 1` — the block **count** after the connect — and fold an epoch at the first count above its deadline, so its row's `h` is the count (`blockchain_db.cpp:689`, `db_lmdb.cpp:5780`); the Rust writer folds on the same comparison (`Transition::count`, commit 4's ruling (1)) but keys the row by the **connecting height** it was handed (`connect.rs:364` → `record_archival_epoch(height, …)` → `write_slashes(height, …)`), one below. The witness `slash_writes_land_at_the_m_epoch_deadline` asserts the slashing *connect* and reads the log through `slash_log_after(p, 0)`; it never asserts the row's height, so nothing had pinned either side. **Not adjudicated here.** Commit 4's ruling (1) binds the schedule comparisons and the close's `close_block_height` to the count; it does not say which height the log row carries, and the A2 reads (`slash_log_after`, `holds_shard_at`) were ported with LMDB as-of-height cases whose heights are counts — so the question has a read-side consequence, not just a key. E2 §0 says a disagreement is adjudicated against the spec and never toward the C++; this one is **commit 8's**, logged now so it is not read off the C++ when the rows disagree. *Disposition in commit 6:* the capture records the C++'s operand as a named input (`schedule.fold_height_operand`, `schedule.slash_log_height_by_epoch`), the Rust test holds the rows to it as the C++'s reading, and the §3.8.1 row for `archival_slash_log` is unchanged — the encoding is not in question, the operand is. *Falsifier for commit 8:* the replayer's `slash_log` row for the same inputs lands at `129 999` or `130 000`; whichever the spec rules, the other side's writer changes, and the capture's `slash_log_height_by_epoch` is re-derived from the ruling, not edited to match. *The class this is the third instance of — index against count, both `u64`, one apart — is posed as `ARW-Q16` with commits 2 and 3 as the other two; commit 8's resolution lands typed at the site it changes under that row's default (a).* *Disposition in commit 8 (2026-10-02) — corrected:* the sentence above saying E2 §0 adjudicates this **against the spec** has nothing to stand on: no spec names the key. `LMDB_SCHEMA.md:681–710` gives the table's shape and its readers; commit 4's ruling (1) binds the *fold* to the count and says nothing of the row; §3.8.1 fixed the encoding. So `ARW-26` is **a new ruling, posed as `ARW-Q17`**, and the capture's role is to say the two sides disagree and exactly how — which the replica (row 8) now does, both equations pinned: same decision, same block (verified at both writers: Rust's `scan_slashes` fires when `Transition::count() > slash_deadline_height(e)`, the C++'s when `prev_height + 1 >` the same — the connecting block of the first count above the deadline), two names for it. The falsifier above is amended to match: whichever name `ARW-Q17` rules, the other writer changes **and** `slash_log_height_by_epoch` is re-derived from the ruling. *Typed (`ARW-Q16` (a)):* `ChainCount::with_tip(tip: BlockHeight) -> Option<ChainCount>` is the missing bridge, with its C9 `compile_fail`; `Transition::count()` returns `ChainCount` and reaches the `u64` schedule edge through `.to_raw()` at three named sites; `record_archival_epoch` / `write_slashes` take `connecting: BlockHeight` — the key is built from a value whose type says which of the two it is, and the grandfather list burned down by two (`172`). *Ruled (2026-10-02):* `ARW-Q17` — the connecting height, `BlockHeight`, coupled to the reader's strict-above predicate; the C++'s count-keyed row is not the other denomination of the same answer but a live off-by-one inside the C++, `ARW-27`. |
| **ARW-27** | **The C++ passes a height into a count-keyed predicate — the slash-log off-by-one is live in the C++, not a denomination difference the capture made visible** (2026-10-02, the check `ARW-Q17`'s ruling asked for). *The three legs, at source:* **writer** — `blockchain_db.cpp:689` `process_archival_slash_at_height(prev_height + 1)`, so `apply_archival_slash_one` keys the row at the post-connect **count**; **reader** — `db_lmdb.cpp:4804` `archival_slash_removed_holding_after` scans from `(at_height + 1, 0)`, strictly above, and `archival_bond_holds_shard_of`'s own comment (`db_lmdb.cpp:4926`) denominates its operand as a **height**: *"a slash **at** `at_height` means already-removed: holdings at `h` are the post-connect state of block `h`"*; **call sites** — both (`blockchain.cpp:4873`, the serve-credit gate; `db_lmdb.cpp:5377`, slash eligibility) pass `h_fire = challenge_fire_height(h_open, h_close, …)`, a block height in `(H_seal, H_close]` (`challenge.rs:171`). So the C++ is **not** count-against-count: its reader was written against a connecting-height key and its writer hands it a count. For a slash applied during the connect of block `H`, `holds_shard_at(H)` sees `H + 1 > H` and answers *held* at the block that removed it — contradicting the reader's own stated semantics, in the C++ alone. *Where it bites, derived:* `slash_deadline_height(e) = last_block(e) + SEB = H_close(e + 1)` (`settlement_schedule.rs:190`), so epoch `e`'s slash connects at exactly epoch `e + 1`'s `H_close` — the top of `e + 1`'s own fire range. A challenge on the slashed `(P, s)` for epoch `e + 1` whose beacon lands on `H_close` (probability `1 / modulus`, `modulus = H_close − H_seal − 1`; of the order of `1 / SEB` per challenge) is answered *held* by the C++ and *not held* by the Rust; the serve-credit gate and the slash-eligibility scan are both consumers. The `ARW-Q15` fixture's epoch-11 row at `deadline + 1` is this defect written down. *Disposition:* the Rust writer (`SlashLogKey.height: BlockHeight`, connecting) and the A2 reads (`above`, strictly) agree with the predicate and stand; **no C++ fix** (rule 20 — a bug fix in C++ is dead code on arrival; the C++ archival writer is a §3.9 deletion target; rule 16's inherited-claim corollary — the capture was true of the C++ and the C++ was wrong). The fixture inputs' `slash_log_height_by_epoch` stays as the record of what the C++ wrote; the replica pins both equations as the record of the disagreement. CHANGELOG carries it as a known defect of the C++ path. *Falsifier for "live":* a C++ call site that passes a count into `archival_bond_holds_shard` — none exists (`rg archival_bond_holds_shard src/` → two sites, both `h_fire`). *Closed by:* §3.9's deletion of the C++ archival writer and readers. |

#### 6.2.2 Questions posed for commit 6 (defaults stated; ruled on the PR)

| Id | Question | Default |
| --- | --- | --- |
| **ARW-Q10** | **How the walker hands a bond record across.** (a) The C++ decodes v7 with its own `ArchivalBondValue::decode` and the FFI carries a flat field struct Rust maps onto `BondRecord`; (b) the FFI carries the raw v7 bytes and Rust gains a v7 decoder. | **(a).** The C++ decoder exists and dies with the walker; a Rust v7 decoder would be new code for a format that has no Rust writer and no future, and rule 20's marshal is "call the decoder the table's owner already has, copy the fields". The v7 corpus test is the belt on the mapping. |
| **ARW-Q11** | **Which `last_slash_epoch` the digest hashes when none has settled.** The C++ cell carries a sentinel for "never"; `ReadSnapshot::last_settled_slash_epoch()` is `Option<SettlementEpoch>` (SAR A9). | **The `Option`'s canonical encoding** (`u8 present ‖ u64`), the walker yielding the C++ sentinel and Rust mapping it to `None` — the digest never sees the sentinel, same as `first_paying_emission_height` 0 ↔ `None` in `ARW-20`. |
| **ARW-Q12** | **How the trace carries the archival state** (`ARW-22`): version bump with a widened `0x02`, or a fourth tag beside the v0 checkpoint. | **Re-ruled 2026-10-01 under `ARW-25`: version bump, `0x02` unchanged, a `0x04` snapshot record** (*`0x04`, corrected the same day from `0x03`, E2's reserved Verdict tag — §3.8.1*). The first ruling (*widened `0x02`*, so that core-or-archival localisation came from which 32-byte half differed) was the right answer to a question the snapshot dissolves: rows localise to family and key, finer than any half. The `0x02` record stays v0's 32 bytes, so every reader of it is untouched; the `0x04` record is the snapshot, exactly one per trace at the covered tip, **required** under `TRACE_VERSION 0x01` and **refused** under `0x00` — the objection to a fourth tag (a trace carrying one without the other) is met by the version requiring both, and the version is falsified by the record's presence rather than by its own byte (§6.2 item 2). |
| **ARW-Q13** | **Where the digest preimage specification lives** (`ARW-24`): §3.8.1 of this document, or a contract document (`CHAIN_DIGEST.md`, LIVING CONTRACT), as `FCMP_SPEND_SIGNING_PREIMAGE.md` is for I17's KAT. *Narrowed 2026-10-01:* §3.8.1 carries **both** v0 and v1 from its first edit (`ARW-24`), so the question is only the section's home, not its content. | **§3.8.1 for commit 6; the contract document is commit 10's decision** (§9). The KAT cites §3.8.1 now; promotion is a `git mv`-shaped move of a section already complete, written at commit 10 if §9 takes it, with the KAT's `specification` field re-pointed in the same commit, or named in FOLLOWUPS with this document as owner if not. |
| **ARW-Q14** | **The per-family accumulator's shape** — the decision §3.8.1 must make before the hasher, and the one that decides *which* defects `ARW-23`'s cardinality catches. (a) v0's shape: `count ‖ XOR of leaf hashes`, leaf = `cSHAKE256(family domain, canonical key ‖ canonical value)` — order-independent by construction (`digest_v0.rs:158`, `spent_accumulator_is_order_independent`); (b) an ordered fold over a canonical key order the specification defines. | **RULED (a), 2026-10-01 (maintainer) — and MOOT the same day under `ARW-25`: no accumulator exists once the snapshot is rows. The ruling and its two preconditions are kept as the record the reversion clause reopens into.** *The ruling:* the digest compares *state*, and a keyed table's state is a set — there is no first persona, so an order the state does not carry does not belong in a hash of it; the decisive argument is what order-dependence *costs*, not what it buys — a legitimate order change (a key type revised, a schema evolution, a redb version with different tie-breaking) would go red in the authority for a non-defect, and a false red in the comparator is worse than a missed divergence that already has its own gate (`schema.rs:547–608` plus `lmdb_order`; one defect, one instrument). *Two preconditions that make XOR sound, written beside the choice rather than relied on silently:* **(i) leaves must be unique by construction** — XOR cancels a duplicate pair to zero; every archival family is `key ‖ Canonical(value)` over unique keys, so distinctness holds *because* of that, and a future family keyed otherwise would inherit the choice without the property; **(ii) the count is load-bearing, not decoration** — with XOR alone an empty family and a family whose leaves cancel are both `0^32`, and the count is what separates them, so `count` is part of the accumulator's soundness and is not to be optimised away. *What the ruling does to multi-row coverage:* re-points it, not retires it — cardinality tests leaf encoding at each count, the §3.6 projection, the cap boundaries and the count's arithmetic, and is not sold as catching an order defect it structurally cannot (`ARW-23`). *The cell's own premise, corrected the same day it was posed:* the first draft of this cell claimed the two sides' iteration orders need not coincide; they do, by construction — every archival table's redb key type is chosen so its `Ord` **is** the LMDB packed-key order (`schema.rs:547–608`, per-table: the `([u8; 32], u64, u64, u64)` tuple "orders component-wise — exactly the packed key's lexicographic order"; `lmdb_order` carries the one order that differs, `compare_hash32`, and no archival table uses it). So (b) needs no sort and no sort-key specification; both sides fold in the order their store already yields. What separates the options is therefore not cost but **which job the digest does.** (b) makes the digest a sequence hash: a walker that iterates one table in a different order than `ReadSnapshot` — the accumulator-ordering defect the maintainer named — goes red in the KAT, and multi-row coverage is what arms it. (a) makes the digest a set hash: that defect cannot register, because the digest does not depend on order; key-order conformance stays the schema's and `lmdb_order`'s job (one mechanism, one job), and a mismatch there surfaces in its own gate rather than as an unexplained digest divergence. Under (a) the multi-row coverage tests the leaf encoding at every cardinality, the count, the §3.6 projection among non-zero rows and the cap boundaries; under (b) it tests those *and* order. v0 chose per family — ordered for the chain (height is the semantics), set-shaped for spent keys (`:20`) — so the precedent supports either for keyed tables. The default stays (a) because the keyed archival tables are sets by meaning (a bond table has no first persona), and a digest that depends on an order the semantics do not carry fails on a storage fact. |
| **ARW-Q15** | **Whether the LMDB unit fixture's archival state is captured as rows before the walker goes** — the half of `ARW-23` that `ARW-25` did not re-point. The six corpus traces commit the C++ reading of every family the corpus *reaches*; no captured chain has a slash, a release, a reinstate or a serve-credit transaction (§2.4), so for `slash_log`, `slash_applied`, `last_slash_epoch`, `serve_credit` and the `Release`/`Reinstate` arms of `bond`, the only C++ reading that will ever exist is over `archival_substrate_lmdb.cpp`'s fixture state, and it cannot be made after commit 9. Capture it (the walker's row emission run inside that fixture, written to a committed JSON beside the scenario driver, with the fixture's **inputs** — the events the C++ appliers were driven with — recorded alongside the rows, since rows without inputs cannot be reproduced on the Rust side); or do not, and commit 8's stamp over those families compares the Rust writer against the Rust writer. | **RULED 2026-10-01 (maintainer): capture, in commit 6, inputs and rows; consumer named: commit 8's scenario driver** (STAGED, rule 23 — the consumer is in this PR's plan, not a future one). *The replayer already exists:* commit 5's `slash_writes_land_at_the_m_epoch_deadline` drives the Rust writer to slash state through blocks — four personas, landing at the deadline — so the question is not whether the Rust side can reach slash state but whether the two sides can be driven to the **same** state, a construction problem with a known shape. *One condition on the capture:* the inputs are recorded in a form that **names what the Rust side must reproduce** — personas, bond amounts, miss sequences, the deadline height, the settlement schedule — not as whatever the C++ fixture happened to pass; rows alone would make any red ambiguous between a writer defect and differently-seeded inputs, and the natural response to an ambiguous red is to adjust the inputs until it goes green, which is the failure this round exists to avoid. The condition and the risk are the same question: a fixture whose inputs are named is replayable by construction; one whose inputs are implicit is not replayable at all. *If commit 8 nonetheless finds no constructed path to the fixture's state,* the fixture is deleted — and the finding is recorded as **the C++ slash and close rows are unreachable in Rust by any constructed path**, a far more serious claim than a wasted capture, to be read as one. The cost is a capture mode on a walker that already emits rows. *Read at the fixture before the capture was built (2026-10-01):* `archival_substrate_lmdb.cpp`'s slash KATs seed their bonds with `put_archival_bond_value` **directly** — `hybrid_pubkey = {0x0A}`, no `bond_spend_pk`, a zero endpoint, `shard_add_epochs` set by hand — not through a JoinMarket connect, so the fixture's `bond` rows carry identity fields **no admitted transaction can produce** and the Rust writer, which only writes a bond the validator admitted, cannot reproduce them byte for byte however the inputs are named. The capture therefore records, per `bond` row, which fields are *fixture-seeded identity* (`hybrid_pubkey`, `bond_spend_pk`, `endpoint`) and which are *state the appliers wrote* (`bonded_total`, `holdings`, `bad_intervals`, `join_settlement_epoch`); commit 8's comparison is over the second set for `bond`, and whole-row for `slash_log`, `slash_applied` and `last_slash_epoch`, which carry no identity. A red on the first set is not a finding; a red on the second is. The fixture's schedule is the genesis `SEB 10 000` (the unit test arms no lever), so the capture names it, and the Rust replay runs under the same pair or states its own and maps the deadline heights. *Held against the slash-capture decision in §6.2 item 5:* that item holds a slash-bearing **corpus** capture for commit 8's stamp to decide; this is the **fixture** capture, cheaper by six generator runs, and does not pre-empt it. *Consumed (commit 8, 2026-10-02):* **a constructed path exists**, so the deletion clause does not fire and the fixture stays. `archival_fixture_replica_tests` reaches the fixture's state through the production stack — two bond posts, eleven injected passes, blocks to one past epoch 11's deadline — under a levered `SEB 100` (the Rust replay *states its own pair and maps the deadline heights*, as this ruling allowed), 76 s in the default lane. The comparison is as ruled: `bond` over the state fields (`bonded_total` as the *burn*, since the seeded two-floor total and the join's pinned floor differ by construction), whole-row through a persona map for `slash_log`, `slash_applied` and `last_slash_epoch`; the identity fields are asserted *different* (seeded bytes there, derived keys here), not skipped. Every state field compares equal; **the one red is on the second set and is `ARW-26` exactly** — the slash-log key, posed as `ARW-Q17`. One more by-construction difference the pre-read did not name: the C++ wrote its eleven passes at height 1 000, the injector attributes to the tip it writes at, so the credit keys compare on `(persona, shard, epoch)` with each side's height held constant. |
| **ARW-Q16** | **Whose work is typing the archival surface's block axis — E4's, a height-semantics slice's, or nobody's because the cutover absorbs it?** Posed 2026-10-01 (maintainer, on `ARW-26`), with three instances as the evidence, because any one of them reads as an ordinary off-by-one and the argument is only persuasive with all three. *The class:* a block **index** and a block **count** are both `u64` and differ by one everywhere they meet — `m_db->height()` is a count, `connecting` is an index, and nothing in the signature has an opinion. *The instances, each found by a test and not by a reader:* (1) **commit 2** — `shekyl_archival_epoch_close_height(E)` `= (E+1)·SEB − 1` against `consensus_state::epoch_close_height(E)` `= (E+1)·SEB` (§10, 2026-09-30; ruled *rename, do not document* → `last_block`); (2) **commit 3** — `cumulative_tx_count` against storage ids, the coinbase term (`storage_ids_through`, §3.7 — the same slip S-PRUNE had corrected four days earlier, rule 05 §*A formula two lanes need is a function*); (3) **commit 6** — the slash-log key, connecting height against post-connect count (`ARW-26`). *Read at the tree before posing (2026-10-01), which sharpens the question:* **the type pair already exists** — `shekyl_types::{BlockHeight, ChainCount, BlockCount}` (`block_axis.rs`: instant/span algebra, mixing does not compile, named bridges `tip` / `next_height` / `from_next_height` / `has_block`), under a ratified contract, `HEIGHT_SEMANTICS.md` §3.1 **C2** (inland Rust never carries a block-axis quantity as a bare `u64`), **C3**, **C7** (never a bare identifier `height`), **C9** (a `compile_fail` per conversion boundary). The archival surface violates all three: `SettlementSchedule` is thirty-one `u64` height parameters (`last_block(epoch: u64) -> u64`, `slash_deadline_height`, `close_due_at_height(block_height: u64)`), `storage_ids_through(listed: u64, height: u64)`, `Transition::count() -> u64`, `record_archival_epoch(height: u64)` / `write_slashes(height: u64)` — the last two written in commit 5, in this lane, against C7 by name. The campaign's census (`HEIGHT_SEMANTICS.md` §2–§3.3) walked the **wallet side** and the daemon-admission reads; `SettlementSchedule`, `shekyl-chain-store` and `shekyl-chain-rules` appear in it nowhere, and Phase 2e's *"C2-complete inland remainder"* (2026-09-21) is true of that census and false of the tree — the DRS lanes have been minting C2 violations in the daemon store since four days after C2 was ruled, with no gate to say so (`scripts/ci` has no height check; C2 is review-borne, and a review-borne rule whose campaign reads *complete* is one nobody re-checks). **Commit 4's ruling (1) predicted this class** — *"the boundary the two close heights sat on is exactly where a `height`/`count` slip would hide"* — and defended it with a **name**: `Transition::count()`. The slip happened anyway, one crate over, where the name is not visible and `height: u64` arrived. A name defends the crate it is in; a type defends the call. That is the rule-05 remedy that worked twice here (`storage_ids_through` made the coinbase term unwritable; `last_block` made the close reading explicit) stated generally, and the tree already has it — what is missing is its application to this surface and **one bridge**: the count of a chain whose *tip* is `h` (`ChainCount::from_next_height(h) + ONE`, the `ARW-26` quantity, `prev_height + 1`) has no name on `ChainCount`; `tip()` is its inverse. *Not absorbed by the cutover:* the count operand is **the spec's**, not the template's — commit 4 (1) ruled every schedule comparison against it and `close_due_at_height(count)` is consensus — so when the C++ goes the count stays, and a type that cannot say *count* here is a type that cannot say the rule. **Default, posed for ruling:** (a) **E4 does, in its remaining commits, what its own sites require and no more** — commit 8's `ARW-26` resolution lands **typed at the site it changes** (whichever quantity the spec rules the log key is, `write_slashes` / `record_archival_epoch` take it as that type, `Transition::count()` returns `ChainCount` through the new named bridge with its C9 `compile_fail`, and the key is built from the typed value, so the ruling is in the signature rather than beside it); commits 7 and 9 write no new bare-`u64` height inland (C2/C7). (b) **The surface-wide retype is a height-semantics slice, not E4's** — `SettlementSchedule`'s thirty-one signatures, `storage_ids_through`, the chain-rules archival module and the store's archival reads/writes become `BlockHeight` / `ChainCount` / `BlockCount` inland with the `shekyl_archival_epoch_*` FFI free functions decoding at the edge (C1/C8), C9 pins on each boundary, **no numeric change**; filed as `HEIGHT_SEMANTICS.md` §3.5 **Phase 2g**, because that document owns the contract and the census this surface fell outside of, and a cross-crate retype is its own validation surface (rule 19) — folding it into commit 8 would bundle a 40-signature retype with the adjudication it exists to make legible. (c) **The gate** the campaign lacks — an inland bare-`u64` height check with an exact-hit, shrink-only allowlist, the `check_test_only_features.py` shape — is Phase 2g's first deliverable, not its last, so the slice cannot be declared complete over a census again. *Falsifier for the posing itself:* a fourth instance before Phase 2g lands. *Reopening (rule 21):* if Phase 2g is ruled not worth its cost, the three instances and the count operand being consensus are the record of what was declined, and the next one is adjudicated against this row. | **RULED 2026-10-01 (maintainer): (a) and (b) as posed; (c) sharpened — the gate lands *now*, in E4, grandfathered at the enumerated sites, not as Phase 2g's first deliverable.** Two reasons given: *a gate that can't pass can't land*, so "first deliverable of a slice that retypes forty signatures" arrives last in practice; and the gate's value is not finding the forty — the filing enumerated them — but preventing the forty-first, which is live while commits 7–10 are written. That converts (a) from a discipline into a mechanism: "commits 7/9 write no new bare height" is held by CI, not memory, and the record list burns down as Phase 2g proceeds (the `check_test_only_features.py` grandfather / `DEFERRED_DOCS` shape, both landed red-proof and both burning down since). **Landed 2026-10-01** between commits 6 and 7: `scripts/ci/check_inland_height_u64.py` + `inland_height_u64_grandfather.txt`, 174 exact-hit records over the five Phase 2g crates (`shekyl-archival-retention`, `shekyl-chain-ingest`, `shekyl-chain-rules`, `shekyl-chain-store`, `shekyl-types`; tests included), `GRANDFATHER_CEILING` that only lowers, `--selftest` on every hit shape and failure class (rule 47), wired in `grep-gates.yml`; red-proofed on the live tree by planting `fn _planted(height: u64)` in a scoped crate. Stated non-coverage, so silence is not read as coverage: count-named operands (`Transition::count()`), heights under other names (`h_open`, `tip`), and the rest of the tree (488 sites tree-wide; widening is Phase 2g's call). |
| **ARW-Q17** | **Which height names a slash-log row — the connecting height of the block whose processing decided it, or the chain count after that block connects?** Posed 2026-10-02 (commit 8), from `ARW-26`. **This is a new ruling, not an adjudication.** Nothing specifies the key: `LMDB_SCHEMA.md:681–710` is the table's shape and readers, commit 4's ruling (1) binds the *fold* to the count and not the row, §3.8.1 fixed the encoding. The `ARW-Q15` capture is evidence of what the C++ *does* — keys epoch 11's row at `130 000`, the fold count — and the replica (row 8) is evidence of what the Rust writer does — `129 999`, the connecting height; adjudicating toward either makes that writer the authority on a point nothing establishes it is right about. Both writers decide the slash on the **same block** (verified at both: the connecting block of the first count above the deadline); the disagreement is only the name the row carries. *Position, stated as one:* a slash-log row records a slash decided during the processing of some block; the height that names that block is its **connecting height**; the post-connect count `h + 1` names a block that does not exist at decision time. Under that reading the Rust writer is right and the C++ key is an artifact of `m_db->height()` being a count — the `ARW-Q16` class once more, read off the template. **The read-side consequence, attached because it is where the ruling bites:** the A2 reads were ported with LMDB as-of-height cases whose heights are counts. `slash_log_after(p, h)` returns rows **strictly above** `h` (`SlashLogKey::above` — `(h + 1, 0)..`), and `holds_shard_at(p, s, h)` answers *held at `h`* as *yes iff a logged slash strictly above `h` removed it*; production passes `h_fire`, the challenge's fire height, strictly below the connecting block. So for a slash decided during block `c`: keyed by the connecting height it is **invisible** to `holds_shard_at(c)` (`c` is not above `c`) and the persona reads as *not holding at `c`*; keyed by the count it is **visible** and the persona reads as *holding at `c`*. The question is therefore also *does a persona slashed during block `c` hold at `c`* — and whichever way it is ruled, the A2 reads' as-of cases are re-read against the ruling, not left as the C++'s. *Default:* the connecting height, as the Rust writer has it; the capture's `slash_log_height_by_epoch` is then re-derived (`deadline`, not `deadline + 1`) and the C++ writer changes in the port's remaining life or is deleted with it (§3.9). *What is pinned until the ruling:* both equations, by the replica test; either writer moving is a red. *Reopening (rule 21):* a consumer of the row's height emerges whose contract needs the count — an as-of read whose spec says *including the block that slashed*. **RULED 2026-10-02 (maintainer), same day — and the basis is sharper than the position above.** The log is neither a per-epoch boolean nor pending-state tracking; it is **the pre-image for the as-of-height fold** (`shekyl-types/src/archival/slash.rs`, `SlashedHolding`: "what one slash took from a record's holdings — the pre-image the as-of-height fold needs"), kept only because `held_shard_ids` is current state and cannot answer tenure questions about the past; the m-of-n decision is the scheduler's, over observations — the log records the effect on holdings. So it answers exactly one question — *for a shard this record does not hold now, did it hold it at `h`?* — and the doc states the predicate: **yes iff a logged slash strictly above `h` removed it.** That settles the key arithmetically. A slash decided during the connect of block `H`: keyed `H`, `holds_shard_at(H)` is `H > H` = false — not held at `H`, where the slash applied, correct; keyed `H + 1`, it is `H + 1 > H` = true — held at the very height the slash removed it, off by one at the boundary. **The strict-above predicate and the connecting-height key are coupled; neither moves without the other.** That is the adjudication's real content, and what it adjudicates on is not the corpus (no slash), not the spec (silent), not the capture alone (the C++'s answer) — it is this doc comment's predicate plus the typed axis: a derivation from what the table is *for*. The ruling is therefore **denominational**: Shekyl's slash log is written in **`BlockHeight`** — the connecting height — and `SlashLogKey.height: BlockHeight` with the strictness stated beside it (`ids.rs`) ends the question for the table, not for this row; `ARW-Q16`'s axis exists so this is answered once rather than at forty sites. *Checked before ruling, as asked — is the C++ consistent inside itself (count against count), or is the off-by-one live there?* **Live. See `ARW-27`.** The capture's rows are a defect the Rust does not inherit, not a clean denomination difference. *Consequences:* the Rust writer and the A2 reads stand as ported — their as-of cases are height-denominated end to end and agree with the predicate; the capture's `slash_log_height_by_epoch` is the C++'s and stays as the record of what the C++ wrote, with the replica pinning both equations as the record of the disagreement; the C++ writer is not changed (rule 20: no C++ bug fix; §3.9 deletion target). The reopening clause above stands unchanged. | **RULED 2026-10-02 — `BlockHeight`, the connecting height, coupled to the strict-above predicate; the C++ key is `ARW-27`'s defect.** |
| **ARW-Q18** | **Whether a slash-bearing corpus capture is owed before genesis, now that the stamp has reported.** Posed 2026-10-02 (commit 8), §6.2 item 5's decision point. *The red, as pre-declared and as measured:* zero `slash_log` / `slash_applied` rows on all six captured chains (`ARW-13`); the `SlashLog` gate's stub is noticed only through the `last_slash_epoch` watermark cell on `emission-claim`; the slash **rows** have no corpus witness at all. *What exists instead:* the `ARW-Q15` replica (row 8) — the fixture's slash reached by construction on the Rust stack and compared row-for-row against the one C++ slash ever written under test, with the key disagreement pinned (`ARW-Q17`). That is evidence of the writer's output against the C++'s; it is **not** the Rust slash writer exercised under the corpus oracle on a chain the C++ walker exported. *What a seventh capture would add:* a slash on a captured chain — `SEB 100`, ~1 300 blocks, the generator run row 8's 2026-09-30 update costed — and with it the driver question that update named: eleven consecutive epochs whose observations settle as misses 2-of-3, which the B9 chain reaches by absence and a populated capture would need the scenario driver to produce. *Default:* **not before genesis as a corpus capture** — the replica discharges the writer-against-C++ comparison the capture was for, the C++ writer is a deletion target (§3.9), and a seventh chain would witness the Rust writer against a template that is leaving; the driver capability (settled-miss epochs) is owed on its own merits if a consumer names it, not as this capture's by-product. *Falsifier for the default:* a slash-writer defect the replica's role map cannot see — one that depends on the walker's export of a live chain rather than on the rows — found by any other means. *Reopening (rule 21):* `ARW-Q17` ruled toward the count, which changes the Rust writer and leaves the replica as the only test of the changed site; then a corpus witness is the cheaper of the two ways to re-pin it. *UPDATE 2026-10-02:* `ARW-Q17` was ruled toward the **connecting height** — the reopening criterion did not fire, the Rust writer does not change, and the default stands as stated. Still the maintainer's to take or refuse. **RULED 2026-10-02 (maintainer): the default taken — no corpus capture — and the one gap it would have closed, closed with a cheaper test.** *Why the default holds:* the replica discharges the writer-versus-C++ comparison and is the only instrument that reaches the slash family at all; a seventh chain would be captured from a generator that is leaving (`DEL-008`), so its oracle expires at the cutover; and `ARW-Q17` already extracted the denomination evidence, with `ARW-27` recording the C++'s live off-by-one as the residue. *What a slash-bearing chain would genuinely have added — and it is not writer coverage:* `slash_writes_land_at_the_m_epoch_deadline` already drives four personas through the real store to the slashing connect, and connect is the same code whether blocks arrive from a trace or from the driver. It is the **`0x04` snapshot's slash-family encoding exercised at non-empty**: every captured chain carries those families empty, so the row-diff instrument had never serialized a slash row from a writer's state — an encoding tested only in its degenerate case and in a writer-reader round trip a symmetric change passes, the shape that has bitten this program repeatedly. *And it does not need a chain:* the driven slash test already builds exactly that state. The witness now calls `archival_snapshot()` at its tip and pins the body — the three slash families' bytes **spelled from the facts** (`n_rows ‖ (len ‖ height ‖ seq ‖ persona ‖ shard ‖ epoch ‖ 0x01)*`, the `slash_applied` members, the watermark), located by the test's own walk of the record framing, and the whole 17 536-byte, 39-row body by cSHAKE — against state produced by the production writer, in a test that already runs (`slash_scan_bench_tests.rs`, `assert_snapshot_pins_the_slash_families`). Same coverage, no generator run, no chain captured against a departing template, nothing that expires at the cutover. The pin also witnesses `ARW-Q17` in the record: the log rows sit at the connecting height, `1 299`. *Recorded this way rather than as a bare refusal* because "we decided not to" and "we found the cheaper instrument" read differently to whoever reopens it. *Reopening (rule 21):* unchanged in substance — a slash-writer defect the pin's state cannot see, one that depends on a live chain's export rather than on the rows, found by any other means; the stamp's census still names the slash families as its declared red, now with the pin beside it. | **RULED 2026-10-02 — refused; the gap discharged by the `0x04` slash-family pin in the slash witness.** |
| **ARW-Q19** | **The slash log's key and its horizon — two questions in one row, because the second may decide the first.** Posed 2026-10-02 (maintainer's framing, after `ARW-Q17`), for a **short round after PR-b** — not commit 8, which rules the denomination and lands the oracle (rule 19: a key change and a retention floor are a different validation surface from the oracle's; the same reasoning that sent the forty-signature retype to its own slice, `ARW-Q16`). Cheap because nothing has shipped and the writer has exactly one caller (`write_slashes`, `archival_write.rs`). **(1) The index.** `archival_slash_log[(height, seq)]` is keyed by *when*; its one production reader asks *did `P` hold `s` at `h`* (`slash.rs:225` → `holds_shard_at`), and the read is one range from `(h + 1, 0)` over **every persona's** slashes, filtered to `P` in `slash_log_after` (`archival_reads.rs:138`, as its own doc says) and to `s` inside the fold. Keyed by its query — `(PersonaId, ShardId, BlockHeight)` — the read is a prefix range: seek to `(p, s, h + 1)`, walk forward; redb carries the tuple natively, as `(TreeLayer, ChunkIndex)`, `(u8, u64)` and `ServeCreditKey` already do. Strict-above then reads off the range and the denomination lands at one site, which makes `ARW-26` smaller. *Three facts the query shape hides, each for the round to rule:* **(a)** `SlashedHolding::CompleteTree` proves `P` held **every** shard while the row names the one challenged — a `(p, s, ·)` range sees only slashes challenged on `s`, so the complete-tree arm needs a second seek (a sentinel shard, or the key is `(p, h)` with the shard filtered as now); **(b)** `(p, s, h)` is not unique — one deadline scan settles several epochs' misses on one pair at one connecting height, which is what `seq` disambiguates today (`archival_slash_applied` is keyed `(p, s, E)`; the key would need `E` or keep `seq`); **(c)** the key is in the v1 digest preimage (§3.8.1: `u64 height ‖ u32 seq ‖ Canonical(SlashLogEntry)`) and in SI-22's *dense per height* invariant, so the re-key is a layout bump, a digest bump and an invariant restated — all pre-genesis, none free. **(2) The horizon — not an optimisation, and not new.** Both readers reach back a bounded distance: the fold is asked at `h_fire ∈ (H_seal, H_close]` and the scan asks at its own deadline, so the deepest row any consensus read reaches is **F19's** `tip − ((k + n)·SEB + D_max)` — `k = SLASH_GRACE_EPOCHS = 1`, `n = FAILURE_WINDOW_N = 13` — **not** `tip − (W + 1)·SEB`: `MAX_CLAIM_AGE_W_EPOCHS` bounds the claim set, which does not read the slash log. Rows below are unreadable by construction, and the log is stored as if they were not — append-only, kept forever by every validating node, the unbounded-state-bounded-purpose shape S-PRUNE removed from the body corpus. **The record already rules this and names its owner:** `PDM-Q-F16` graded the seven journals `LOCAL-BOUNDED` and `PDM-Q-F19` proved the bound emergent, not enforced (`ARCHIVAL_PRUNED_DAEMON_MODE_ROUND.md`); S-PRUNE **built** the expression as `shekyl_chain_rules::journal_horizon(tip) -> Option<BlockHeight>` beside `D_MAX` (`reorg.rs:96`, 2026-09-25) and re-homed the *retirement site* — where the horizon is asserted and rows below it retired — to **S-ARCH**, *"when those writers land"* (`DRS_E1_SPRUNE.md` §3, §12; FOLLOWUPS *Journal horizon asserted at the journals' retirement site*). **Commit 8 landed the writer, so that condition fired in this lane** (rule 22: a fired condition reads exactly like a pending one). The six other F16 journals dissolved into `undo_log` (`ARW-Q2`), which S-PRUNE already retires at `tip − D_max`; the slash log is the **only** F16 journal left with a retirement to build, and this plan did not carry it. So the horizon's owner is this surface, the function is S-PRUNE's (one home, never a literal — `05-system-thinking` §"a formula two lanes need is a function"), and the deadline is genesis: retirement is node-local, so adding it later is not itself a hard fork — but a reader added later that reaches **below** the horizon would be one, and the assertion at the retirement site is what turns F19's emergent bound into a contract. **Why one row:** retirement is a range deletion `..(horizon, 0)` under the height-led key and a full scan under a persona-led one; the query is a prefix range under the persona-led key and a filtered scan under the height-led one. With the horizon enforced the table is small either way — slashes are events, F19's window is `14·SEB + D_max` blocks — so neither scan is the argument; the argument is **which read the key's shape makes unspellable-wrong**: strict-above and the denomination (the query), or the retirement boundary (the horizon). A table with a retention floor may want the height leading after all. *Coupling to the oracle:* the C++ walker exports the whole log and the redb snapshot walks the whole table (`archival_reads.rs:489`), so a retiring node's `slash_log` family diverges from a non-retiring one's once a chain outgrows the window — the six corpus chains (~1 300 blocks at `SEB 100`) do not, and the C++ is a deletion target (§3.9), so the oracle's comparison is unaffected before the C++ goes; the round states which snapshot the digest covers after it. **Default for the round, not taken here:** the horizon first — assert `journal_horizon` at `write_slashes`' batch and retire below it in the same batch S-PRUNE's body discard runs in; then the key, chosen for the two reads that remain. *Falsifiers:* for (1), `rg 'entry.persona == \*persona' rust/shekyl-chain-store/src/store/archival_reads.rs` still matching after the round rules the re-key; for (2), FOLLOWUPS' journal-horizon row still open after the round, or `rg 'ARCHIVAL_SLASH_LOG' rust/shekyl-chain-store/src/store/prune.rs` returning nothing while a `journal_horizon` caller exists. | **RE-HOMED 2026-10-02 (commit 10) → [`DRS_E4_SLASH_LOG_ROUND.md`](../design/DRS_E4_SLASH_LOG_ROUND.md) `SLK-Q1` (the horizon) and `SLK-Q2` (the key), both POSED there, neither ruled here.** The row above is the record of the posing; the round owns the question and the FOLLOWUPS journal-horizon row from its start. *Was:* POSED 2026-10-02 — for a short round after PR-b; carries the fired FOLLOWUPS condition (the slash log's retirement site is E4's). |

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
| E2's S-ARCH bar (SAR-11) | *(re-pointed 2026-10-01, `ARW-25`: was "`digest_v1` present; each checkpoint at v1")* `rg 'fn archival_snapshot' rust/shekyl-chain-store/src` → present; each vector's trace carries exactly one `0x04` record under `TRACE_VERSION 0x01`; the sufficiency test red for each **exercised** family, with rule 47's half first — every retained writable family names a witness through an exhaustive `match` over `ArchivalFamily` (falsify by adding a variant to the X-macro: the test must fail to compile, not pass; `cargo test -p shekyl-chain-ingest stubbed_family_reddens`; §3.8 item 2) |
| The injected credit modelled | `rg 'Inject' rust/shekyl-chain-ingest/src/source.rs` → a variant; `emission-claim`'s trace carries one; **the manifest half HOLDS 2026-09-29**: `rg out_of_band_writes rust/shekyl-chain-ingest/tests/vectors/*/manifest.json` → six hits, one non-empty, and `vectors_tests::only_the_named_chains_carry_out_of_band_writes` green |
| `SAR-Q7`'s staged pair | `rg 'fn slash_log_after' rust/shekyl-chain-store/src/store/archival_reads.rs` → present |
| The daemon-uniformity sentence (FOLLOWUPS `:176`) | `rg -n 'no archival serving state' docs/design/DAEMON_REDB_STORE.md` → hits — **HOLDS 2026-09-29** (written by this PR) |
| One shard definition on `dev` | `rg 'leaves_per_segment\|SEGMENT_LAYER_J\|frozen_segment_count' rust/shekyl-chain-rules rust/shekyl-chain-store rust/shekyl-archival-retention/src` → nothing on the consensus side |

Denominator at the pin: `cargo test -p shekyl-chain-store --lib` 375,
`-p shekyl-chain-rules --lib` 262, `-p shekyl-chain-ingest` 89,
`-p shekyl-archival-retention` (unchanged in count — commit 9 did not
delete the pop folds' tests; the folds stay until the cutover, §3.9's
corrected timing); `check_redb_schema_bijection.py` /
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
conformance run with the archival snapshot compared (commit 8; was
"`digest_v1` on" — `ARW-25`).

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
the trace's `0x04` snapshot record and `TRACE_VERSION 0x01` — was
"`digest_v1`", `ARW-25`); this file's banner → LANDED, staying in `design/` while slice
8 cites §2.3 and §3.1.

**Discharged 2026-10-02 (commit 10), item by item against the list above
— each read at the tree, not from this list.** `DAEMON_REDB_STORE.md`: the
two `[E4 hook]` texts are gone from §7 and from `store/connect.rs` (commit
5); the S-ARCH row's write half → LANDED (commit 10c); §7.5 table 2 is a
*schedule* view ("the increment each arrives with") that no landed lane has
flipped — E1's and E3's rows read the same as E4's — so its E4 rows are left
as the schedule and the arrival is recorded on the S-ARCH row, where status
lives; the lane graph's E4 node is the S-ARCH row; §7.1.1 DISCHARGED (commit
6). `DRS_E1_SARCH.md` → `docs/completed/` (commit 10c, its own condition
met). `STORE_INVARIANT_REGISTER.md`: SI-19…23 landed (commit 5a); SI-15 carries
its writer-side UPDATE (commit 4: the validator's refusal is the first
check, SI-15 the belt); **SI-6 was not restated** — this item was written
before `ARW-Q2` ruled, and with five journals dissolved into `undo_log` the
rows they would have added are entries SI-6 already governs. `CONSENSUS_RULE_CENSUS.md`:
L7 / L8 / L9 carry their as-built Rust notes (commit 4, 2026-09-30); L16
gains its as-built note at commit 10c (the port landed, `holds_shard_at` in
`shekyl-archival-retention`); L14's four sites are C2-R8b's to name, not
this increment's; **CEN-L10 → bucket 3 is at the cutover, by design**, and
is now one row of §12.1's cutover-day list rather than a sentence here;
`ARW-3`'s two siblings are `SAR-Q7`'s sweep-subject question, folded as
that row ruled. `CONSENSUS_STORE_RECONCILIATION.md`: the L rows' verdicts
hold their as-built text (L16 names `holds_shard_at`'s signature and the
LMDB cases it reproduces). `CHAIN_RULES_CRATE.md`: `ArchivalDelta` on the
verdict is recorded (three mentions). `LMDB_WRITE_ATOMICITY_AUDIT.md` §10:
done in commit 6 as ruled. `ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md` → archives
**at the cutover**, with `DEL-008` (commit 9 found the Rust freeze half is
the live pipeline's, not dead), so it is a §12.1 row, not this commit's
move. FOLLOWUPS: `:176`, `:157`, `SAR-Q7`'s staged row and the `:727`
narrowing are gone from the file (removed as resolved, rule 95 — not found
by content 2026-10-02); `:153` (the reorg-depth split) is owned by
`ARCHIVAL_SHARD_FETCH.md` `SF-D8` as disclosed in §2.2; `:161`'s owner
names this document — repointed to `completed/` at 10c (Phase 2g's slice is
`HEIGHT_SEMANTICS.md` §3.5's). `IMPLEMENTATION_INDEX.md`: `ARW-`, `ARW-Q`,
this document's row and `DRS_E1_SARCH.md`'s → archived; `SLK-` / `SLK-Q`
registered with the new round. `CHANGELOG.md`: each commit's entry landed
with its commit; 10c adds one Unreleased line. **This file's banner →
CLOSED-as-record, not LANDED-in-`design/`:** the "staying while slice 8
cites §2.3 and §3.1" clause is void — slice 8's doc
(`ARCHIVAL_SHARD_FETCH.md`) cites neither section, and the maintainer's
ruling is that a document kept live for one open question becomes the place
that question hides. `ARW-Q19` goes to the round that owns it.

---

## 10. Decision log

| Date | Entry |
| --- | --- |
| 2026-10-02 | **Commit 13 (PR #937 review) — `ArchivalSnapshot::insert` holds the row bound the codec relied on.** The review found `write_body` asserting *"a row was bounded by `MAX_ROW_BYTES` at insert"* over an `insert` that bounded nothing: it checked key width, fixed value width, duplicates and singletons, and let a variable-width family (`Bond`, `AttestationWitness`, `SlashLog`) take a row of any length. A snapshot was therefore constructible that `write_body` emitted and `read_body` refused as `RowTooLong` — the writer and the reader of one codec disagreeing on the type's own invariant — and at `u32::MAX + 1` bytes the `expect` was a panic in a writer. No producer reaches it — the store's reader and the C++ walker's FFI pushers both build rows through the typed `push_*` constructors, each of which bounds what it encodes (`BondRecord`'s caps, `WitnessShape` at `MAX_ATTESTATION_WITNESS_BYTES`, fixed-width slash entries) — so this was a hole in the type, not a live fault; it is closed in the type: `insert` refuses `key.len() + value.len() > MAX_ROW_BYTES` with the same `RowTooLong` the reader raises, the constant's doc now states it is held at both ends, a `const` assertion pins `MAX_ROW_BYTES <= u32::MAX` so the length conversion is total by construction, and a test takes a row one byte over (refused, no residue) and one at the bound (round-trips). The store's `archival_reads.rs` already mapped `RowTooLong` through `refused(...)`, so no caller changed. Same commit, from the same review: three C++ comments cited the E4 record as `docs/design/…` after it moved to `docs/completed/`; they now cite the basename, as the other sixty sites do and as `check_doc_code_citations.py` resolves — a path survives archival only when it carries no directory. And the inland-height gate's docstring and `HEIGHT_SEMANTICS.md` §3.5 gain a stated blind side: a grandfathered line moved within its file with its text intact is invisible to a `(path, text, count)` record, by choice — a line-numbered record would be invalidated by every unrelated edit above it — so the touched-site law is review-borne for that case. |
| 2026-10-02 | **Commit 12 (PR #937, the merge with `dev`) — `ShardClose::ClosedAt` and `shard_age_milli` take `BlockHeight`; the inland-height gate's first red on a merged tree, typed rather than recorded.** The merge of `dev` (`b9a793a03e`) into this branch brought SHT-Q2's close operand (`shekyl-archival-retention/src/consensus_state.rs`, `dev` commits `9c91407bba` / `a9d8123a64`): `ShardClose::ClosedAt(u64)`, `age_milli(self, at_height: u64, …)`, and `shard_age_milli` re-parametered from `freeze_height` to `shard_close_height`. Each side was green alone; together, `check_inland_height_u64.py` — which exists only on this branch — reported six findings: two grandfathered records whose text had moved out from under them and four bare-`u64` heights no record covers. That is the semantic conflict rule 06's merge queue exists to catch, and the gate's law decides its disposition: a touched site is typed, a new site is typed, neither is recorded. So the operand is `ClosedAt(BlockHeight)`; `shard_age_milli(close_block_height, shard_close_height: BlockHeight, …)` subtracts on the axis (`checked_sub → Option<BlockCount>`, the after-close case `None` → zero age, no wrap); `age_milli(judged_at: BlockHeight, …)`; `ShardCloseWire::closed(closed_at: BlockHeight)` encodes and `from_wire` decodes, the wire field itself staying the grandfathered bare `u64` it is (C1/C8). The callers that held a bare `u64` decode once at their edge — `admission.rs`'s `parent_height`, `shard_coverage.rs`'s `tip_height` and rows, `bond_duration.rs`'s epoch close — and `chain-rules`' `close.rs` **loses a `.to_raw()`**: `shard_close_height()` already returned `BlockHeight`, and the call was unwrapping it to feed a `u64` parameter — the exact *name defends the crate, not the call* shape `ARW-Q16` was ruled on, one crate boundary over. Records deleted: 2 (`fn shard(…, freeze_height: u64)`, `freeze_height: u64,`); one record's count 4 → 3; ceiling 170 → 167, list at 167. |
| 2026-10-02 | **Commit 11 (PR #937 review) — the checkpoint is read once, after the run's last committed event.** The review found the pipeline comparing the covered-tip checkpoint inside `apply_ready`, at the checkpoint block's connect — before a same-tip `Inject` barrier committed. The corpus law files an `inject` at the tip (`InjectNotAtTip`), so a chain whose last event is an injection at the covered tip would grade `DIVERGE` on a faithful replay, the credit `only_theirs`. No captured chain has that shape (`emission-claim`'s injection is at 115 under a tip of 1025; the other five carry none), which is why the oracle stayed green; the reproduction was run — the new test under the old placement fails exactly so. Disposition: not the reviewer's "refresh after an injection" (a second read at a second moment, which is the hazard's shape kept), but the walker's — one connector message, `CheckpointState`, one redb read snapshot answering `TipEncodings { tip, digest, archival }`, asked once by `run_loop` after the loop drains; compared only when that read's `tip` is the checkpoint height, else both report fields `None`. The scenario driver keeps `ArchivalState`; rewind's `Switch` keeps `Digest`. Pinned by `an_inject_at_the_covered_tip_commits_before_the_checkpoint_is_compared` and its control (`test_support::trace_read` mints a trace from a read state). The `ARW` family is closed (index §2) and mints no row for this; the record is here. What it records: §3.8 specified *what* the checkpoint carries and never *when* it is read, and the two moments read identically on every chain in hand — the "exercised only in its degenerate case" shape `ARW-Q18`'s ruling named, met again one commit later. |
| 2026-10-02 | **Commit 10d — the serve-credit mirror and its equivalence KAT deleted; §3.9's deferral of it was void.** Maintainer's ruling on the commit-10 report. §3.9 had carried `serve_credit_decisions.rs` as *"retires with `PDM-Q6` item 4's re-key"* — a deferral whose blocker was itself a ruling with no schedule, which rule 22 does not count as a blocker. Read on its own terms the mirror had no caller, implemented the leaf preimage `PDM-Q6` item 4 retired, and read to anyone grepping for one as a Rust serve-credit verifier the Rust validator does not have (`census.rs` J8–J10 pending). So the mirror, its equivalence KAT (Rust leg, C++ leg, shared fixture) and the two fuzz targets over it were deleted together, `DEL-008`'s exclusion of them struck, and the gap stated plainly where it is owed (FOLLOWUPS *Serve-credit acceptance (CEN-J8–J10) has no Rust rule*; the successor is built from the ruling with its own vectors, `ARCHIVAL_CREDIT_WIRE.md`). Behaviour unchanged; what the tree claims changed. §3.9's own sentence edited under rule 91's refuted-premise bullet — belatedly, at the PR-937 review: the commit that refuted the premise edited the register and the census and left this document's sentence standing, which is the exact shape 10a's bullet names. |
| 2026-10-02 | **`ARW-Q18` ruled (maintainer): the default taken — no slash-bearing corpus capture — and the gap it would have closed, closed with a cheaper test (commit 10e).** The arguments for the default held: the replica discharges the writer-versus-C++ comparison and is the only instrument that reaches the slash family; a seventh chain would be captured from a generator that is leaving, so its oracle expires; `ARW-Q17` had already extracted the denomination evidence, `ARW-27` the residue. What a slash-bearing chain would genuinely have added was named precisely — not replay coverage of the writer (the driven witness already connects four personas through the real store to the slashing block, and connect is one code path whatever the block's source) but the **`0x04` snapshot's slash families serialized at non-empty**, which no captured chain does: an encoding exercised only in its degenerate case, the shape that has bitten this program repeatedly. And it needed no chain: the witness already builds that state, so it now calls `archival_snapshot()` at its tip and pins the bytes — the slash sections spelled from the facts, the whole body by hash — against the production writer's output, in a test that already runs. Recorded as *the cheaper instrument was found*, not *we decided not to*, because the two read differently to whoever reopens it. The same ruling named a reporting hole worth its own line: the inland-height gate landed on 2026-10-01 as its own commit (`ARW-Q16` (c), `96253fa6be`) and the commit 8, 9 and 10 reports cited only its ceiling moves, `174 → 172 → 170` — three numbers and no instrument, the same shape as a count quoted without its log. Rule 08 gains the habit (commit 10f): when a gate lands between the commits a report covers, the report names it once. |
| 2026-10-02 | **Commit 10 — DRS-E4 closes as record; `ARW-Q19` re-homed; the deletion register gains the cutover-day list; rule 91 gains the refuted-premise bullet.** Three maintainer directions on commit 9's report, each landed as its own commit. (1) *The §12 register is a register of deletion decisions, not the cutover checklist* — `DEL-008` was the first entry that could anchor that checklist, so `DAEMON_REDB_STORE.md` §12.1 is now the one list of what goes red or stale on the day (each entry built where it was built: `held_by_cxx`, `MET_TRIGGER_UNGOVERNED_AT_REGISTRATION`, the bijection gate's empty-subject guards, `MIN_CONSTRAINTS`, `MIN_DIGEST_RS` / `MIN_WALKER_CPP`, `check_segment_freeze_sites.sh`, the C++ walker's marshal, the conformance register's two unreachable states), with the rule for the day — retire the subject, never clear the gate — because the temptation under that pressure is to clear a gate rather than retire it. (2) *Three times in this lane a correct finding did not reach the artifact that produced the error* (`SPR-1`'s formula, the rule-22 row whose condition fired, §3.9's sentence) — rule 91 now says a finding that refutes a premise edits the premise's own text in the same commit, and this commit applies it: `reorg.rs`'s `journal_horizon` doc and `DRS_E1_SPRUNE.md` §3 no longer say the journals have no Rust writer. (3) *Archive it, and re-home Q19* — `DRS_E1_SCURVE.md` the precedent: this document and `DRS_E1_SARCH.md` (its own condition met) go to `completed/` with banners naming what each owns nothing of, and `ARW-Q19` becomes `SLK-Q1` / `SLK-Q2` in `DRS_E4_SLASH_LOG_ROUND.md`, the round that owns it from its start. The S-ARCH row's write half → LANDED. §9 discharged item by item, with the three items that did not go as written named with why (table 2 is a schedule view; SI-6 needed no restatement after `ARW-Q2`; the "staying in `design/` for slice 8" clause was void — slice 8 cites neither section). |
| 2026-10-02 | **Commit 9 — §3.9's Rust half does not delete in this increment; the premise was refuted, not re-weighed.** The row's sentence — *"the Rust pop folds and the freeze half delete in this increment (no caller survives the C++'s retirement…)"* — gave as its reason a state that obtains after the cutover, and the increment runs before it. `release_pop` / `reinstate_pop` are the C++ pop path's through `shekyl_archival_{release,reinstate}_pop` (`db_lmdb.cpp:6237`, `:6369` — inside §3.9's own C++ surface); the freeze half is the C++ freeze pipeline's, the coverage RPC's, the serve-credit verifier's, and the economics sim's. Commit 3 had already found this for the freeze half and re-scheduled it in §3.7; §3.9's timing was never amended to agree, and the pop folds were not examined. The survey of every archival export (60) found one with no caller at all — `shekyl_archival_settlement_epoch_overridden` — deleted with its backing fn. The surface is one deletion with the FFI as its seam; it is registered whole as `DEL-008` in `DAEMON_REDB_STORE.md` §12, trigger the cutover, with a falsifier. Rule 22: disclosed here and in the commit; rule 16: *refuted* (the premise's tense), so that the next reader does not re-open "delete the Rust half early" as a weighing. |
| 2026-10-02 | **`ARW-Q19` posed (maintainer's framing): the slash log's key and its horizon, one row, a short round after PR-b — and the round inherits a condition that had already fired.** Two questions, only one an optimisation. The key: `(height, seq)` is keyed by *when* and read by *who held what at `h`*, so the one reader scans every persona's slashes above `h` and filters; keyed `(PersonaId, ShardId, BlockHeight)` the read is a prefix range and strict-above reads off it. The horizon: both readers reach back a bounded distance and the log is stored as if they did not — the shape S-PRUNE removed from the body corpus. Checked at source before posing: the horizon is **F19's** `tip − ((k + n)·SEB + D_max)`, not `(W + 1)·SEB` (claims do not read the log); it is already ruled (`PDM-Q-F16`/`F19`), its function already built (`journal_horizon`, S-PRUNE, 2026-09-25), and its retirement site re-homed to S-ARCH *"when those writers land"* — commit 8 landed the writer, this plan never carried the retirement, and the FOLLOWUPS row has sat since 2026-09-22 reading *pending* while its condition fired here. That is the rule-22 finding the row records, with the carrier named (the round) rather than left to the next re-scope audit. The two are one row because the horizon's answer may decide the key's shape: retirement is a range deletion under a height-led key and a scan under a persona-led one, and the table is small either way once the horizon exists, so the choice is which read the key makes unspellable-wrong. Three facts the query shape hides are written beside the proposal — the complete-tree arm proves every shard, `(p, s, h)` is not unique, and the key is in the digest preimage and SI-22 — so the round rules them rather than meeting them. Not folded into commit 8 (rule 19). |
| 2026-10-02 | **`ARW-Q17` ruled (maintainer): the slash log is written in `BlockHeight` — the connecting height — because the reader's predicate says so; and the check the ruling asked for found the C++ off-by-one live (`ARW-27`).** The lane had posed the key as a choice between two names for one block, with a position. The ruling re-read what the log *is* — `SlashedHolding`'s doc: the pre-image for the as-of-height fold, nothing else — and took the key from the one question the table answers: *did `P` hold `s` at `h`* is *yes iff a logged slash **strictly above** `h` removed it*. A slash decided during block `H`, keyed `H`, is not held at `H` (correct — that is where it applied); keyed `H + 1`, it is held at the height that removed it. The predicate's strictness and the connecting-height key are one coupled fact, so the adjudicator is the doc comment plus the typed axis — not the corpus (no slash), not the spec (silent), not the capture (the C++'s answer). That makes the ruling **denominational**, which is exactly the question `ARW-Q16`'s axis was minted to make answerable once: `SlashLogKey.height: BlockHeight`, strictness stated beside it, ends it for the table. The ruling named one check before it stood — *does the C++ pass a height into its count-keyed predicate anywhere?* — and it does, at both call sites (`h_fire`), with its own reader comment stating the height semantics the writer's count breaks: a live off-by-one where epoch `e`'s slash connects (exactly `H_close(e + 1)`, the top of the next epoch's fire range), surfacing at `1 / modulus` per challenge on the slashed pair. The capture's rows are therefore the C++'s defect, written down, which the Rust writer does not inherit either way. No C++ fix (rule 20; §3.9 deletion target); the pins stay as the record. `ARW-Q18`'s reopening criterion did not fire. |
| 2026-10-02 | **Commit 8 lands the oracle green on the corpus, the `ARW-Q15` replica with its one red, and two posings — `ARW-Q17`, `ARW-Q18` (maintainer's framing; the lane built it).** The framing corrected the plan before the commit ran: `ARW-26` had been written as a disagreement to *adjudicate against the spec*, and there is no spec to adjudicate against — nothing names the slash-log key — so it is a **new ruling**, posed with a position attached (the connecting height; the C++'s count is `m_db->height()` read as a height, the `ARW-Q16` class) and the **read-side consequence** that makes it more than a key: `slash_log_after` / `holds_shard_at` read strictly above their height, so the ruling decides whether a persona slashed during block `c` holds *at* `c`. The capture's role was re-stated — say the two sides disagree and exactly how, settle nothing — and the replica does that: the fixture's state reached by construction under a levered schedule, every state field equal through a role map, both key equations pinned. Pre-declared before the stamp ran: slash rows empty on all six, the slash and close families' stub red; the census refuted one third of it same day (`last_slash_epoch` is the deadline scan's progress, not a slash row) and the correction is recorded beside the prediction, not over it. That red, with the replica's finding attached, is `ARW-Q18` — the slash-bearing corpus capture — posed with a default of *not before genesis*, because the replica discharges the comparison the capture was for and the C++ writer it would witness against is a deletion target. The typing landed as `ARW-Q16` (a) said: `ChainCount::with_tip` with its C9 `compile_fail`, `Transition::count() -> ChainCount`, `connecting: BlockHeight` at the two write sites, the grandfather list down two. |
| 2026-10-01 | **`ARW-Q16` ruled; the inland-height gate lands in E4, now, grandfathered (maintainer).** The question was posed as *whose work is typing the archival surface's block axis* with three one-apart defects as evidence; reading the tree before posing found the type pair and its contract already existed (`HEIGHT_SEMANTICS.md` §3.1 C2/C7) and the surface sat outside the campaign's census. Ruled: (a) E4 lands its own sites typed (commit 8's `ARW-26` resolution first); (b) the surface-wide retype is `HEIGHT_SEMANTICS.md` Phase 2g, a separate slice; (c) **sharpened** — the gate is not Phase 2g's first deliverable, because *a gate that can't pass can't land* and its value is preventing the forty-first instance, which is live during commits 7–10. Landed as `check_inland_height_u64.py` with 174 exact-hit records and a ceiling that only lowers; (a) is thereby held by CI rather than by the implementer. Two formulations from the filing kept where they will be reread (rules 05 and 47): *a name defends the crate it is in; a type defends the call* — commit 4's `count()` ruling explaining its own failure, and general past heights; and *a review-borne rule whose campaign reads complete is one nobody re-checks* — Phase 2e true of the census and false of the tree is the same class as the §3.4 nettype sweep's "only I4 remains" beside a hard-fork divergence its instrument could not see: five sweeps now whose conclusions outran their subjects, and the remedy each time a gate, not a better sweep. |
| 2026-10-01 | **`ARW-Q14` ruled (a), and then the hash itself struck: at one checkpoint per chain the archival state travels as rows, and the grader diffs (maintainer; `ARW-25`).** The ruling first: the digest compares state, a keyed table's state is a set, and order-dependence would turn a legitimate order change into a false red in the authority while the order already has its own gate — with two preconditions written beside it (leaves unique by construction, because every family is `key ‖ Canonical(value)` over unique keys; the count load-bearing, because XOR alone cannot tell empty from cancelled). Then the reframe, on a premise checked at `trace.rs:22`: **one checkpoint, at the covered tip (RD-F18) — six across the corpus, not per block.** At six, a hash buys nothing a diff does not and costs the localisation the comparator exists for; the archival state at the tips is kilobytes. So commit 6 is re-shaped: §3.8.1's row encodings stay as the serialization both sides emit; the `digest_v1` hasher, its domain strings, the 459-byte preimage, the singletons' presence tags, the accumulator (`ARW-Q14`, moot) and the KAT fixture are struck the same day they were specified (`b728a8c81` holds the text); the trace gains a `0x04` snapshot record (*corrected from `0x03` the same day — E2's reserved Verdict tag; §3.8.1*), `0x02` unchanged (`ARW-Q12` re-ruled); the grader names family and key. Two of this record's own claims corrected under it (`ARW-23`): cardinality does not catch ordering under a set comparison and is not sold as doing so; state cannot distinguish *ran and wrote nothing* from *never ran* — `Provenance.stubbed` and the oracle's non-empty rows do, which is what makes the stamp's denominator readable off the corpus. The reflex was inherited, not the code: a 32-byte commitment is how this codebase thinks about state, and a comparator has the opposite requirements of a root. Reversion clause in row 6: the condition is the cadence, not the choice. `ARW-Q15` poses the LMDB-fixture capture for the families the corpus does not reach; default capture with inputs, consumer commit 8. |
| 2026-10-01 | **The KAT's coverage is stated, the empty case is pinned, and §3.8.1 carries v0 as records-was (maintainer, on the KAT direction).** *Partly superseded the same day — see the entry above (`ARW-25`): the KAT fixture is not built, the empty-case claim is corrected in `ARW-23`, the v0 records-was stands.* The LMDB fixture writes multi-row families (writer calls in fifteen loops over epochs, shards, sequences, intervals), so the KAT does too, and says so: its `description` names each family's cardinality — empty, one, several, at the frozen cap where one exists — the `the_record_round_trips_at_every_cap` discipline (`ARW-23`). The empty case is the load-bearing one: the stamp tells *ran and wrote nothing* from *never ran* only against a pinned empty-family digest. The accumulator's shape is posed as `ARW-Q14` with v0's order-independent `count ‖ XOR` as default — ordering eliminated by construction rather than tested (its first draft claimed LMDB and redb iterate the tuple keys in different orders; they coincide, `schema.rs:547–608`, corrected the same day — the question is which job the digest does, not what a sort would cost, and the ruling is owed before the hasher). And §3.8.1 carries **v0 verified against `digest_v0.rs`** beside v1, because the E2 comparator's history is denominated in v0 and v0's specification would otherwise retire with the file; `ARW-Q13` narrows to the section's home. |
| 2026-10-01 | **Two directions carried into commit 6 (maintainer, on the pre-flight).** *Re-pointed the same day under `ARW-25`: (1)'s principle stands and its carrier is commit 7's six `0x04` records, not a KAT fixture; (2)'s trace falsifier is the `0x04` record's presence, not a widened `0x02`.* (1) **The walker's output is captured as committed data before the cutover deletes it** — the I17 KAT shape: a C++ leg in capture mode over the LMDB unit fixture's state (the corpus commits no LMDB and has no slash; the fixture reaches every family, `ARW-23`), writing rows, preimage and digest *as the specification's output* — documented against §3.8.1, what `digest_v1` is specified to be, not against what the walker produced; the Rust leg holds `digest_v1` to it after the C++ is gone. This requires the preimage to be specified before the hasher (`ARW-24`; §3.8.1 is commit 6's first edit; its promotion to a contract document is `ARW-Q13`, commit 10's). (2) **The format tag bump is v4, and neither format number is a falsifier.** The manifests move `3 → 4` in commit 7 and the trace `0x00 → 0x01` in commit 6; v3 already demonstrated that a version is satisfiable by any writer, so each is falsified by the *fields* it introduces — the injection's `height` and `persona` on every `out_of_band_writes` row; two 32-byte digests in every `0x02` record — never by the number (row 6, §6.2 item 2, rule 22). |
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
