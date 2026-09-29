# DRS-E4 — the archival writer: pre-flight

**Status:** OPEN — **Round 0 executed 2026-09-29 at `dev@cac2dadbe`** (#889
merged; the slice-7 c3 tree). Findings `ARW-1…ARW-14` recorded (§5);
questions `ARW-Q1…ARW-Q9` **posed with defaults, not ruled** (§8) — no
implementation commit lands on this lane before §8 is RULED
(`26-sub-pr-design-discipline.mdc`'s halt condition). Identifier families
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
(the serve-credit preimage is re-keyed over `shard_id` and
`(k·T, (k+1)·T)`, landing site "E4 / S-ARCH in `shekyl-chain-rules`",
`:821`) and **item 5** (shards are fixed-cardinality `T`; no length rows);
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
   `regtest_inject_archival_serve_credit` (`regtest_e2e.rs:3325`;
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
   shard universe is `{k : (k+1)·T ≤ cumulative_tx_count}` — a function of
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
- **`total_bonded_atomic`** as a checked view (§3.4, SI-20).
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
  first, the rule judged what it wrote.
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
  lands with the serve-credit rule in slice 8 — this document changes the
  row's owner to that slice and records the disclosure here (rule 22).
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
finding): `k = ⌊tx_id / T⌋`, `[k·T, (k+1)·T)`, closed iff
`(k+1)·T ≤ cumulative_tx_count`. `segment_leaf_count`, `SEGMENT_LAYER_J`,
`leaves_per_segment()` and `frozen_segment_count` lose their last consensus
consumer here; the wallet-side store's use is that lane's (`PDM-Q12`).

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
Vec<(ShardId, RMarket)>, sigma_work, budget }>`, and the accrual. The store
writes each through its handle and checks what it can (§4). **The store
holds no archival arithmetic**: `connect` does not know what a slash is,
only that a record is replaced and a set gains a member.

*What this costs, said plainly:* the slash scan reads every bond record at
a deadline height, and the close reads the epoch's snapshot — reads that
today happen inside the write transaction and would move to the view. The
C++'s own scan-cost note (`db_lmdb.cpp:5708–5719`) says the cost is once per
epoch, not per block; B9 says measure it rather than assert it, and §6's
commit 5 does.

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
  claim through `open_upsert_table(ARCHIVAL_BOND)` with the pre-image
  journaled. `total_bonded_atomic` is not written (§3.4: a view).
- **Phase 5**: `archival_attestation_witness[h] = witness` when the
  verdict's witness is non-empty (`blockchain_db.cpp:669–671`'s rule, A10's
  two absences kept).
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
| `total_bonded_atomic` cell | **view** — `Σ bonded_total` over `archival_bond`; **no reader** outside the writers that maintain it (`blockchain_db.cpp:313`, `:943`; `db_lmdb.cpp:5610–5613`) | **not written**; a `total_bonded()` read sums the table, and SI-20 checks the sum against the records when a record changes (`ARW-Q9`) |
| `archival_slash_applied` | **fact** (a set) | typed `Present` |
| `archival_slash_log` | **fact** — history (§3.3) | typed |
| four revert logs + `archival_epoch_close_log` | journals | **dissolved / deleted** (§3.3); `NOT_PORTED` rows with the reason |
| `archival_shard_segment` | retired (`PDM-Q12`, SAR-5) | **deleted**; CEN-L10 → bucket 3 |
| `archival_settlement` | **fact** with no writer until SO-D8's cutover and no reader (`SO-D8` §5.1) | **held `Unshaped`, blocker named** — falsify by the cutover PR; not shaped (SAR-Q1's ground), not deleted (its production caller is a rule-22 hold, not an absence) |
| `archival_alt_attestation_witness` | folded into `alt_blocks` (S-ALT) | unchanged |

Net: three tables typed (`slash_log`, `slash_applied`, the accumulator), six
deleted (`shard_segment`, the four dead journals, `epoch_close_log`), one
dissolved (`budget_accrual`), one held; `tables.snap` moves by **−7 + 1**;
the `NOT_PORTED` register gains six rows and `RUST_ONLY_TABLES` one; layout
16 → 17.

### 3.5 The accrual — `ARW-Q3`, default: one row per epoch, not one per height

The C++ writes a row per block and range-sums it once at the close
(`db_lmdb.cpp:7830–7864`), deleting the block's row on pop
(`blockchain_db.cpp:790`). Nothing reads a single height's accrual. The
dissolved shape: `archival_budget_accruing[E]` — one `Coded<AtomicUnits>`
row per open epoch, upserted every block with the pre-image journaled; the
close reads it, writes `archival_budget[E]`, and the accruing row is left
(or deleted — either is pop-symmetric through `undo_log`). Pop of a block
restores the accumulator's pre-image; a pop across the close restores the
budget row's absence and the accumulator; a re-close re-reads the
accumulator. `ARCHIVAL_BUDGET_SCHEDULE.md` §3.2's KAT B3 (pop-and-re-close
reproduces the budget byte-identically) is the test, and it must pass on
the new shape before the old one is deleted.

The value written is the verdict's `staker_emission + staker_pool_amount`.
Until CEN-F17 lands (slice 7 wave B, on this increment's operand — §3.7),
the burn term is what `burned` already is: a `Fact` with
`Origin::PassedThrough`, one more row in `DELETED_BY` naming F17. **Disclosed
here** (rule 22): the accrual is half passed-through at landing, the file
says so in `passed_through_facts`, and the E2 grade is not archival parity
evidence until F17 derives the other half.

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

### 3.7 The shard universe — `ARW-Q6`, default: closed `T`-shards, read off the chain

Two consumers of the retired leaf partition sit on this surface: the
complete-tree slash arm (§1 item 9) and CEN-F17's `n` (§1 item 8,
FOLLOWUPS `:727`). Under `PDM-Q6` item 5 both become
`closed_shards(view, h) = ⌊cumulative_tx_count(h) / T⌋`, read from
`block_info` — a `ChainView` read that already exists in substance
(`cumulative_tx_count` is store-derived, `connect.rs:411–418`). No table, no
freeze, no `frozen_segment_count`. `segment_leaf_count` leaves
`consensus_constants.json` in the commit that deletes the last Rust reader
of `leaves_per_segment` on the consensus side (`DRS_E3_CURVE_WRITER.md` §3.9
scheduled it here; the wallet-side store's reader is that lane's and is not
a consensus reader). CEN-F17 then has its operand; the rule stays E6's.

### 3.8 The §7.1.1 discharge — `ARW-Q5`, default: an archival digest family, tip-compared, plus the stamp

The gate names two acceptable forms: digest coverage over the archival
families, or a named exclusion with a **replacement KAT that forces
apply/revert to run**. This increment lands the first and makes the
existing mechanism for the second real:

1. **`digest_v1`** — v0's three families plus the archival state as
   *logical* sets: bond records (`p → canonical record`), serve-credit
   keys, `(shard, E) → r_market` with zero-rows projected out (§3.6),
   `E → Σwork`, `E → budget`, `h → witness`, the slash log, `slash_applied`,
   `last_slash_epoch`. Computed by the C++ walker over LMDB
   (`BlockchainLMDB::logical_state_digest_v0`'s sibling, a marshal into the
   Rust hasher — rule 20's shim, no C++ hashing) and by `ReadSnapshot` over
   redb; format tag bumped; the trace's checkpoint carries both. Tip-only,
   because that is what the C++ can produce (§1 item 5).
2. **The sufficiency stamp armed**: with writers present, a session that
   stubs family X skips X's phase body and widens `Provenance.stubbed`
   (`ARW-9`'s default), and the run's digest goes **red** against the trace
   — the test that proves the apply ran, run once per family in CI.
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
| SI-15 | serve-credit rows are keyed by a persona with a record | built (E1); the **writer's** check lands here — phase 2 refuses a credit for an unknown persona before writing (CEN-L7's first backstop) |
| SI-19 (new) | **a persona has at most one record, and a JoinMarket is the only insert** — `archival_bond[p]` is insert-once; every later change is an upsert with a pre-image | phase 2 (`open_insert_table` for JoinMarket, `open_upsert_table` otherwise); CEN-L14 site 2 |
| SI-20 (new) | **`Σ bonded_total` over `archival_bond` equals the total the delta implies** — the view's check: after a record write, the new sum equals the old sum plus the delta's signed change | phase 2 / phase 9; `ARW-Q9` |
| SI-21 (new) | **an epoch closes whole**: `archival_sigma_work[E]` and `archival_budget[E]` exist together with every `(shard, E)` r-market row the snapshot named, or none does | phase 9 (insert-once on `E`; a second close of `E` is `StoreInvariant`, never a silent overwrite — CEN-L14's O-2 adversary) |
| SI-22 (new) | **the slash log is dense per height** — `(h, seq)` rows for `seq ∈ [0, n)` and no other, and every row's `(p, shard, E)` is in `archival_slash_applied` | phase 9 |
| SI-6 | pop-ability is `undo_log[h]` — restated: **no archival table is a second pop mechanism** | by construction (§3.3); falsifier: a `Restorable` impl that reads an `archival_*_log` |

Every one is a *store* property; whether a slash was due or a close was
correct is the validator's (§3.1).

---

## 5. Round-0 findings

| Finding | Statement |
| --- | --- |
| **ARW-1** | **The corpus's only closed-epoch chain is priced on a write no block made.** `emission-claim`'s serve credit is the regtest injector's direct LMDB write (`regtest_e2e.rs:3325`, `core_rpc_server.cpp:958`); a block-driven replay cannot reproduce it, so an archival tip digest over that chain diverges by construction unless the injection is an event in the trace (§3.8 item 3). Found by reading the generator, not by running the replay — which would have reported a red that looked like a writer bug. |
| **ARW-2** | **Five of the six revert logs are CTW-2/CTW-3's shape; the sixth is history.** `undo_log` holds every pre-image the C++ journals recompute or copy; `release_pop` and `reinstate_pop` exist only to reverse what a pre-image restores. The slash log alone is read forward (`holds_shard`), and its epoch-marker row kind exists only because the C++ had no pre-image of `last_slash_epoch` (§3.3). |
| **ARW-3** | **The C++ decides in its storage class in three places, not one.** CEN-L16 minted the holds-shard fold; the challenge-failure decision (`archival_challenge_failed_at_height`, `:5459`) and the shard-enumeration of the slash scan (`:5720–5752`) are the same class — consensus predicates evaluated by `BlockchainLMDB` with no R8 row. The sweep that minted L16 covered reads; these are writes' preconditions. One census question, not three (the FOLLOWUPS sweep-subject row `SAR-Q7` opened). |
| **ARW-4** | **The complete-tree slash arm walks the retired freeze registry.** `db_lmdb.cpp:5720–5744` enumerates `archival_shard_segment` to name a `CompleteTree` bond's shards; `PDM-Q12` retired the table. Under `PDM-Q6` item 5 the universe is `⌊cumulative_tx_count / T⌋` closed shards — a view the store already holds (§3.7). |
| **ARW-5** | **The accrual table is a view read once.** Per-height rows, one consumer (the close's range-sum), one deleter (pop). A per-epoch accumulator is the fact (§3.5). |
| **ARW-6** | **Slash burns into the cell phase 8 owns.** `total_burned += slashed` (`db_lmdb.cpp:5615–5618`) inside the slash apply; `connect` folds `burned` into the same cell (`connect.rs:449–457`, SI-8). Two writers of one running total in one transaction is the SI-8 hazard; the slash contribution goes through the one fold. |
| **ARW-7** | **`total_bonded_atomic` has no reader.** Both `get_total_bonded_atomic` callers are the writers maintaining it (`blockchain_db.cpp:313`, `:943`; `db_lmdb.cpp:5610`). A running total nobody reads is a view with a corruption surface and no consumer; not written (§3.4). |
| **ARW-8** | **The close writes zero as absence.** `r_market == 0` skipped at `:7804` while the budget row is written *because* zero must be distinguishable (`:7830–7833`) — the same file, two conventions, one screen apart. SAR-8's read-side fix needs its write side (§3.6). |
| **ARW-9** | **The stub refusal has no caller-side semantics.** `admit()` returns `StoreCannot::FamilyStubbed` (`write.rs:395–405`); nothing catches it, because nothing writes. The mechanism's own doc says a stubbed apply is *skipped* and *widens the provenance*; the error today would abort the connect. E4's phase bodies decide: skip-and-widen (default — it is what makes the sufficiency red attributable) or abort. |
| **ARW-10** | **The graph argument in S-ARCH §3.4 has lapsed.** `shekyl-chain-rules` depends on `shekyl-archival-retention` (`Cargo.toml:55`) and the store on the rules crate, so the retention crate is in the store's closure. The conclusion (`BondRecord` in the store's codec) held on rule 18's *readers* test, not the graph; that test flips when slice 8 reads the record through `ChainView` (`ARW-Q8`). |
| **ARW-11** | **The epoch prune is nobody's.** `prune_archival_epochs_before` and its watermark (`db_lmdb.cpp:7084–7166`) are neither S-PRUNE's (bodies, undo rows) nor the close's in redb; the C++ watermark's one consumer is the pop floor `pop_target_allowed` (`blockchain_db.cpp:705–736`), which SI-6's undo floor already provides. Whether closed-epoch rows are pruned at all is `ARW-Q7`. |
| **ARW-12** | **Phase 5 has nothing to write on any chain that exists.** The attestation producer is unbuilt (FOLLOWUPS `:139`); every captured witness is empty; the body's only witness is a scenario that supplies one. Recorded so a phase that writes zero rows across the whole corpus is not read as verified. |
| **ARW-13** | **The serve-credit rule the corpus was captured under is retired.** J8–J10 as the C++ runs them sign the leaf preimage `PDM-Q6` item 4 re-keyed; no chain the C++ daemon can capture carries a record the Rust rule will accept. Serve credits are Rust-first (§2.4) — the C++ is not an oracle for them, and this document does not pretend otherwise. |
| **ARW-14** | **HoldingsUpdate is dead in three places at once.** REJECTED 2026-09-20 (immutable bond); the appliers are no-ops (`db_lmdb.cpp:6270–6289`), the revert is a "named no-op so pop order stays explicit" (`blockchain_db.cpp:773–776`), the journal table is empty by construction, and CEN-J17 / J13's drop arm describe it as live. Deleted here; the census rows are slice 8's to re-key (rule 23: REJECTED keeps the name in the contract, marked). |

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
| 1 | **Tables and types.** `archival_slash_log`, `archival_slash_applied` typed; `archival_budget_accruing` added (Rust-only); six tables deleted (`NOT_PORTED` rows); `total_bonded_atomic` not minted; layout 17; snapshots; SI-19…22 minted. `BondRecord` and its vocabulary to `shekyl-types` (`ARW-Q8`). | M | a hidden reader of a deleted table (falsify: `rg` each name outside `schema.rs` and `apply_policy.rs` before cutting) |
| 2 | **`ChainView` grows the archival reads** (§2.3) — trait, `BatchView`, `MockView` held to each other by the conformance test; A2 `slash_log_after` and `holds_shard_at` land (the `SAR-Q7` pair), with the LMDB as-of-height cases (`archival_substrate_lmdb.cpp:1674–1893`) as Rust tests. | M | `MockView` needing archival state it cannot construct honestly — the signal that a `Mock*` is being built (§5.2) |
| 3 | **The shard universe** (§3.7): `closed_shards` on the view; CEN-F17's operand ruled; `segment_leaf_count` out of the JSON; the consensus-side `leaves_per_segment` readers deleted. | S | a wallet-side reader in the consensus closure (falsify: `cargo tree -i shekyl-fcmp -e features` shows the freeze module reached from `shekyl-chain-rules`) |
| 4 | **The transition on the verdict** (§3.1): `ArchivalDelta` derived in `validate` from the vin arms and the folds; the slash scan and the close as functions of the view; carried on `ChainValid`. Tests: each arm on a driven chain; the KAT B3 pop-and-re-close on the accumulator shape. | **L** | the slash scan's view reads being the wrong shape (a scan over `archival_bond` needs a range read the view does not have — this is where it shows) |
| 5 | **The phase bodies** (§3.2) with SI-19…22 built; the stubbed-family skip-and-widen (`ARW-9`); the regtest injector on the store; **the slash scan measured** (B9: once per epoch on the floor, against the C++'s own note) — the accrual's burn half a `Fact` until F17 (§3.5, disclosed). | M | `pop` of a block that closed an epoch: the journal's restore of insert-once rows under a tuple key (the `Restorable` impl the table did not need until now) |
| 6 | **`digest_v1`** (§3.8): the Rust hasher over the archival families; the C++ walker's marshal; the trace format's checkpoint carries v1; format tag bumped. | M | the C++ walker: the only C++ this increment adds, and rule 20 holds it to a marshal — if it grows arithmetic, stop |
| 7 | **The injection event** (§3.8 item 3): `IngestEvent::Inject`, the exporter reading the injector's receipt, the connector applying it through the store's regtest door; **re-capture of the four chains** under the corrected regtest table and the v1 checkpoint. | M | the exporter cannot see the injection (no receipt in LMDB) — then the generator writes one, and the re-capture waits on it |
| 8 | **The oracle** — the protected commit. Replay all four chains; the v1 digest at every tip; the sufficiency red once per family. A tip disagreement on `bond-post` or `emission-claim` **stops the PR** and is adjudicated against the spec (E2 §0), never toward the C++ — with one named exception: a divergence that traces to zero-as-absence (§3.6) is the projection's bug, not a finding. | S | a disagreement — which is what the commit exists to produce |
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
1–5 land as **PR-a** with the family stubs *on* for the four chains and the
provenance widened — the file honestly not parity evidence — and 6–9 as
**PR-b**. That is a **split** (rule 22: re-scheduled inside the scope, both
PRs named here), not a deferral; PR-a's description says PR-b is owed and
what its falsifier is (`rg 'digest_v1' rust/shekyl-chain-store/src` →
present; the four manifests at `format_version: 3`).

---

## 7. What E4 unblocks, and the measurable

| Waiting | Falsifier |
| --- | --- |
| E6 slice 8 (4.J, 26 rows) | `rg 'fn bond_record\|fn slash_log_after' rust/shekyl-chain-rules/src/view.rs` → the trait methods with `BatchView` impls |
| CEN-L16 | `rg 'fn holds_shard_at' rust/shekyl-archival-retention/src` → present; `rg 'archival_bond_holds_shard_of' src/blockchain_db` → still present until cutover, and the census row says both |
| CEN-F17's operand | `rg 'fn closed_shards' rust/shekyl-chain-rules/src/view.rs`; `rg segment_leaf_count config/consensus_constants.json` → nothing |
| E2's S-ARCH bar (SAR-11) | `rg 'digest_v1' rust/shekyl-chain-store/src` → present; each manifest's checkpoint at v1; the sufficiency test red for each family (`cargo test -p shekyl-chain-ingest stubbed_family_reddens`) |
| The injected credit modelled | `rg 'Inject' rust/shekyl-chain-ingest/src/source.rs` → a variant; `emission-claim`'s trace carries one |
| `SAR-Q7`'s staged pair | `rg 'fn slash_log_after' rust/shekyl-chain-store/src/store/archival_reads.rs` → present |
| The daemon-uniformity sentence (FOLLOWUPS `:176`) | `rg -n 'no archival serving state' docs/design/DAEMON_REDB_STORE.md` → hits — **HOLDS 2026-09-29** (written by this PR) |
| One shard definition on `dev` | `rg 'leaves_per_segment\|SEGMENT_LAYER_J\|frozen_segment_count' rust/shekyl-chain-rules rust/shekyl-chain-store rust/shekyl-archival-retention/src` → nothing on the consensus side |

Denominator at the pin: `cargo test -p shekyl-chain-store --lib` 375,
`-p shekyl-chain-rules --lib` 262, `-p shekyl-chain-ingest` 89,
`-p shekyl-archival-retention` (unchanged in count until commit 9 deletes
the pop folds' tests); `check_redb_schema_bijection.py` /
`check_redb_schema_key_types.py` (six out, one in, `NOT_PORTED` +6,
`RUST_ONLY_TABLES` +1); `check_store_invariant_register.py` (SI-19…22);
`check_lmdb_schema_coverage.py` **unchanged until cutover** (no C++ table
dies here); the chain-rules coverage gate **unchanged** — the transition is
an operand, not a row, as growth was (`CTW-Q1`'s corollary); the doc gates.
Extended: the E2 conformance run with `digest_v1` on (commit 8).

---

## 8. Round-1 questions — POSED 2026-09-29 with defaults; each row line-local

| Q | Question | Default | Why the default |
| --- | --- | --- | --- |
| **ARW-Q1** | Who derives the archival transition — the verdict (`validate` runs the folds over `ChainView`; `ChainValid` carries `ArchivalDelta`), or the store under principle 3's first clause (a `WriteBatch` method calling the retention crate inside the transaction, as the C++ does)? | **the verdict** | §3.1: the values determine future validity (`CTW-Q1`'s reason); the C++ shape is the fusion principle 3's second clause forbids; the edge already exists. Reopens if commit 5's measurement shows the deadline-height scan through the view is the connect's dominant cost on the floor **and** profiling attributes it to the view boundary rather than the fold (B9). |
| **ARW-Q2** | The six journals: dissolve all six into `undo_log`, or keep the slash log as history? And does any consumer of as-of-height holdings survive `PDM-Q3`'s re-key? | **five dissolve; the slash log is kept and typed** (§3.3); the epoch-marker row kind is deleted | history is a fact `undo_log` cannot hold past `tip − D_max`; J8's operand is *held at `H_fire`*. Reopens if slice 8's re-keyed J8 drops the as-of-height operand — then the table and the fold go, and CEN-L16 → bucket 3. |
| **ARW-Q3** | The accrual: per-height rows range-summed at the close (the C++), or one accumulator row per epoch? | **one row per epoch** | §3.5: nothing reads a single height's accrual; pop-symmetry through the pre-image; KAT B3 is the test. |
| **ARW-Q4** | The close's zero rows: skip (the C++), or write `RMarket(0)` for every shard in the snapshot? | **write them**; the digest projects zero-rows out on both sides | §3.6: the read side already says `None` ≠ 0; a write side that does not write zero makes the type a lie. |
| **ARW-Q5** | The §7.1.1 discharge: an archival digest family tip-compared plus the stamp, or a replacement KAT only (stub-reddens, no digest)? | **both** — `digest_v1` and the stamp | the gate's own text names either; a digest without the stamp cannot attribute a red to a family, and a stamp without a digest never compares content. Neither alone is the gate's intent. |
| **ARW-Q6** | The shard universe for the complete-tree challenge set and F17's `n`: closed `T`-shards `⌊cumulative_tx_count / T⌋` on the view, or a stored count? | **the view** | §3.7: a function of a fact the store holds; a stored count is `curve_tree_meta`'s shape with no C1-style one-row read to justify it. |
| **ARW-Q7** | Closed-epoch rows: pruned (at what horizon, by whom — S-PRUNE's boundary batch, or the close), or kept? | **kept; no epoch prune in this increment** | `ARW-11`: the C++ prune's only consumer was a pop floor SI-6 already provides; rows per closed epoch are `O(shards held)` and claims reach back `W = 26` epochs. Reopens on a measured size argument (B9) — then it is a phase of S-PRUNE's boundary batch, inside the same transaction, and the horizon is derived from `W`, not chosen. |
| **ARW-Q8** | `BondRecord`'s home: stays in `shekyl-chain-store::codec::archival` with `ChainView` re-spelling it, or moves to `shekyl-types` under `SAR-Q2`'s reopening clause? | **moves** — the clause's condition is met | S-ARCH §3.4 as built: *reopens if slice 8 needs `BondRecord` on `ChainView`*; it does. The `AtomicUnits` objection (shekyl-units is shekyl-types' sibling) is answered by carrying `bonded_total` as `AtomicUnits` from `shekyl-units`, which `shekyl-types` may already reach or the record type lives beside `shekyl_types::archival` in whichever crate rule 18 names when both readers exist — commit 1 decides the crate by `cargo tree`, not by preference, and says which. |
| **ARW-Q9** | `total_bonded_atomic`: a typed cell maintained on every bond write (the C++), or a sum over `archival_bond` with SI-20 checking the delta? | **the sum, checked** | `ARW-7`: no reader; a running total is a view. Reopens with a production reader that needs `O(1)` (the RPC's `get_info`?) — then it is a cell *with* SI-20's check, never without. |

---

## 9. Documentation owed by the increment (rule 91)

`DAEMON_REDB_STORE.md` (the two `[E4 hook]` phase texts; the S-ARCH row →
LANDED with the write half; §7.5 table 2's E4 rows flipped; the lane graph's
E4 node; §7.1.1 re-read against the tree — the gate discharged, how);
`DRS_E1_SARCH.md` → `docs/completed/` (its §0/§2.2/§2.3 boundary statement
is owned here from landing); `STORE_INVARIANT_REGISTER.md` (SI-19…22;
SI-15's writer check; SI-6's restatement); `CONSENSUS_RULE_CENSUS.md`
(CEN-L10 → bucket 3 at cutover — **not here**, the C++ is live;
L7/L8/L9/L14/L16's store sites re-cited; `ARW-3`'s two siblings minted or
folded into L16's row as the sweep-subject row rules);
`CONSENSUS_STORE_RECONCILIATION.md` (the L rows' verdicts as built);
`CHAIN_RULES_CRATE.md` (`ArchivalDelta` on the verdict; the `ChainView`
archival reads; §13's F29 property re-held); `LMDB_WRITE_ATOMICITY_AUDIT.md`
§10 (the sixteen archival journals' `Digest v0` state → `v1`, the exclusion
retired); `ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md` → `docs/completed/` when the
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
| 2026-09-29 | **Round 0 executed** at `dev@cac2dadbe` in a fresh worktree off `dev` HEAD (#889 merged). Fourteen findings (ARW-1 … ARW-14); nine questions posed with defaults (ARW-Q1 … Q9). The surface's C++ writers map to one verdict-borne delta and eight phase-body writes; five of six journals dissolve into the undo log and one is history; the slash scan's shard enumeration walks a retired table; the accrual and `total_bonded` are views; the corpus's one closed-epoch chain depends on an injected write the replay must model as an event, and no captured chain carries the transaction kinds slice 8's rules will judge — the C++ is an oracle for bonds, accrual, closes and claims only. The §7.1.1 gate is re-read and its discharge is inside the increment (commits 6–8), with the seam at which the PR may split named (§6.1). Families registered at birth. FOLLOWUPS `:176` discharged by writing the constraint into the parent plan (§2.6). No code. |
