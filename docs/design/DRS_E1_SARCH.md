# DRS-E1 S-ARCH — archival reads: increment plan and Round-0 pre-flight

**Status:** OPEN — **Round 0 executed 2026-09-23** at `dev` @ `d8ebfd18c`;
**Round 1 RULED 2026-09-23** (maintainer, on PR #840; §9, each row
line-local): **Q1, Q2, Q4, Q5 defaults held; Q3 approved with one word
checked (same *semantics*, not byte-compatible); Q6 approved with the
reason the `Option` is load-bearing recorded; Q7 — defer the *port*, not
the *row*: the store-evaluated predicate is minted as CEN-L16 now, an
R8-class placement row C2-R8's write-path sweep never reached.** The
increment may now be cut from `dev` (§7). This file stays in `design/` as
the E1/E4 boundary statement (§0, §2.2, §2.3) until E4's plan owns it.
Implements *from* [`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) §5 (the
S-ARCH row: extraction order **7**, "largest surface (18) and gated on the
P0b journal audit"), §3.4 rule 3 ("Archival (DRS-E4): design typed cursors
for retention; **delete gather shell**"), §7.5 table 2 (CEN-L7 … L10 and
four CEN-L14 sites are **E4 S-ARCH** — the archival *writers* are E4's, and
this increment mints the shapes they will write into) and §7.1.1 (the E2
digest excludes `archival_*` and E2 may not act on any S-ARCH row until
archival digest coverage exists); from
[`DRS_E1_SCURVE.md`](DRS_E1_SCURVE.md) (the E1 shape this increment repeats:
reads on `ReadSnapshot`, typed absence, vocabulary in `shekyl-types`, the
writer named and left to its own increment); from
[`DRS_E1_STX.md`](../completed/DRS_E1_STX.md) §3.3 (the absence
discriminator, applied in §3.3); and from
[`ARCHIVAL_PRUNED_DAEMON_MODE.md`](ARCHIVAL_PRUNED_DAEMON_MODE.md) **`PDM-Q3`**
(the C++ serve-credit admission verifier dies at E4 / S-ARCH when the
preimage is re-keyed), **`PDM-Q12`** (the segment-freeze pipeline retires;
no successor object) and **`PDM-Q6`** (txid commits `prunable_hash` and
`pqc_auth_hash`; membership derives from length rows) — the rulings that
decide which of this surface's readers are already dead. Process per
`26-sub-pr-design-discipline.mdc`; identifier families **`SAR-`** (findings)
and **`SAR-Q`** (round questions) registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 by the PR that adds
this file (rule 94 §1; `check_index_prefix_uniqueness.py` branch (a): the two
parse to distinct prefixes and clear the 95 registered).

**The gate that lifted, re-read rather than inherited (rule 22).** The §5
row's blocker is "the P0b journal audit — its write paths are the ones whose
atomicity is still being characterised." P0b landed 2026-09-05
([`LMDB_WRITE_ATOMICITY_AUDIT.md`](../LMDB_WRITE_ATOMICITY_AUDIT.md)
RECONCILED; `DAEMON_REDB_STORE.md` §2 "Atomicity audit — rewritten by P0b"
and readiness row A1 "met 2026-09-05"). The blocker has been lifted for
eighteen days; the row still reads as blocked because nobody re-read it. This
document is that re-read, and §1 records the state the increment actually
depends on.

**Two lanes, stated once so they are not conflated.** *E1 S-ARCH* (this
document) is the **read** surface: the typed record shapes and the reads
`blockchain.cpp` performs on archival state, on `ReadSnapshot`. *E4* is the
**write** surface: the connect-side hooks (epoch close, settlement, slash,
bond folds — CEN-L7 … L10), their pop reversal, and the retirement of the C++
marshalling that E6 slice 8 (census 4.J, 26 rows, "all verdicts already
Rust-side") then adopts behind the rules crate. E1 mints what E4 writes into;
E4 does not get to choose a second shape for the same byte (the S-CURVE
contract, §2.3 there).

---

## 1. Preconditions, as found at the pin

| Precondition | State at `d8ebfd18c` |
|---|---|
| S-TXN … S-CURVE (E1 increments 1–7) | landed (#740, #749, #757, #772, #783, #800, #815) |
| `ReadSnapshot`, `AtHeight`, `AtIndex`, `chain_reads::cell`, the fault policy | landed (S-CHAIN-R, S-OUT-KI) |
| The 17 `archival_*` tables exist in the redb schema | landed, **all `Unshaped`** (`rust/shekyl-chain-store/src/schema.rs:373–438`); accumulator classes assigned (`accumulator/class.rs:110–137`) |
| `properties` shaped (`&str → Blob<PropertyCellBytes>`) | landed (`schema.rs:368`) — two of this surface's reads are cells in it (§2.1 #13, #14) |
| The settlement-epoch schedule pin (`codec/settlement_epoch.rs`) | landed (S-CHAIN-W SCW-2) — every epoch-keyed row here is meaningful only under it |
| P0b journal audit (the §5 row's gate) | **met 2026-09-05** (above) |
| `PDM-Q3`, `PDM-Q6`, `PDM-Q12` | RULED 2026-09-18 (`PDM-Q2` re-ruled 2026-09-22 does not touch this surface's reads) |
| `connect` leaves the archival vin arms to E4 | landed: `store/connect.rs:500–501` ("the archival vin arms — serve-credit bit, bond post, emission claim — are E4's hooks and write nothing here"); `ConnectFacts` is "minus E4's `archival_budget_accrual`" (`:161`) |
| `digest_v0` excludes `archival_*` | landed (`digest_v0.rs:23–30`, P0e / §7.1.1) — this increment moves no digest family |

The stated dependency is S-CHAIN-R (height and epoch context) and nothing
from a later surface. Unblocked on that ground.

---

## 2. Scope

### 2.1 In — the census, method by method

Eighteen methods (`blockchain_db.h`; declaration line in the table), every
caller outside the DB layer enumerated by `rg` at the pin and classified.
**Class** is what happens to the caller: *validator* (the C++ validation path
E6 replaces — here always a C++ marshal into a Rust verify FFI, the shape 4.J
rows describe), *RPC* (a served route or the submit facts FFI, whose Rust home
is `shekyl-daemon-rpc`), *alt* (the alt-chain / reorg path, E5 S-ALT's),
*retired* (dead by ruling, live in code, deleted at the named increment),
*log* (a diagnostic string only), *test-hook*.

| # | Method (`blockchain_db.h`) | Table read | Production callers (`blockchain.cpp` unless noted; enclosing function) | Class | Rust read |
|---|---|---|---|---|---|
| 1 | `get_archival_bond_value(p_id, out)` → `bool` (`:2186`) | `archival_bond[p_id]` | `:3920` `check_tx_inputs` (emission dispatch); `:4437` `compute_fcmp_verification_hash`; `:4506` `check_archival_bond_post_input`; `daemon_submit_ffi.cpp:204,380,392,552`; `archival_claim_source.cpp:41` | validator ×3, RPC ×5 | **A1** `bond_record(&PersonaId) -> Option<BondRecord>` |
| 2 | `get_archival_bond_hybrid_pubkey(p_id, out)` → `bool` (`:2181`) | `archival_bond[p_id]` (one field of #1's row) | `:4615` `check_archival_bond_post_input`; `:4801` `check_archival_serve_credit_input`; `:5167` `verify_block_attestation`; `daemon_submit_ffi.cpp:371` | validator ×3, RPC | **A1** (a projection of the record; no second read — SAR-1) |
| 3 | `archival_bond_join_epoch(p_id)` → `u64` (**`u64::MAX` when absent**) (`:2192`) | `archival_bond[p_id]` | `:4807` `check_archival_serve_credit_input` | validator | **A1** (`BondRecord.join_settlement_epoch`) |
| 4 | `archival_bond_good_through(p_id, epoch)` → `bool` (`:2190`) | `archival_bond[p_id]`; the fold is **already Rust** — `consensus_state::good_through` reached through `archival_bond_good_through_ffi` (`db_lmdb.cpp:5052–5058`, `:5062–5072`) | `:4816` `check_archival_serve_credit_input` | validator | **A1** + the existing Rust fold, called directly on `&BondRecord` (the C++ flatten-and-marshal dies — SAR-2) |
| 5 | `archival_bond_holds_shard(p_id, shard, at_height)` → `bool` (`:2188`) | `archival_bond[p_id]` **and `archival_slash_log`** — a C++ as-of-height fold (`archival_bond_holds_shard_of`, `db_lmdb.cpp:4889–4950`) that, for a shard not held at tip, range-scans the slash log strictly above `at_height` for a row that removed it (`archival_slash_removed_holding_after`, `:4804–4870`) | `:4874` `check_archival_serve_credit_input`; **and E4's slash writer** (`:5381`, slash eligibility inside `process_archival_slashes`) | validator; E4 | **A1 + A2** (`slash_log_after`) + the fold ported to `shekyl-archival-retention` — **`SAR-Q7` RULED: the port travels with E4's journal ruling; the finding is CEN-L16 now** (SAR-2, SAR-7) |
| 6 | `archival_bond_last_served_epochs(p_id, shards)` → `Vec<u64>` (`:2332`) | `archival_serve_credit` — one reverse seek per shard over `P ‖ BE64(shard) ‖ BE64(epoch) ‖ BE64(height)` (`db_lmdb.cpp:6464`) | `:4534` `check_archival_bond_post_input`; `daemon_submit_ffi.cpp:316`; `archival_claim_source.cpp:76` | validator, RPC ×2 | **A3** `last_served_epoch(&PersonaId, ShardId) -> Option<SettlementEpoch>` (per shard; the marshal's `Vec` is the caller's loop — SAR-3) |
| 7 | `archival_bond_all_last_served_epochs(p_id)` → `Vec<u64>` (`:2340`) | `archival_serve_credit` — `P`-prefix hop scan (`db_lmdb.cpp:6546`) | `:4533` `check_archival_bond_post_input`; `daemon_submit_ffi.cpp:315`; `archival_claim_source.cpp:75` | validator, RPC ×2 | **A4** `served_shards(&PersonaId) -> Vec<(ShardId, SettlementEpoch)>` (the CompleteTree form: every served shard with its last-served epoch) |
| 8 | `archival_serve_credit_pass_count(p_id, shard, epoch)` → `u32` (`:2135`) | `archival_serve_credit` — pair-epoch prefix count (`db_lmdb.cpp:4695`) | `:4794` `check_archival_serve_credit_input` (collapsed to `> 0`) | validator | **A5** `pass_count(&PersonaId, ShardId, SettlementEpoch) -> PassCount` |
| 9 | `get_archival_r_market(shard, epoch)` → `u64` (**0 when absent**) (`:2352`) | `archival_r_market[(shard, epoch)]` (`db_lmdb.cpp:7922`) | `:4657` `check_archival_bond_post_input`; `archival_shard_coverage.cpp:66` | validator, RPC | **A6** `r_market(ShardId, SettlementEpoch) -> Option<RMarket>` |
| 10 | `gather_archival_emission_epoch_snapshot(p_id, epoch, out)` (`:2372`) | `archival_bond`, `archival_serve_credit`, `archival_shard_segment`, `archival_sigma_work[epoch]`, `archival_budget[epoch]` — the one shared gather (`db_lmdb.cpp:7703`) | `:3932` `check_tx_inputs` (emission dispatch); `daemon_submit_ffi.cpp:574` | validator, RPC | **none — the gather shell is deleted** (§3.4 rule 3; SAR-4): its consumers compose **A1 + A5 + A7 + A8** and the `EmissionEpochSource` the Rust verifier already takes |
| 11 | `archival_shard_freeze_height(shard, out)` → `bool` (`:2311`) | `archival_shard_segment[shard]` (`db_lmdb.cpp:6401`) | `:4665` `check_archival_bond_post_input` (shard-age operand); `archival_shard_coverage.cpp:54` | **retired** (`PDM-Q12`; SAR-5) | none |
| 12 | `get_archival_shard_segment_at_height(shard, h, rk, count)` → `bool` (`:2193`) | `archival_shard_segment[shard]` (`db_lmdb.cpp:5085`) | `:4883` `check_archival_serve_credit_input` (the segment sub-root the challenge preimage is keyed on) | **retired** (`PDM-Q12`, and the verifier itself under `PDM-Q3`; SAR-5) | none |
| 13 | `get_archival_last_slash_epoch()` → `u64` (**`u64::MAX` when absent**) (`:2347`) | `properties["archival_last_slash_epoch"]` (`db_lmdb.cpp:5205`) | `:4537` `check_archival_bond_post_input`; `daemon_submit_ffi.cpp:208`; `archival_claim_source.cpp:112` | validator, RPC ×2 | **A9** `last_settled_slash_epoch() -> Option<SettlementEpoch>` |
| 14 | `get_archival_prune_watermark_epoch()` → `u64` (**0 when absent**) (`:2076`) | `properties["archival_prune_watermark_epoch"]` (`db_lmdb.cpp:7122`) | `:638` `pop_blocks`, `:2422` `handle_alternative_block`, `:6228` `check_against_checkpoints` — **all three are `MERROR`/`MINFO` string operands** | log | **none here** — the watermark is **S-PRUNE's** own receipt (`DRS_E1_SPRUNE.md`; SAR-6) |
| 15 | `get_archival_attestation_witness_at_height(h)` → `blobdata` (**empty when absent**) (`:2672`) | `archival_attestation_witness[h]` (INTEGERKEY; `db_lmdb.cpp:9097`) | `:1170` `switch_to_alternative_blockchain` (demoted block); `:2573` `get_block_attestation_witness` (RPC) | alt, RPC | **A10** `attestation_witness_at(BlockHeight) -> AtHeight<Option<AttestationWitness>>` |
| 16 | `get_archival_alt_attestation_witness(blkid)` → `blobdata` (**empty when absent**) (`:2704`) | `archival_alt_attestation_witness[blkid]` (`db_lmdb.cpp:9142`) | `:1192` `switch_to_alternative_blockchain` (promoted block) | alt | **E5 S-ALT's** (`SAR-Q5`) — an alt-block attribute stored beside `add_alt_block` |
| 17 | `store_archival_alt_attestation_witness(blkid, witness)` (`:2696`) | writes `archival_alt_attestation_witness` | `:2368` `handle_alternative_block`, in `add_alt_block`'s write txn | alt (**write**) | **E5 S-ALT's** (`SAR-Q5`) |
| 18 | `set_archival_serve_credit_bit(p_id, shard, epoch, height)` (`:2126`) | writes `archival_serve_credit` | `:4732` `regtest_inject_archival_serve_credit` (the regtest injector; the production writer is the connect hook, `blockchain_db.cpp` add_block's serve-credit arm — CEN-L14 site 1) | test-hook (**write**) | **E4's** — the writer and its test injector land together (§2.2) |

Two things the §5 row's count of 18 does **not** include and this increment
does not port, recorded so their absence is a decision: the sibling reads
`get_archival_sigma_work_milli(epoch)` (`:2353`) and `get_archival_budget(epoch)`
(the frozen close row, `:2354` region) are reached from `blockchain.cpp` only
*through* #10's gather, so the surface map credits them to the gather; with
the gather deleted they become this increment's **A7** `sigma_work(SettlementEpoch)`
and **A8** `budget(SettlementEpoch)` — two reads the census names by their
consumer, ported under the method they replace.

### 2.2 Out (named, so it is not scope shed by omission)

- **The writers.** Every `put_`/`set_`/`process_`/`revert_` on the archival
  tables (`blockchain_db.cpp:630–923`, the AFC-1 register's 34 cells;
  `db_lmdb.cpp` epoch close `:7703–7920`, slash `:5911–6042`, settlement
  `:6819`, bond folds `:5085–5300`) and the six pop-reversal journals
  (`archival_slash_log`, `_emission_claim_log`, `_bond_unbond_log`,
  `_bond_holdings_update_log`, `_bond_reinstate_log`, `archival_epoch_close_log`).
  **E4** (§7.5 table 2: CEN-L7 … L10, four L14 sites). Whether the journals
  survive as tables at all in redb — S-CHAIN-W made pop-ability "does
  `undo_log[h]` exist" (SCW-7), and a per-family revert log beside a
  per-height undo log is two answers to one question — is **E4's first
  question**, named here and not decided here (SAR-7). This increment leaves
  the six journal tables `Unshaped`.
- **The C++ marshals and their verify FFIs** (`check_archival_bond_post_input`,
  `check_archival_serve_credit_input`, the emission dispatch in
  `check_tx_inputs`, `daemon_submit_ffi.cpp`'s facts) — **E6 slice 8** adopts
  the verdicts behind the crate and E4 retires the marshalling
  (`DAEMON_REDB_STORE.md` table 3, 4.J).
- **The segment-freeze registry** (`archival_shard_segment`, CEN-L10) —
  retired by `PDM-Q12`; the two reads over it (#11, #12) are dead by ruling.
  Deletion of the C++ (the freeze at `db_lmdb.cpp:8035–8085`, the two reads,
  `archival_shard_coverage.cpp:54`, `shekyl_archival_frozen_segment_count`'s
  callers SCU-3 already named) is **E4's deletion surface**, with CEN-L10 →
  bucket 3 at that PR (SAR-5). The table stays `Unshaped` here and is
  **not** shaped: shaping a retired table is pre-provisioning (rule 21).
- **The alt-attestation witness pair** (#16, #17) — `SAR-Q5`; default E5
  S-ALT.
- **The prune watermark** (#14) — S-PRUNE's (SAR-6).
- **The RPC callers' moves** (`archival_claim_source.cpp`,
  `archival_shard_coverage.cpp`, `daemon_submit_ffi.cpp`) — they move when
  `shekyl-daemon-rpc` reads the redb store; not this increment's, and no
  daemon is built until the redb conversion is complete.

### 2.3 What E4 gets from this increment

The tables it writes, **typed**: `archival_bond[PersonaId] → BondRecord`,
`archival_serve_credit[ServeCreditKey] → Present`,
`archival_r_market[(ShardId, SettlementEpoch)] → RMarket`,
`archival_sigma_work[SettlementEpoch] → SigmaWorkMilli`,
`archival_budget[SettlementEpoch] → BudgetAtomic`,
`archival_attestation_witness[BlockHeight] → AttestationWitness`, and two
typed `properties` cells. E4 writes what these reads read.

### 2.4 What E6 slice 8 gets

The reads the re-keyed verdicts need, on `ReadSnapshot` and — for the rules
that are consensus — through `ChainView` once slice 8 names them
(`CHAIN_RULES_CRATE.md` G13: no recorded *body* crosses the view; a bond
record is recorded *state*, the class the view exists to carry).

### 2.5 What DRS-E2 gets

Nothing to compare yet — `digest_v0` excludes `archival_*` by design
(§7.1.1), and this increment does not add a digest family: a family over
tables no Rust writer fills is a MATCH over emptiness. The archival digest
coverage §7.1.1 gates E2's S-ARCH rows on arrives with **E4's writers**, not
with the reads.

---

## 3. The contract proposed for freezing (round 1)

### 3.1 Where the reads live

`rust/shekyl-chain-store/src/store/archival_reads.rs`, methods on
`ReadSnapshot`, faults through `chain_reads::cell`. No new handle, no new
error enum. The folds the C++ wraps around reads (#4, #5) live in
`shekyl-archival-retention`: `good_through` is already there
(`consensus_state.rs:105`); `holds_shard_at` is ported there **by E4** (`SAR-Q7` RULED), taking a
`&BondRecord` and the slash-log rows A2 returns.

### 3.2 The mapping — 16 reads and two writes, 10 reads (11 with A2)

| Read | Signature | Replaces | Semantics |
|---|---|---|---|
| **A1** | `bond_record(&self, p: &PersonaId) -> Result<Option<BondRecord>, StoreError>` | #1, #2, #3, and the record half of #4, #5 | `archival_bond[p]`, decoded. `None` is "no bond record for `p`" — the reachable state every caller tests for (`bond_present`, `record_exists`, `have_record`). A row that does not decode is `CellCorrupt`. The pubkey (#2) and join epoch (#3) are fields; the C++'s `u64::MAX` join epoch on absence (`db_lmdb.cpp:5074`) is gone by the type. |
| **A2** (`SAR-Q7`) | `slash_log_after(&self, p: &PersonaId, h: BlockHeight) -> Result<Vec<SlashLogEntry>, StoreError>` | the slash-log half of #5 | The rows of `archival_slash_log` at heights strictly above `h` whose persona is `p`, excluding epoch-marker rows (`db_lmdb.cpp:4804–4870`: the scan starts at `(h + 1, 0)`, and `h == u64::MAX` is `false` by construction so the start key cannot wrap — a bound the tuple key makes moot). The fold over them (`holds_shard_at(&BondRecord, ShardId, BlockHeight, &[SlashLogEntry])`) is the retention crate's. **Requires shaping `archival_slash_log`** — a journal whose fate is E4's first question (SAR-7); `SAR-Q7` RULED: not in this increment — A2 and the fold are E4's commit 1, the census row (CEN-L16) is this PR's. |
| **A3** | `last_served_epoch(&self, p: &PersonaId, shard: ShardId) -> Result<Option<SettlementEpoch>, StoreError>` | #6 (per shard) | The greatest `epoch` with any row under `P ‖ shard` — one reverse seek in the composite key's own order (§4). `None` is never-served, which the Rust fold already treats as "cooldown vacuously elapsed" (`blockchain_db.h:2332–2339`); the marshal's omission of never-served shards becomes the type. |
| **A4** | `served_shards(&self, p: &PersonaId) -> Result<Vec<(ShardId, SettlementEpoch)>, StoreError>` | #7 | The `P`-prefix hop scan: each served shard with its last-served epoch, one reverse seek per shard, never a full-table walk (`db_lmdb.cpp:6546–6650`). Empty for a persona that never served. |
| **A5** | `pass_count(&self, p: &PersonaId, shard: ShardId, epoch: SettlementEpoch) -> Result<PassCount, StoreError>` | #8 | Rows under the pair-epoch prefix; `PassCount(0)` when none. A `u32` in C++ (`PC-D5`); the newtype keeps the bound. |
| **A6** | `r_market(&self, shard: ShardId, epoch: SettlementEpoch) -> Result<Option<RMarket>, StoreError>` | #9 | `archival_r_market[(shard, epoch)]`. **`None`, not 0**: the C++ returns 0 on `MDB_NOTFOUND` (`db_lmdb.cpp:7929`) and every consumer then treats "no market row" as "zero co-holders", which is the absence-as-value class (SAR-8). A closed epoch with zero co-holders is a written `RMarket(0)`; an epoch that never closed is `None`. |
| **A7** | `sigma_work(&self, epoch: SettlementEpoch) -> Result<Option<SigmaWorkMilli>, StoreError>` | the gather's Σwork leg | Same shape and the same reason as A6 (`db_lmdb.cpp:7936–7950`, 0 on absence). |
| **A8** | `budget(&self, epoch: SettlementEpoch) -> Result<Option<BudgetAtomic>, StoreError>` | the gather's budget leg | The frozen close row. The C++ gather already distinguishes absent from zero here (`has_budget_row`, `blockchain_db.h:554–558`) — the one place the C++ got the class right, and the reason the whole gather must keep the distinction rather than lose it in a `u64`. |
| **A9** | `last_settled_slash_epoch(&self) -> Result<Option<SettlementEpoch>, StoreError>` | #13 | `properties["archival_last_slash_epoch"]` as a typed cell. `None` is "no epoch settled yet"; the C++ `u64::MAX` sentinel (`db_lmdb.cpp:5215`) is gone by the type. |
| **A10** | `attestation_witness_at(&self, h: BlockHeight) -> Result<AtHeight<Option<AttestationWitness>>, StoreError>` | #15 | `archival_attestation_witness[h]`. Two absences the C++ collapsed into one empty blob (`blockchain_db.h:2672–2676`: "an empty attestation set, or a pruned/never-written height"): `AboveTip` for a height the chain has not reached; `Recorded(None)` for a recorded block whose attestation set was empty (the writer stores no row for an empty witness — `:2696–2700`'s rule for the alt twin, and `add_block`'s for this one). Whether a *pruned* height reads as `None` or as a third state is S-PRUNE's to say when it deletes anything here (`DRS_E1_SPRUNE.md` §11 names the witness rows); until a prune exists the two states are exhaustive. |

The gather (#10) is **deleted, not ported** (SAR-4): its Rust consumer,
`emission_verify::EmissionEpochSource<'a>` / `ClaimantBondRecord<'a>`
(`shekyl-archival-retention/src/emission_verify.rs:204–236`), is already the
typed shape the verdict takes; E4 / slice 8 fill it from A1, A5, A7, A8 at the
call site, with the rows' immutability for a claimable epoch the gather's
comment asserts (`blockchain_db.h:2372–2384`) becoming a property of *which
rows exist*, not of a C++ routine.

### 3.3 Absence, faults, and what a read may not do — the S-TX discriminator applied

S-TX §3.3's rule: absence earns a type when its case carries caller-actionable
semantics; otherwise `Option`. Applied:

- **"No bond record" is a case, not a `false`.** Every one of #1's eight
  callers tests presence and branches on it (a bond post that finds a record
  is an update; one that finds none is a join). `Option<BondRecord>`.
- **"Never served" is a case** (A3, A4 empty): the release-cooldown fold's
  vacuous arm. `Option` / empty `Vec`.
- **"No market row" / "no Σwork row" / "no budget row" are cases the C++
  conflated with zero** (A6, A7; A8 excepted). The bond-post admission reads
  `r_market` for every held shard to price shard age (`blockchain.cpp:4657`);
  a shard whose epoch never closed and a shard with zero co-holders are
  different facts that today read identically as `0`. `Option`. What the
  *consumer* does with `None` is the rule's business (E6 slice 8), not the
  read's — the read's job is to stop erasing the distinction.
- **`u64::MAX` as "none"** (#3, #13) — gone by the type, as S-CHAIN-R did for
  `top_block_hash`'s `UINT64_MAX`.
- **An empty witness and an unwritten height** (A10) — two states the C++
  reported as one empty blob; typed apart.
- **What a read may not do:** synthesise 0 or `u64::MAX`, decode a bond record
  partially (no "pubkey-only" fast path — SAR-1), or walk the serve-credit
  table without a persona prefix.

### 3.4 Types this increment adds — and where they live (`SAR-Q2`)

The daemon store cannot depend on `shekyl-archival-retention` — it pulls
`shekyl-fcmp`, `shekyl-crypto-pq`, `shekyl-curve-generators`,
`shekyl-ct-balance` (`shekyl-archival-retention/Cargo.toml:17–27`), the same
graph that ruled `shekyl-curve-tree` out under `SCU-Q2`. Rule 18's written
rule (landed with S-CURVE): *a type both stores/crates need lives in
`shekyl-types`; the computation lives in the owning crate.* So the
**state-shaped** archival record types move to `shekyl-types`, and the
**folds** over them (`good_through`, `holds_shard`, interval arithmetic,
`release_cooldown`) stay in `shekyl-archival-retention`, which already owns
them (`bond_connect.rs:60–396`, `release_cooldown.rs`).

| Type | Shape | Home (default) | Why |
|---|---|---|---|
| `PersonaId` | `[u8; 32]` — the canonical `p_id` (`crypto::hash` in C++; `shekyl-archival-retention/src/id.rs` derives it) | `shekyl-types` (`hash32!` family) | Keys `archival_bond` and prefixes `archival_serve_credit`. The retention crate keeps the derivation; the store keys on the word. |
| `ShardId`, `SettlementEpoch` | `u64` newtypes | `shekyl-types` | Key components in four tables; `SettlementEpoch` already exists as a codec concept (`codec/settlement_epoch.rs`) — the newtype is where it belongs. |
| `BondRecord` | the persisted bond record: `hybrid_pubkey: Vec<u8>` (≤ 2048), `bond_spend_pk: Vec<u8>`, `endpoint: [u8; 32]`, `join_settlement_epoch`, `bonded_total_atomic: AtomicUnits`, `holdings: Holdings` (`ShardSet(Vec<ShardId>)` with per-shard `add_epochs`, or `CompleteTree`), `bad_intervals: Vec<BadInterval>` (≤ 256, **consensus-frozen**, `shekyl_types.h:1130–1141`), `claimed_settlement_epochs: Vec<SettlementEpoch>` (≤ 32, pinned to `W + 6`, `:1142–1151`), `first_paying_emission_height: BlockHeight` | `shekyl-types` (record); `BadInterval`, `ShardSet`, `HoldingsDescriptor` **already exist** in `shekyl-archival-retention` (`bond_connect.rs:60`, `bond_wire.rs:182,285`) — `SAR-Q2` asks whether they move down or the record is defined in terms of them from below | The C++ `ArchivalBondValue` v7 (`shekyl_types.h:1124–1470`, a 350-line hand codec) has **no Rust twin**; the store has nothing to decode into (SAR-9). `Canonical` codec via `shekyl-store-codec`. |
| `Holdings` | `enum { ShardSet { ids, add_epochs }, CompleteTree }` | with `BondRecord` | The C++ `holdings_kind` byte + two parallel vectors (`:1122–1123`, `:1137`) is one sum type; the parallel-vector invariant (`held_shard_ids.len() == shard_add_epochs.len()`) becomes unrepresentable. |
| `BadInterval` | **exists**: `consensus_state::BadInterval { start_epoch: u64, end_exclusive: u64 }` with `u64::MAX` as the open end (`consensus_state.rs:98–101`), consumed by `good_through` and `bond_connect` | moves to `shekyl-types` (`SAR-Q2`); **shape unchanged** | The fold consumes this shape and the FFI's flat pair layout mirrors it; re-shaping the fold's input is the retention crate's own change, not the store's. The zero-length clean-close marker and the header's warning are reproduced verbatim on the Rust side (SAR-10) — recorded, not fixed here. |
| `ServeCreditKey` | `(PersonaId, ShardId, SettlementEpoch, BlockHeight)` as a **tuple key**, component-wise order | daemon store (`ids.rs`) | The C++ packs `P ‖ BE64 ‖ BE64 ‖ BE64` into a 56-byte key for LMDB's one-key limit (`PC-D4`); redb's tuple key gives the identical lexicographic order (`SCU-Q3`'s precedent: remove the thing that needs pinning). The reverse seeks A3/A4 become `range(..).rev()` over the tuple. |
| `PassCount` | `u32` newtype | daemon store | `PC-D5`'s bound. |
| `RMarket`, `SigmaWorkMilli`, `BudgetAtomic` | `u64` newtypes (`BudgetAtomic` = `AtomicUnits`) | `shekyl-types` / `shekyl-units` | Three close-row scalars the C++ stores as `BE64`; typed so `Option<RMarket>` cannot be added to a height. |
| `AttestationWitness` | the witness blob, opaque to the store | `shekyl-types` (`shekyl-archival-retention/src/attestation_wire.rs` owns the parse) | Stored bytes; the store does not parse it. `Blob`, not `Coded`. |

### 3.5 What this surface inherits, and for how long

- **The 56-byte packed serve-credit key** — **not inherited** (tuple key; the
  comparator projects logical content, §7.6). Row order is preserved
  component-wise, so A3's reverse seek and A5's prefix count are the same
  walks.
- **`archival_bond`'s v7 byte layout** — **not inherited.** DRS-D8 (schema
  redb-native at engine swap, RECORD-AND-SPECIFY) applies; the record is
  re-specified as a `Canonical` codec with the **same field set** (B4
  results-fidelity) and the same consensus-frozen caps, and the two caps'
  `static_assert` twins in C++ (`shekyl_types.h:1137`, `:1149`) become the
  one Rust constant each already names (`bond_connect::MAX_BOND_BAD_INTERVALS`;
  the claimed-epoch cap derived from `max_claim_age_w`). One owner per
  constant.
- **The `properties` cells' string keys** — inherited as the cell's key
  (`"archival_last_slash_epoch"`), typed as the cell's value. The prune
  watermark's cell is S-PRUNE's and untouched.
- **`archival_settlement`** (SO-D8's per-`(P, shard, epoch)` settlement rows)
  — **not read from `blockchain.cpp`** (`set_`/`get_`/`delete_archival_settlement`
  are reached from the epoch-close hook inside `add_block`, `blockchain_db.h:2154–2170`),
  so it is outside the §5 row's 18 and stays `Unshaped` for E4. Recorded so
  the omission is a decision.

---

## 4. The read set, table by table

| Table | Key → value at v9 | After this increment (v10) | Read |
|---|---|---|---|
| `archival_bond` | `&[u8]` (32-byte `p_id`) → `Unshaped` | `PersonaId` → `Coded<BondRecord>` | A1 |
| `archival_serve_credit` | `&[u8]` (56-byte packed) → `Unshaped` | `(PersonaId, ShardId, SettlementEpoch, BlockHeight)` → `Present` | A3, A4, A5 |
| `archival_r_market` | `&[u8]` (`BE64 ‖ BE64`) → `Unshaped` | `(ShardId, SettlementEpoch)` → `Coded<RMarket>` | A6 |
| `archival_sigma_work` | `u64` → `Unshaped` (BE64) | `SettlementEpoch` → `Coded<SigmaWorkMilli>` | A7 |
| `archival_budget` | `u64` → `Unshaped` (BE64) | `SettlementEpoch` → `Coded<BudgetAtomic>` | A8 |
| `archival_attestation_witness` | `u64` → `Unshaped` | `BlockHeight` → `Blob<AttestationWitness>` | A10 |
| `properties["archival_last_slash_epoch"]` | `Blob<PropertyCellBytes>` | typed cell → `Option<SettlementEpoch>` | A9 |
| `archival_shard_segment` | `u64` → `Unshaped` | **unchanged — retired table** (`PDM-Q12`; E4 deletes) | none |
| `archival_alt_attestation_witness` | `LmdbHashKey` → `Unshaped` | unchanged (E5 S-ALT, `SAR-Q5`) | none |
| `archival_slash_log` | `&[u8]` (`BE(height) ‖ BE(seq)`) → `Unshaped` | **`SAR-Q7`**: `(BlockHeight, JournalSeq)` → `Coded<SlashLogEntry>` if A2 lands here; unchanged if deferred to E4 | A2 |
| `archival_settlement`, `archival_slash_applied`, `archival_budget_accrual`, the five other journals | `Unshaped` | unchanged — E4's writers shape them | none |

Layout `SCHEMA_VERSION` 9 → 10 (rule 42; the snapshot moves by exactly the
seven rows above — eight if `SAR-Q7` shapes the slash log here).

---

## 5. Store invariants this increment builds or restates

| Row | Statement | Armed where |
|---|---|---|
| **SI-14** | **A bond record's holdings are one shape.** `Holdings::ShardSet` carries exactly one `add_epoch` per shard id, in shard-id order, ids distinct — the parallel-vector invariant the C++ checked at decode (`shekyl_types.h:1335–1470`) made unrepresentable by the type; a row that decodes to anything else is `CellCorrupt`. | A1 (decode) |
| **SI-15** | **Serve-credit rows are keyed by persona.** Every `archival_serve_credit` key's `PersonaId` component has a bond record (`archival_bond[p]` exists) — the writer's precondition (the connect hook refuses a credit for an unknown persona, CEN-L7). Observed by A3/A4 as a walk that finds a prefix with no record. | A3, A4 |

Both register rows land with commit 1 (`STORE_INVARIANT_REGISTER.md`). No
invariant is stated over the close rows (A6–A8): whether "an epoch that
closed has all three rows" holds is E4's to assert when it writes them.

---

## 6. Round-0 findings

- **SAR-1 — one row, four reads, four absence values.** `get_archival_bond_value`,
  `get_archival_bond_hybrid_pubkey`, `archival_bond_join_epoch`,
  `archival_bond_good_through` all decode `archival_bond[p]`
  (`db_lmdb.cpp:4778`, `:4796`, `:5062`, `:5074`, `:4876`) and each invents
  its own absence: `false`, `false`, `u64::MAX`, `false`. Two callers read
  the same record twice in one function (`check_archival_bond_post_input`
  `:4506` then `:4615`; `check_archival_serve_credit_input` `:4801`, `:4807`,
  `:4816`, `:4874` — four decodes of one row). A1 is one read returning the
  record; the projections are field accesses.
- **SAR-2 — two reads are folds, and they are not the same case.**
  `archival_bond_good_through` decodes the record, flattens its intervals
  and calls the Rust fold through an FFI shim (`archival_bond_good_through_ffi`,
  `db_lmdb.cpp:5052–5058` → `shekyl_archival_good_through` →
  `consensus_state::good_through`, `consensus_state.rs:105`): the C++ is
  marshal, and with a Rust `BondRecord` the shim has no job.
  `archival_bond_holds_shard` is the other case: a **fifty-line C++
  consensus fold in the DB layer** (`archival_bond_holds_shard_of`,
  `db_lmdb.cpp:4889–4950`) implementing as-of-height holdings (P2B-7 Pin 5's
  `E_add + 1` rule; complete-tree back-to-join; the slash reconstruction) and
  reaching a second table to do it (`archival_slash_removed_holding_after`,
  `:4804–4870`, a range scan over `archival_slash_log`). Its comment says
  "storage adapters with no consensus logic" of the helpers three lines
  below it. This is the rule-20 finding on the surface: the fold ports to
  `shekyl-archival-retention` as `holds_shard_at(&BondRecord, ShardId,
  BlockHeight, &[SlashLogEntry])`, with the LMDB tests' as-of-height cases
  (`archival_substrate_lmdb.cpp:1674–1893`) as its Rust tests — when
  `SAR-Q7` says the log it reads is shaped.
- **SAR-3 — the per-shard marshal is the caller's loop.**
  `archival_bond_last_served_epochs(p, shards)` returns a `Vec<u64>` with
  never-served shards *omitted*, so the vector's length is not the input's
  and positions do not correspond (`blockchain_db.h:2332–2339` documents
  this). The Rust fold consumes the *set* of last-served epochs. A3 is per
  shard with `Option`; the set is the caller's `filter_map`.
- **SAR-4 — the gather shell is what §3.4 rule 3 said to delete.**
  `gather_archival_emission_epoch_snapshot` (`db_lmdb.cpp:7703–7920`)
  assembles a C++ struct from five tables so the FFI can marshal it into
  `EmissionEpochSource`, which is already the Rust verifier's input
  (`emission_verify.rs:218`). With typed reads on `ReadSnapshot`, the Rust
  caller fills its own struct; the C++ intermediary has no job.
- **SAR-5 — two reads and a table are dead by ruling, live in code.**
  `archival_shard_freeze_height` and `get_archival_shard_segment_at_height`
  read the segment-freeze registry `PDM-Q12` retired 2026-09-18 ("no chain,
  no successor object"); the freeze itself is CEN-L10 (`db_lmdb.cpp:8035–8085`),
  still a live bucket-1 row in the census. Their callers: `blockchain.cpp:4665`
  prices shard age off a freeze height the ruling says will not exist; `:4883`
  keys the serve-credit challenge on a segment sub-root, inside the verifier
  `PDM-Q3` kills; `archival_shard_coverage.cpp:54` serves it. **Disposition:**
  not ported; the table not shaped; E4's deletion surface, with **CEN-L10 →
  bucket 3** at that PR and the census's L10 row amended. SCU-3 named the
  same family's `frozen_segment_count` callers; this is the rest of it.
- **SAR-6 — the prune watermark is read only to be printed.** All three
  `blockchain.cpp` callers of `get_archival_prune_watermark_epoch` (`:638`,
  `:2422`, `:6228`) are `<<` operands in error/info strings. The cell is the
  retention prune's receipt (`blockchain_db.h:2076–2087`, "written by the
  prune itself … EXEMPT from pop reversal"), which is S-PRUNE's whole
  subject. Not this increment's.
- **SAR-7 — the journals are a question, not a table set — and one of them
  is not only a journal.** Six revert-log tables exist so a pop can undo
  archival writes per family (`ArchivalSlashRevertValue` …
  `ArchivalBondReinstateRevertValue`, `shekyl_types.h:594–1031`; the shared
  `BE(height) ‖ BE(seq)` helpers, `db_lmdb.cpp:4951–5040`). The redb store's
  pop already has one undo shape (`undo_log[h]`, SCW-7). Two mechanisms for
  one property is the question E4 opens with. **But the slash log is read
  forward as consensus history**, not only backward on pop: `holds_shard`'s
  "not held at tip ⇒ held at `h` iff a logged slash strictly above `h`
  removed it" (SAR-2) makes the log the *only* record of a shard's past
  tenure, and the log carries a second row kind besides — epoch-marker rows
  with a special `seq` (`entry.is_epoch_marker()`, `:4848`; "the slash log's
  epoch-marker special seq keeps its own bespoke loop", `:4962`). So E4's
  question is not "journals or `undo_log`" but "which of the six are
  *history* the read path needs, and which are pop-only" — and the slash log
  is already known to be the first kind. This increment neither shapes the
  six nor deletes them (`SAR-Q1`), except as `SAR-Q7` rules for the one.
- **SAR-8 — three close-row reads return `0` for "no row".** `r_market`
  (`db_lmdb.cpp:7929`), `sigma_work_milli` (`:7943`) — and the C++ gather
  itself contradicts them by carrying `has_budget_row` for the third
  (`blockchain_db.h:554–558`), which is the one place the codebase kept
  absent and zero apart. A6/A7 adopt A8's discipline: `Option`.
- **SAR-9 — the persisted archival records have no Rust type.** Seven hand
  codecs in `shekyl_types.h` (`ArchivalBondValue` v7 and six revert values,
  `:594–1491`), no `shekyl-types` or `shekyl-archival-retention` twin: the
  Rust side sees bond state only as FFI-marshalled arrays. This is the
  substrate fact that sizes the increment — the reads are small; the
  **record type and its codec** are the work (§3.4), and they are the first
  thing E4 needs.
- **SAR-10 — the interval log carries two entry kinds in one vector, and
  both sides of the FFI beg the reader not to check.** `shekyl_types.h:1153–1162`:
  a zero-length `start == end` entry is the Release "clean interval-close"
  marker, "never add a 'valid interval is non-empty' assertion here" — and the
  Rust twin repeats the sentence (`consensus_state.rs:95–97`). A comment
  defending an invariant against the next reader, twice, is a type asking to
  exist (`IntervalEntry { Bad { start, end_exclusive: Option<_> }, CleanClose(epoch) }`).
  **Not this increment's:** the shape is the fold's input and the fold is the
  retention crate's; the store records the field as the crate defines it.
  Forward-action to the retention crate's owner, recorded here (A5).
- **SAR-11 — the E2 bar on S-ARCH rows does not lift with the reads.**
  §7.1.1 bars E2 from acting on S-ARCH census rows until archival digest
  coverage exists; coverage means a digest family over tables a Rust writer
  fills. This increment fills none (§2.5). The bar lifts with E4, and this
  document says so rather than letting the reads' landing be read as
  coverage.

### 6.1 Reproduced deviations on this surface (DRS §7.6 item 1)

None. The four absence sentinels (SAR-1, SAR-8, `u64::MAX` join epoch and
slash epoch) are **not** reproduced (§3.3); the packed key and the v7 byte
layout are not inherited (§3.5).

---

## 7. Commit sequence (rule 90; one PR, ≤ 4 commits, cut from `dev` after §9 is RULED)

1. **Vocabulary and record shapes.** `PersonaId`, `ShardId`, `SettlementEpoch`,
   `BondRecord`, `Holdings`, `IntervalEntry`, `RMarket`, `SigmaWorkMilli`,
   `BudgetAtomic`, `AttestationWitness` per `SAR-Q2`'s ruling, with `Canonical`
   codecs; `ServeCreditKey` tuple key and `PassCount` in `ids.rs`; the seven
   tables re-typed in `schema.rs`; `SCHEMA_VERSION` 10; snapshot regenerated
   (rule 42); SI-14 in the register.
2. **The reads.** `store/archival_reads.rs`: A1, A3–A10; SI-15 armed; the
   `properties` cell typed; tests: empty store, planted rows, each `Option`
   arm, the SI-14 decode refusal, a `BondRecord` round trip at every cap
   (`MAX_BOND_BAD_INTERVALS`, the claimed-epoch cap), A3's reverse seek
   against a planted multi-epoch persona, A10's two absences — **and the
   cross-check that the round trip cannot give (ruled on PR #840):** a
   round trip of the new codec against itself proves it self-consistent;
   only a comparison against what LMDB actually holds proves it is the
   *same record*. Commit 1 captures a small corpus of real `ArchivalBondValue`
   v7 blobs (from `archival_substrate_lmdb.cpp`'s fixtures: compact and
   complete-tree holdings, an open bad interval, a clean-close marker, a
   full claimed-epoch set) as checked-in bytes with their C++-decoded field
   values beside them, and commit 2 asserts the Rust `BondRecord` decoded
   from each equals those fields. Cheap now, impossible once E4 deletes the
   C++ decoder — which is why the corpus is captured in this increment and
   not E4's.
3. **The fold.** `good_through` already takes `(join, epoch, &[BadInterval])`;
   a `BondRecord`-taking form beside it is one line. `holds_shard_at(&BondRecord,
   ShardId, BlockHeight, &[SlashLogEntry])` ported from `db_lmdb.cpp:4889–4950`
   + `:4804–4870` with the LMDB tests' as-of-height cases
   (`archival_substrate_lmdb.cpp:1674–1893`) as Rust tests — **this commit
   exists only if `SAR-Q7` rules A2 in**; otherwise the fold travels to E4 with
   the log.
4. **Docs** (rule 91): §5 row flip in `DAEMON_REDB_STORE.md`, index rows,
   `STORE_INVARIANT_REGISTER.md`, this file's status; the census's CEN-L10
   row gains the `PDM-Q12` note pointing at E4's deletion.

---

## 8. Denominator — what must stay green, what must be extended

- `check_chain_rules_no_store.sh` (the rules crate reaches no store).
- Rule-42 schema snapshot: **must move**, and only by the seven tables +
  version (the gate's diff is the review). **Arming checked 2026-09-23:**
  layout 10 is this lane's fourth bump (6 → 7 at slice 2's commit 9, the tx
  side's, S-CURVE's 8 → 9), and a gate whose subject exists only on bump
  commits decays quietly between them — so it was checked in the failing
  direction rather than assumed: `ci/schema-snapshot`'s *Assert committed
  schema snapshots* leg went red on 2026-09-22 (`feat/delete-cxx-tx-data-prune`)
  and its *Enforce paired block_version bump* leg on 2026-09-21
  (`refactor/rebond-to-reinstate`), both on real bump commits. Fresh, not
  hypothetical; re-check at the next bump the same way (`gh run list
  --workflow schema-snapshot.yml --status failure`).
- `check_conformance_coverage.py`: no register row is touched — the archival
  reads are storage; the rules stay where they are (4.J, slice 8).
- `check_lmdb_schema_coverage.py`, `check_archival_forcing_cells.py`: the
  LMDB side is untouched by this increment (no C++ changes), so both are
  unchanged; recorded so a red there is known to be someone else's.
- `check_store_unlock_time_projection.py`: unchanged.
- E2's `pipeline_tests` and `digest_read_tests`: unchanged in outcome
  (SAR-11); they are the belt that proves it.
- `cargo test -p shekyl-archival-retention` grows by commit 3's fold tests.

---

## 9. Round-1 questions — RULED 2026-09-23 (maintainer, on PR #840; each row line-local)

| Q | Question | Ruling | Why |
|---|---|---|---|
| **SAR-Q1** | Does this increment shape only the seven tables its reads touch (§4), leaving the journals, `archival_settlement`, `archival_slash_applied`, `archival_budget_accrual` and the retired `archival_shard_segment` `Unshaped` for E4 — or shape all seventeen now? | **RULED: default held** — **Seven.** | A shape with no reader and no writer is pre-provisioning (rule 21); the journals' *existence* is E4's first question (SAR-7), and shaping a retired table (SAR-5) is worse than leaving it. S-CURVE left `curve_tree_checkpoints` `Unshaped` on the same ground. |
| **SAR-Q2** | Where do the record types live: move `BadInterval`, `ShardSet`, `HoldingsDescriptor` from `shekyl-archival-retention` down to `shekyl-types` and define `BondRecord` beside them — or define `BondRecord` in `shekyl-types` with its own `IntervalEntry`/`Holdings` and have the retention crate convert? | **RULED: default held** (an application of rule 18 as written at `SCU-Q2` rather than a ruling — the rule doing its job on its fourth instance) — **Move down.** | Rule 18 as written at `SCU-Q2`: one definition, both crates. A conversion layer between two spellings of the same interval is CTS-3 reborn. The retention crate keeps every fold; it loses three struct definitions and gains `use shekyl_types::…`. |
| **SAR-Q3** | Is `BondRecord`'s codec a re-specified `Canonical` (same fields, redb-native layout, DRS-D8) — or a byte-for-byte port of `ArchivalBondValue` v7? | **RULED: re-specified — approved with one word checked: "same fields, same frozen caps" means same *semantics*, not byte-compatible.** Byte-parity with LMDB was never the constraint (the comparator projects; `zerokval` already diverges); a 350-line hand codec becoming a `Canonical` impl is the work, and it is free to choose its encoding. | Nothing hashes or relays the stored record (the wire record is `bond_wire.rs`'s, a different object); byte-parity with LMDB was never the constraint (§7.6, `zerokval`, `SCU-Q3`). The v7 layout carries a `holdings_kind` byte plus two parallel vectors that the sum type retires (SI-14). B4 results-fidelity: same field set, same caps, one owner per cap constant. |
| **SAR-Q4** | The gather (#10) is deleted (SAR-4, §3.4 rule 3). Does the store also offer one composed convenience read — `emission_epoch_source(p, epoch)` assembling A1 + A5 + A7 + A8 into the retention crate's `EmissionEpochSource` — or do E4 / slice 8 compose it at the call site from the primitive reads only? | **RULED: default held** — composition belongs to the caller; a composed read would put the composition in the store — **Primitives only; no composed read.** | A composed read is the gather shell with a Rust accent: it fixes *which* rows a claim needs inside the store, which is the verdict's knowledge, not the store's (`emission_verify.rs` owns `EmissionEpochSource`). The five-table "immutable for a claimable epoch" argument (`blockchain_db.h:2372–2384`) is a property the rule states about the rows it reads; the store's job is to return them typed. Reopens if two production composers appear and disagree (rule 21). |
| **SAR-Q5** | Do the alt-attestation witness pair (#16 read, #17 write) land here as an archival read, or with E5 S-ALT as an alt-block attribute? | **RULED: default held** — **E5 S-ALT.** | The row is written in `add_alt_block`'s transaction and read only by `switch_to_alternative_blockchain`; it is an attribute of an alt block that happens to live in an `archival_` table. S-ALT owns the alt block's shape; splitting one alt-block attribute across two increments is the god-object-by-table-name error the §5 map warns against. |
| **SAR-Q6** | A6/A7 return `Option` (§3.3, SAR-8). The C++ consumers treat `0` and absent identically today. Does the increment also record, for E6 slice 8, that the *rule's* treatment of `None` is an open question — or is that slice 8's own pre-flight's to find? | **RULED: record it here, decide it there — and the `Option` is load-bearing independent of the ruling.** The store returning `Option` is what makes slice 8's decision *possible*: had it returned `0` as the C++ does, "is absence the same as zero co-holders?" would be unaskable from the Rust side, the distinction destroyed at the read. Recording the question here and deciding it in the rules slice is the S15 / FL-R16c shape done right the first time. | The read stops erasing the distinction; what a bond-post admission does when a held shard's epoch has no market row is a consensus question with a spec owner (`ARCHIVAL_CONSENSUS_STATE.md` §3.3–3.5), not a store's. A5-shape forward-action: named in slice 8's inherited list by this PR's docs commit. |
| **SAR-Q7** | `holds_shard` (#5) needs the slash log (A2) and its fold. Land A2 + the fold here — shaping `archival_slash_log` (`SlashLogEntry`, the epoch-marker row kind, the `(height, seq)` tuple key) ahead of E4's journal ruling — or defer the pair to E4, where the log's shape is decided with the other five? | **RULED: defer the *port*, not the *row*.** Deferring the read and fold to E4 is right for this increment. But the *finding* — a consensus predicate computed inside the store layer (`db_lmdb.cpp:4889`: folds `held_shard_ids` against `shard_add_epochs`, calls `shekyl_archival_settlement_epoch_at_height`, FATAL on desync at `:4943`) with no R8 row — belongs in the census **now**, as **CEN-L16**. C2-R8 established that the store computes nothing consensus-visible, and its eight L-rows were all drawn from `add_block` / `pop_block`; `holds_shard` is a *read*, and the sweep did not cover reads — the category test applies, the enumeration behind it does not reach here. Carried only as an E4 deferral, the R8 gap travels with it and nobody sees the pattern. Third instance this month of a sweep whose subject excluded the finding's surface (slice 4's S25 shims, slice 5's `shekyl-wire` constants, R8's store reads); the census lane is asked one question rather than three (`FOLLOWUPS.md`, the sweep-subject row). | The read's two consumers are the C++ verifier `PDM-Q3` kills and E4's own slash writer (`db_lmdb.cpp:5381`); its re-keyed Rust successor is slice 8's to state. Shaping the log now pre-decides E4's question (SAR-7) for one of six tables from the read side; deferring keeps the decision with the increment that writes the rows and knows whether epoch markers survive. **Named blocker, falsifier:** blocked on E4 Round 0's journal ruling — falsify by that ruling landing, at which point A2 and `holds_shard_at` are E4 commit 1. Recorded as STAGED with E4 named (rule 23); the C++ fold stays live until then, as every other C++ marshal on this surface does. |

---

## 10. Documentation owed by the increment (rule 91)

- `DAEMON_REDB_STORE.md` §5: S-ARCH row → LANDED with the mapping and the
  gate re-read; §7.5 table 2's E4 rows gain "shapes minted by E1 S-ARCH".
- `IMPLEMENTATION_INDEX.md`: `SAR-` / `SAR-Q` rows lead with status; this
  document's row.
- `STORE_INVARIANT_REGISTER.md`: SI-14, SI-15.
- `CONSENSUS_RULE_CENSUS.md`: **CEN-L16 minted by this PR** (Q7 as ruled: the
  row now, the port with E4) — §4.L row, counts 174 → 175 / 165 → 166 / bucket 1
  88 → 89, §7 #23; `CONSENSUS_STORE_RECONCILIATION.md` row UNREVIEWED by
  construction (register 126 / 2 / 5); `shekyl-chain-rules` `CenRow::L16`
  pending (154 rows); `CHAIN_RULES_CRATE.md`'s figure; `DAEMON_REDB_STORE.md`
  §7.5 re-derived (21 of 175 store-bound; 154 = 14 + 140; table 2 row). CEN-L10's
  row notes `PDM-Q12` and the E4 deletion (SAR-5); no bucket move until E4
  deletes the code.
- `CHAIN_RULES_SLICE_8` (when scaffolded) inherits `SAR-Q6`'s forward-action;
  until then it is recorded in `DAEMON_REDB_STORE.md` table 3's 4.J row.
- `18-type-placement.mdc`: no change — the rule already covers this instance
  (`SCU-Q2`'s general form); this document cites it.
- CHANGELOG: one entry (schema layout 10; the typed archival reads; the
  bond record's Rust type).

---

## 11. Decision log

| Date | Entry |
|---|---|
| 2026-09-23 | **Three carries into the increment** (maintainer, PR #840, after the rulings): **(1)** the v7 cross-check corpus — real `ArchivalBondValue` blobs decoded by the C++ reader, asserted equal to the Rust `BondRecord` (§7 commit 1/2), because a self round trip proves self-consistency and not identity, and the C++ decoder E4 deletes is the only oracle; **(2)** the schema gate's arming verified in the failing direction, not assumed (§8); **(3)** S-PRUNE's dependency on `PDM-Q11`'s provisional `D_max` moved onto that skeleton's banner (`DRS_E1_SPRUNE.md`), because a watermark fixed before the constant is confirmed is picked by implementation convenience — R8's shape. |
| 2026-09-23 | **Round 1 RULED** (maintainer, PR #840). Q1, Q2, Q4, Q5 held (Q2 an application of rule 18, not a ruling; Q4 because `EmissionEpochSource` already exists and composition is the caller's). Q3 approved with the word checked: same *semantics*, not byte-compatible. Q6 approved, with why the `Option` is load-bearing regardless of slice 8's answer. **Q7 amended: defer the port, not the row** — CEN-L16 minted in this PR; the R8 sweep gap and its two siblings (slice 4 S25, slice 5 shard-set bound) folded into one census-lane question on the existing FOLLOWUPS row. **Process note acted on:** the §5 row's eighteen-day stale gate is the `DEFERRED_DOCS` self-expiry shape applied to plan-row blockers; measured over `docs/design/*.md` table rows — 119 blockers, 45 naming an identifier a gate could resolve, 74 prose — so it is a wish until blockers take rule 22's `blocked on <ID> — falsify by <check>` form; a FOLLOWUPS row proposes the lint (owner `DAEMON_REDB_STORE.md` §5). |
| 2026-09-23 | **Round 0 executed** at `d8ebfd18c`. Eleven findings (SAR-1 … SAR-11); seven questions posed with defaults (SAR-Q1 … Q7). The surface's eighteen methods map to ten Rust reads: two are dead by ruling (SAR-5), one is a log operand and S-PRUNE's (SAR-6), two are E5 S-ALT's (`SAR-Q5`), one is E4's test hook, one is the gather shell §3.4 rule 3 said to delete (SAR-4), one wraps a fold that is already Rust behind an FFI shim, and one is a C++ consensus fold in the DB layer that reads the slash log as history (SAR-2, SAR-7) — its port travels with E4's journal ruling by default (`SAR-Q7`). The substrate fact that sizes the increment is SAR-9: the persisted bond record has no Rust type. The §5 row's gate was found lifted eighteen days before this read (rule 22). |
