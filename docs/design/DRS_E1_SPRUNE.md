# DRS-E1 S-PRUNE — the retention prune: plan-doc skeleton (`PDM-Q-F31`)

**Status:** OPEN — **SKELETON, not a plan.** Written 2026-09-18 at
`dev@20ebdf1e5` by the pruning charter's lane
([`ARCHIVAL_PRUNED_DAEMON_MODE.md`](ARCHIVAL_PRUNED_DAEMON_MODE.md),
`PDM-Q-F31`) for the **DRS-E lane to fill**: every section below names the
contract it consolidates and where that contract is ruled, so that the
three homes the prune's obligations are scattered across today (`PDM-Q-F10`,
`PDM-Q-F26`/`F32`, `SCW-7`) become one document before the first increment
is cut (rule 26: design closure precedes any cut; E1 got
[`DRS_E1_SCHAIN_W.md`](../completed/DRS_E1_SCHAIN_W.md) before its writers).
**Nothing here is proposed as new design**; where a section's contract is
not yet ruled it says so and names the question. The increment ordinal and
the Round-0 pre-flight are DRS-E's; the filename is provisional until DRS
numbers the increment (`FOLLOWUPS.md`'s F31 row is the falsifier). **The
Q1 gate is cleared:** `PDM-Q1` RULED 2026-09-18 (§9 of the charter graded
against the tx unit), so the plan **may open**; its Round-0 pre-flight owes
Q1's journal-horizon check alongside (§9 below).

**Family:** none minted here. Findings and questions this document raises
at pre-flight take DRS-E's next free series (rule 94 §1), not a `PDM-` id.

---

## 1. Charter

S-PRUNE is the **Rust-only successor to the Monero-era stripe engine**, per
`PDM-Q-S0` (no C++ landing before the cutover) and `PDM-Q7` (**RULED
2026-09-18: the engine is removed completely; nothing of it survives as
design**; **the C++ engine was deleted 2026-09-21**, `feat/pruning-seed-wire-deletion`,
with both flags and the `pruning_seed` wire field — `S0` forbids
*implementing* in C++, not deleting, and the wire half did not die with the
store). Not an extraction and not a port: four of its six methods were
the stripe engine and are gone; `prune_tx_data` (Shekyl's C++ tx-data
discard, a different mechanism) dies at `DRS-E*` with the store;
`PDM-Q-F17`'s triple — assignment /
advertisement / coverage — is **not** read from, because each has a
successor that is not the engine (the bond, the bond, price). S-PRUNE reads
nothing from `src/common/pruning.{h,cpp}`. [`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md)
§7's S-PRUNE row is **NOT EXTRACTED** for that reason and already carries two
contracts (§5 below) with no home; this document is the home.

## 2. The predicate

`PDM-Q2` (RULED 2026-09-18, shape), verbatim:

> Shard `k` — a byte-bounded `tx_id` range `[b_k, b_{k+1})` (`PDM-Q-F32`) —
> has its prunable regions and `pqc_auths` discarded **atomically, as a
> whole**, iff `b_{k+1} ≤ first_tx_id(tip − W)` **and**
> `close_height(k) + SEB < tip`.

*(The `k ∉ exceptions` conjunct of the first draft is struck — `PDM-Q9`
RULED on PR #775: the daemon holds no retention exceptions; **all daemons
prune uniformly**. There is no per-daemon input to this predicate.)*

**Enforcement point:** the per-epoch batch that advances the watermark.
Asserted there, never discovered downstream — a violated predicate is a
refused discard, not a corrupted write. `first_tx_id(h)` is
`block_info[h−1].cumulative_tx_count` for `h ≥ 1` and **`first_tx_id(0) = 0`**
(FL-R3-STORE, `BlockInfo`, landed on #772); `close_height(k)` is
`height(b_{k+1} − 1)` — the last **included** transaction's height, since
`b_{k+1}` is the first of `k+1` and need not exist yet — a binary search
over the same running total. No new state for either. **Genesis guard:** the batch evaluates the predicate
**only when `tip ≥ W`**; while the chain is younger than `W` no shard
discards. `tip − W` is never formed by saturating arithmetic — the store's
`BlockHeight − BlockCount` panics on this boundary, and that is correct: a
launch-window discard is a bug, not a zero (Q2, amended on review).

## 3. Three horizons, one constant

| Horizon | Retires | Value | By |
| --- | --- | --- | --- |
| Bodies (prunable + `pqc_auths`) | `W` | `CRB + n·SEB + D_max` ≈ 140,720 (PROVISIONAL) | `PDM-Q2` |
| Pop-undo journal | `≥ D_max` | 720 (PROVISIONAL) | `SCW-7` / `PDM-Q11` |
| Slash log and the six other window-retired journals (`PDM-Q-F16`) | `tip − (CRB + n·SEB + D_max)` | = `W` | `PDM-Q-F19` |

**State which are equal by ruling and which by coincidence.** Bodies and
journals are equal **by ruling** (Q2 chose F19's floor *so that* they are one
horizon); the undo floor is a **lower bound** on both (`W ≥ D_max`, F10) and
is not the same number. A Round-2 re-pin that moves `W` below the journal
floor separates the first two and this table records that it did.

## 4. No retention exceptions — the archiver's store is the wallet's

`PDM-Q9` RULED 2026-09-18 on PR #775 (`PDM-Q-F33`): the daemon holds
archival **consensus** state only and **no archival serving state, ever**;
the fingerprint criterion is *persistent, posture-correlated*; **all
daemons prune uniformly**. The daemon-storage candidate this section was
first written for — `retain(k)` / `release(k)` over the operator leg — is
**REJECTED and withdrawn**. S-PRUNE therefore has **no exception set, no
operator input, and no per-node state**. The archiver's shards live in the
**wallet-side store** (`shekyl-curve-tree`'s store rebuilt around bodies,
served by `shekyl-p-serve`; PR #775's two-stores-by-obligation). **The
specified-to-scarce window is when the wallet fills that store from the
local daemon:** shard `k` closes at `b_{k+1}`; the archiver's wallet pulls
`k`'s bodies over the operator leg through the ordinary split transaction
read (`PDM-Q10`) while its daemon still holds them in-window; S-PRUNE then
discards `k` at `W` on that daemon like every other. After the window,
acquisition is an episodic daemon fetch from another archiver (the daemon
retains nothing). Lapse is the wallet-side store's (#775's FOLLOWUPS row).
Unbonded retention (`PDM-Q7`) lives in the same wallet-side store, never
the daemon.

## 5. Store contracts in force

- **The store invariant: three legs landed, a fourth owed.**
  `DAEMON_REDB_STORE.md` §7.7 as it stands (F26, landed with A3 on #772):
  (i) hash row ⇔ 4-part txid, permanent, written at connect, never deleted;
  (ii) segment present ⇒ hash row present; (iii) hash row ∧ segment absent ⇔
  *discarded* — below `W`, or never held (band 1) — one store state with
  one meaning. **Owed with S-CHAIN-W amendment A4 (`PDM-Q-F32`), not yet
  in §7.7:** (iv) the length rows, **pairwise** — prunable-length row
  present ⇔ `txs_prunable_hash` row present; `pqc_auths`-length row
  present ⇔ `txs_pqc_auth_hash` row present. The plan may not present
  (iv) as in force until A4 lands.
- **Hash rows and length rows are outside every prune surface**, permanent.
  `txs_prunable_hash` (exists), `txs_pqc_auth_hash` (A3, #772), the two
  `u32` length rows (A4, owed).
- **`StoreCannot::PopBelowFloor`** as the pop refusal; the undo-log
  watermark `≥ D_max` (SCW-7, landed).
- **Body-absent is one state** for discarded and never-held; S-PRUNE writes
  nothing to mark the difference and reads nothing that depends on it.

## 6. `PDM-Q3`'s instrument

`ChainView` exposes no recorded-body accessor (`PDM-Q-F29`;
[`CHAIN_RULES_CRATE.md`](CHAIN_RULES_CRATE.md) §13). **S-PRUNE adds none.**
Any body read S-PRUNE itself needs (the batch reads segment presence, not
bytes) is on its own trait, marked above-`W`, and never reachable from
`shekyl-chain-rules`. Falsifier: a `ChainView` method returning recorded tx
bytes with no `CenRow`, or an S-PRUNE type imported by the rules crate
(`check_chain_rules_no_store.sh` is the belt).

## 7. What S-PRUNE does not do

Never touches `spent_keys`. Never touches a hash row or a length row.
**Never varies per node** — inside or outside `W` (`PDM-Q7`/`Q8`/`Q9`,
#775's corollary: all daemons prune uniformly; there are no exceptions on
any daemon). Never advertises: what a node retains reaches no wire (`PDM-Q8`, serve-side
uniformity); the bond is the advertisement.

## 8. Falsifiers

Q2's six (a shard discarded whose `b_{k+1} > first_tx_id(tip − W)`; **at or
before** `close_height(k) + SEB` — the predicate is strict `<`, so equality
is also red; a shard *retained* past its discard on any daemon;
partially; a second window constant not `W` by reference; `W < D_max`),
SCW-7's one (`undo_log` retention `< D_max`), F29's one (§6), plus: any
durable archival serving state on a daemon — a body past `W`, a persona
id, a retention list (#775 / Q9); and a discard that runs while the
serve-credit admission verifier still derives `R_k` from a frozen segment
(§11).

## 9. Sequencing

`PDM-Q1` RULED 2026-09-18 — §9 is graded against the tx unit, so the
retained set is known and the plan **may open**. Its Round-0 pre-flight
owes Q1's one implementation item first or alongside: the journal horizon
asserted at the journals' retirement site (F19's "the check"). Its first increment cannot land before: `#772` (A3, the second
hash row, `cumulative_tx_count`); A4 (the length rows); and §11's
precondition.

## 10. Replay and the digest (`DRS-D10`, `DRS-D11`)

- **Replay from the skeleton is load-bearing** (`PDM-Q-F13`, now a ruling's
  ground): every leaf-derivation input is in the unprunable base, so
  `apply_block` replay rebuilds every derived table without a byte from
  either discarded region. S-PRUNE's existence is what makes that claim
  testable — the negative control is a replay over a store S-PRUNE has run
  on. `PDM-Q6`'s reversion (b) is the falsifier.
- **`W` enters the digest domain as the accumulator's floor** (DRS-0a,
  `DAEMON_REDB_STORE.md` §11.2: a uniform discard yields a floor-defined
  accumulator; PDM hands DRS the boundary `W`, not `Excluded` re-grades).
  Pre-cutover the digest runs over the full chain on both sides and the
  `AppendMostly` running hash is already over the permanent rows; `W`
  enters only when this surface does.

## 11. The serve-credit transaction and the verifier precondition

- **Pass records fall under the predicate.** A serve-credit transaction's
  prunable region holds its pass records (`RF-D1`, `PDM-Q-F15`); below `W`
  it is discarded like any other. Any settlement, slash or reward read of a
  pass record after `W` is a band-2 read — the SO contact (`PDM-Q-F26`;
  `ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md`). SO states per read which it is.
- **Precondition, not a section to fill:** S-PRUNE **cannot discard a
  shard while a live verifier derives `R_k` from its frozen segment.** The
  serve-credit admission verifier signs two verifier-derived leaf terms
  today (`wire.rs:345-360`; `blockchain.cpp:5085-5125`); `PDM-Q6` item 4
  row 1 reopens it as consensus and lands its tx-unit restatement at E4 /
  S-ARCH. Until that lands, the first real discard is refused by §8's last
  falsifier.

## 12. Named inputs

| Input | Value / source | Status |
| --- | --- | --- |
| `W` | `CRB + n·SEB + D_max`, via `shekyl_archival_failure_window_params` | PROVISIONAL, Round-2 gate |
| `D_max` | 720 | PROVISIONAL, Round-2 gate (`PDM-Q11`) |
| `SEB` | `settlement_epoch_blocks = 10,000` | pinned |
| `SHARD_BYTES` | 3.33 MB (`RF-D6`'s, as the boundary metric) | ruled (`PDM-Q-F32`) |
| Length rows (A4) | two `u32` per tx, sparse | **owed** to S-CHAIN-W |
| `b_*` | derived from the length rows, binary-searched | derived, never received |
| `first_tx_id(h)` | `BlockInfo.cumulative_tx_count`; `first_tx_id(0) = 0`; evaluated only for `tip ≥ W` | landed on #772 |
| `w_launch` | flat in-window commitment weight before any shard is scarce; superseded by the derived scarce-set median at the first `discard(k)` | **reward leg's** (Q6 item 3 amendment, routing note) — a fourth numeric on the Round-2 gate; not S-PRUNE's to compute, but S-PRUNE's `discard(k)` event is what defines the *scarce set* the median is over |

## 13. C++ deletions and their timing

`process_archival_segment_freezes_at_height`, `archival_shard_segment`,
`frozen_segment_count`, `get_archival_shard_segment_at_height`,
`SEGMENT_LEAF_COUNT` (`PDM-Q12`) **die at `DRS-E*`** with the C++ store,
under `PDM-Q-S0`. The stripe engine's four methods (`check_pruning`,
`get_blockchain_pruning_seed`, `prune_blockchain`, `update_pruning`;
`PDM-Q7`), `src/common/pruning.{h,cpp}`, `CRYPTONOTE_PRUNING_*` and
`--prune-blockchain` **were deleted 2026-09-21** — gated by
`scripts/ci/check_no_stripe_engine.sh`; `prune_tx_data` stays until the
store goes. Not touched by this surface's increments. The `u32` seed
arithmetic (`PDM-Q-F17`) is **not** read from — `PDM-Q7` refuted the triple;
the holdings advertisement is the bond. `--sync-pruned-blocks` **was deleted
with them (2026-09-21), under `PDM-Q5`'s rejection**
(trust-the-txid with no anchor), recorded on its own FOLLOWUPS row so the
reason outlives the engine.
