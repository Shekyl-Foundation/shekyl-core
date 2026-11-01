# DRS-SB — the daemon below the body horizon

**Status: RULED 2026-10-31, BUILT 2026-11-01** (Rick, on #1233; the code
increment `SB-Q2` on #1239) — Round 0 posed and ruled the
same day: `SB-Q1`…`SB-Q8` RULED, `SB-F1`…`SB-F7` recorded. Round 0 is
closed. This document is now the contract for the `DRS-SB` node: the
rulings as they bind, the register of what lands where (§3), and the
findings that drove them. The pre-ruling recommendations are in git at
`4836afc2e5`, cited by sha, not kept here.

**Parent:** [`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) §7 — the `DRS-SB`
node between `DRS-X` and the D2 diamond, and its row (:1418). The design
it was minted to build is
[`ARCHIVAL_PRUNED_DAEMON_MODE.md`](ARCHIVAL_PRUNED_DAEMON_MODE.md) (`PDM-Q*`,
LIVING CONTRACT), which this round amends at `PDM-Q10`.

**Ground:** `dev@8c4f8fed88`, 2026-10-31. Line numbers carry that sha;
re-verify before relying on one. PR [#1212](https://github.com/Shekyl-Foundation/shekyl-core/pull/1212)
(the DRS-X flip) read at `eeef5f6cbf`; "at the flip" means that PR's merge.

**Families:** `SB-Q` (questions) and `SB-F` (findings), registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 (rule 94). Not to
be confused with `PDM-Q-S0`, a `PDM-Q` token.

**Process:** [`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
Round 0, zero code. Rule 21 shapes every ruling; rule 23 governs what each
leaves in the tree. **Edit rule for the re-tenses this round orders
(`SB-Q4`, `SB-Q5`):** each live sentence is edited in place to what is true
now; the pre-ruling text is **not** kept as records-was inside a living
design document — history is in git, cited by sha. Rule 91's records-was
is for shipped and dated records, not living contracts.

---

## 0. What this round settled

The `DRS-SB` node was minted 2026-10-10 to build set-B discard in the Rust
daemon. S-PRUNE built it on 2026-09-25 ([`DRS_E1_SPRUNE.md`](DRS_E1_SPRUNE.md)
§14; `rust/shekyl-chain-store/src/store/prune.rs`): at every boundary
`E·SEB`, `E ≥ 2`, inside the block's own transaction, the store discards
`D(E) = { k : close_epoch(k) + 2 ≤ E ≤ close_epoch(k) + 3 }` —
`txs_prunable` and `txs_pqc_auths` for every transaction of those shards —
and retires the journals and per-epoch tables at their own floors. It is
`PDM-Q2`'s predicate: no per-daemon input, no exceptions (`PDM-Q9`), the
genesis guard a branch, every epoch comparison additive, idempotent across
a boundary reorg; the ruling's falsifiers are tests
(`prune_tests.rs`: `epochs_zero_and_one_run_no_batch`,
`the_hook_is_idempotent_across_a_boundary_reorg`,
`pruned_and_unpruned_stores_place_every_shard_alike`,
`consecutive_boundaries_and_every_batch_match_the_model`). `PDM-Q-S0`
forbade implementing in C++; nothing was.

So the node owns **the daemon's contract below the body horizon**
(`SB-Q1`): the skeleton as the one pruned form on every surface, the
`archived` slot for a full-form request past the horizon, the operator
refusals, and the re-tenses of the statements that still describe the
discard as pending. Nothing of the discard itself is rebuilt.

**Out of scope, by prior ruling, not reopened:** the archiver serving-store
rebuild (`PDM-Q12`, `WSS-`); cold sync and the skeleton band (`PDM-Q5`,
`CS-Q2`); node-local retention (`PDM-Q7`, `PDM-Q9`); the retained set
(`PDM-Q1` §9); the discard predicate (`PDM-Q2`).

---

## 1. Rulings

### SB-Q1 — What `DRS-SB` owns — RULED as recommended

`DRS-SB` is the below-horizon read contract and its register: `SB-Q2` (the
skeleton form and the `archived` slot), `SB-Q3` (the peer wire, conformant;
one function), `SB-Q6` (refusals only), and the re-tenses `SB-Q4`/`SB-Q5`.
The discard is S-PRUNE's and is not rebuilt, wrapped or given a second
computation site.

**Rejected.** Closing the node as landed (the read contract was unbuilt on
one surface and contradicted on paper); a `shekyl-chain-prune` increment
owning discard in the daemon (a second `D(E)` site is the node-local source
S-PRUNE §8 forbids). **Reopens** if a `PDM-Q1`/`Q2` obligation S-PRUNE does
not discharge is named with the `prune_tests.rs` test that does not exist
for it.

**Falsifier.** `rg -n 'close_epoch\(.*\)\s*\+\s*2|shard_of\(' rust/ --glob '!**/tests*'`
resolves the discard boundary to one computation (`prune.rs` over
`shekyl_types::shard_of`).

### SB-Q2 — The pruned form, and a full-form request past the horizon — RULED (b)

**The skeleton is the pruned form, everywhere.** Under `prune`
(IG-Q55's switch), every chain entry is the skeleton: the pruned segment
exactly (`Transaction::from_pruned_bytes` parses it) plus the three txid
operands — `prunable_hash`, `pqc_auth_hash` (an `Option`; `None` ⇔ the
identity has no third component, `TxidParts`' predicate) and
`archival_len`. This holds whether or not the node still holds the
archival good: **one shape above and below the horizon.** The `pqc_auths`
bytes never ride in the pruned form. The operands ride on pruned entries
keyed by the request's switch, never by retention. The RPC's `TxEntry` and
the sync wire's `SkeletonTx` (`shekyl-wire/src/sync_body.rs`,
`PDM-Q-F28`) are two encodings of one value, built by one function in the
store (`TxRecord::skeleton_of`, `shekyl-chain-store/src/store/tx_reads.rs`;
`serve.rs` and the RPC's `TxEntry` projection both call it; rule 05).

- **`PDM-Q10` is amended to this.** Its "split form … `pruned_flag` set" is
  superseded by IG-Q55 (RULED 2026-10-19), which deleted `split`,
  `prunable_as_hex` and `pruned`.
- **DX-Q3's register line** ([`DRS_X_STORE_FLIP.md`](DRS_X_STORE_FLIP.md)
  :407, *"`get_transactions` refuses a transaction whose body this node has
  pruned, naming it: Design"*) **is superseded.**
- **Every wallet consumer binds through the skeleton:** refresh, tx
  proofs (`proofs_chain_facts.rs`) and P-scan (`engine/pscan/block_source.rs`)
  all fetch with `prune` and go through `block_fetch.rs`'s `parse_tx_batch`,
  which binds each served skeleton to the requested id by
  `SkeletonTx::bind` (`hash_with_supplied_components`) and yields a
  `BoundTx` — a body only the binding constructs, whose `txid()` is what
  `verify_exhaustive` compares. `TxBodyForm::Full`, the P-scan full-body
  fetch and `Transaction::hash_with_supplied_prunable` are deleted
  (`SB-F4`; Brief B, landed).

**A full-form request for a transaction past the horizon is a per-slot
answer, `archived`, carrying its shard.** It is not a request error;
`tx.pruned_here` (`read_methods.rs` :549) is deleted. The slot is the id
plus `archived: { shard: k }` and no body. `k` is `shekyl_types::shard_of`
of the transaction's cumulative-before archival length — public calendar
data, identical on every node at a tip. The text names the shard and says
that every daemon keeps the skeleton (request with `prune`) and that the
archive serves the body. Never *"here"*, never *"an archival node"*: under
`PDM-Q9` there is no archival daemon. `archived` applies only to a
transaction that carries archival good (`ReadSnapshot::tx_carries_archival_good`,
`read.rs` :800); a transaction with none (a coinbase) answers its full
body, which is its skeleton. `block_list` without `prune` answers per
transaction the same way, and **a height never fails because a body is
archived**: a discarded spend is that slot's `archived` state, and a
coinbase answers its pruned segment. `block_list` gains the `prune` request
field it lacks (`SB-F7`).

**Timing — RULED: after #1212 merges, before the next release cut.** The
DB layout is stable after the flip, so testnet need not be wiped per
release; a long-lived testnet will close real shards and run real discards,
so this increment has to be in that release. Every "before genesis" in
this document's register reads "before the next release cut".

**Rejected.** Keeping the refusal and sending wallets to the wallet-side
store for history (reads `PDM-Q1`'s KEEP-W as archiver-served, which
`PDM-Q5` ruled the other way, and makes every seed restore depend on a
bonded third party past two epochs); carrying `pqc_auth_hash` only on
discarded entries (a per-node fact on the wire, `PDM-Q9`). **Reopens** only
if the wallet lane rules restore-from-seed reads the wallet-side store by
design — re-evaluated in `WSS-`'s round, which would then own this surface.

**Falsifiers.** (i)–(ii) live in one test over one real chain,
`shekyl-chain-ingest`'s `rpc_store_facts_tests/below_horizon.rs`
(`the_wallet_and_the_rpc_read_a_spend_whose_shard_the_store_discarded`,
live lane: the shard driver closes shard 0 with a few hundred real spends,
then empty blocks to the boundary `(close_epoch(0) + 2) · SEB` whose
connect discards it). (i) The wallet's `fetch_scannable_block` under
`prune` for a fill block of that shard succeeds and binds every body to
the id the block lists; `verify_exhaustive` over a range holding it
passes and fails when one bound body is edited; one operand of one served
skeleton changed (a pruned byte, the prunable hash, the length, the third
operand dropped) is refused by the binding; the proof paths' fetch binds
the discarded spend. (ii) The full form of the discarded id answers
`archived { shard: 0 }` and omits it from `txs`; the block's coinbase
answers its whole body; `block_list` without `prune` over that height
succeeds with every spend `archived`, and under `prune` every slot rebinds;
the pruned form of the spend is byte-identical before and after the
discard. The arity downgrade in both directions is pinned beside the
binding: `shekyl-engine-core` `block_fetch_tests`
(`a_third_operand_for_a_prefix_that_carries_none_is_refused`) and
`shekyl-wire` `pruned_tx_hash_parity` (a carrying prefix served with
`pqc_auth_hash: null`). (iii) `rg -n 'fn skeleton_of' rust/` → one
definition, in the store crate; `rg -n 'pruned_here|PRUNED_HERE' rust/` →
nothing. (iv) The IG Part C census carries `pqc_auth_hash` under `tx` and
`archived` with its `shard`, and the generated wire tables' diff is empty.

### SB-Q3 — The peer wire — RULED as recommended

The chain-sync serving path (`serve.rs` :177–210, CS-3) answers a
discarded body with the skeleton by the server's holdings, with no peer-set
flag (`CS-Q3`, F28 taken in); a receiver that cannot bind a skeleton
refuses it. Nothing to build for the wire; `serve.rs` adopts the store's
`skeleton_of` in `SB-Q2`'s increment. The C++ `handle_get_objects` arm that
honoured a peer's `prune` flag is decided: **deleted**, not built on. The
serving half went with `blockchain.cpp` at the flip — the shim that replaced
it (`src/cryptonote_core/cryptonote_core.cpp`, `handle_get_objects`) always
serves the full block from `shekyl_core_block` — and the one line that still
copies the peer's flag onto the entry (`entry.pruned = arg.prune;`), marking
a full body pruned for a peer that asked, is deleted in `SB-Q2`'s increment.
The FOLLOWUPS row (owner `PDM-Q-F28`) is removed by this ruling, its question
answered here.

**Falsifier.** `rg -n 'arg\.prune' src/` → nothing after the increment;
`FOLLOWUPS.md` has no `handle_get_objects` row.

### SB-Q4 — "No node-variable content until this lands" — RULED (SB-F1), edit rule changed

The discard is uniform (`PDM-Q2`, `PDM-Q9`; `prune.rs` §4;
`pruned_and_unpruned_stores_place_every_shard_alike`): every daemon's store
is identical below the horizon at the same tip, whether it discarded,
skeleton-synced or booted yesterday. The class *node-local content created
by discarding* that `DAEMON_REDB_STORE.md` §11.2 graded is empty **by
ruling**, not by timing; the digest oracle's "window" did not close on
2026-09-25 and does not close at the flip.

**Ruled:** the `DRS-SB` row (:1418) and the §11.2 sentence (:2718–:2722)
are edited **in place to what is true now** — no records-was copy in the
living document (the pre-ruling text is `4836afc2e5` and `dev` history).
Done in this round's ruling commit, together with the §7 node label and
edge (`SB-Q7`) and the §11.2 CONDITIONAL row (`SB-Q8`).

**Falsifier.** A digest of two stores at the same tip, one connected through
every boundary and one skeleton-synced, that differs on a table S-PRUNE
touches (DRS-E2's digest form over the partition test above).

### SB-Q5 — The PDM contract's present tense — RULED (SB-F2), edit rule changed

Four live sentences in [`ARCHIVAL_PRUNED_DAEMON_MODE.md`](ARCHIVAL_PRUNED_DAEMON_MODE.md)
describe the landed discard as waiting, or an owed function as owed: the
banner's *"Nothing here is built while DRS is in progress — the
implementation waits on the C++→Rust daemon cutover"*; the `PDM-Q-S0` row
(:1846; satisfied — no C++ was written, S-PRUNE is after `DRS-E1`, genesis
follows the flip — it reads DISCHARGED, naming what remains gated,
`SB-Q2`); `PDM-Q1`'s body (:137, *"no computing function yet … owed with
`D_max`'s constant"*) and row (:1847) — `shekyl_chain_rules::journal_horizon`
exists (`reorg.rs` :96), its slash-log instance `SlashLogFloor` is asserted
at the retirement site and at the read, and the FOLLOWUPS row is gone. After
the flip, `ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md` :20 joins the list.

**Ruled:** one re-tense commit **after #1212 merges**, editing each live
sentence in place to what is true now — no records-was retained — and
bumping the PDM banner's last-verified pin. The same commit **removes the
inline "(deleted, `DEL-008`)" annotations #1212 adds** to the `PDM-Q1` body
and row and to the `D_max` paragraph: after the flip each of those
sentences says what is true now rather than what was deleted. The
`PDM-Q10` amendment (`SB-Q2`) is recorded in its row by this round's
ruling commit, since #1212 does not touch that row.

**Falsifier.** `rg -n 'no computing function yet|Nothing here is built while DRS|\(deleted, `DEL-008`\)' docs/design/ARCHIVAL_PRUNED_DAEMON_MODE.md`
→ nothing after the commit.

### SB-Q6 — The operator surface — RULED as recommended

None exists and none is minted: the body horizon is a rule of the epoch
calendar (`prune.rs` header), no option, no `option show` row, no runtime
lever, no `dev-` lever (a short `Horizons` retention is the store's test
seam). Two `X` rows in [`INPUT_GRAMMAR.md`](INPUT_GRAMMAR.md) §5's REJECTED
table, posed to the `IG-` lane: `prune-blockchain` — *every daemon discards
the same bodies at the same boundary (`PDM-Q2`, `PDM-Q9`); there is no
node-local retention to choose (`PDM-Q7`)*; `sync-pruned-blocks` —
*trust-the-txid with no anchor; the skeleton band below the checkpoint is
`PDM-Q5`'s and needs no flag*. The refusal states what is: bodies below
the horizon are not held by any daemon; the archive serves them.

**Reopens** only if `CS-Q11`'s loopback harness needs a discarded shard on
a running daemon and the store seam cannot reach it — an `IG-Q` with the
harness as the named consumer.

**Falsifier.** `shekyld --prune-blockchain` exits 2 with a refusal that
names the reason, not the nearest live name; both rows in §5's REJECTED
table and in the generated docs.

### SB-Q7 — What the genesis gate still gates — RULED

The node stays a gate on both genesis nodes; its label and edge follow the
amended scope: **the below-horizon read contract — the skeleton form, the
`archived` slot, the refusals, the re-tenses.** The edge reads *"genesis
does not precede the below-horizon contract"*. Its register is §3. Done in
this round's ruling commit (`DAEMON_REDB_STORE.md` :1374, :1399).

**Falsifier.** `SB-Q2` (i)–(iv) green on `dev` and the IG rows landed is the
gate open; the node and the row say *landed* with the date
(`DAEMON_REDB_STORE.md`'s `DRS-SB` row: landed on #1239, 2026-11).

### SB-Q8 — The attestation witness is corpus — RULED as recommended, on a corrected ground

`archival_attestation_witness` is never in set B **because `bind_body`
(`rust/shekyl-chain-rules/src/header_path.rs` :341, `B4::bind_root` :357)
binds the attestation witness for every body, skeleton bodies included**:
skeleton sync below the horizon needs it, so it can never be discarded.
That no S-PRUNE horizon names the table (`prune.rs`) is an observation
about the code, not the reason. §11.2's CONDITIONAL row — *reconstructible
iff the node retains the prunable region* — has no instance: the table is
corpus (KEEP-C), written at connect from the block's supplement and kept,
not derived from the prunable region. Closed in this round's ruling
commit; D10's domain clause is unaffected.

**Falsifier.** A skeleton-synced store binds a block whose shard is
discarded, and its `attestation_witness_at(h)` reads `Recorded`. A S-PRUNE
horizon that ever names the table reopens the row.

---

## 2. Findings

- **SB-F1** — The store carries no node-variable content before or after
  the discard; `DAEMON_REDB_STORE.md` :1418 and §11.2 :2718 assumed the
  discard to come was node-variable (`SB-Q4`).
- **SB-F2** — Four live PDM sentences describe the landed discard as
  waiting and `journal_horizon` as owed (`SB-Q5`).
- **SB-F3** — `PDM-Q10` and DX-Q3's `get_transactions` register line
  contradicted each other, and the code (commit `87bde68239`, 2026-10-23)
  followed the later one: `chain_slot` (`store_read_facts.rs` :247) answered
  *pruned here* on `Prunable::Discarded` (:258) and `PqcAuths::Discarded`
  (:270) before reading the request's form, `transactions` (:319, :340)
  stopped the slot list, `read_methods.rs` :549 refused the request, and a
  wallet could not scan a discarded shard from any node. The store holds
  everything the binding needs — the pruned segment and the permanent
  hash rows (`prune.rs` :115–116) — and the wire lacked `pqc_auth_hash`
  (`shekyl-rpc-types/src/transactions.rs` :112–136).
- **SB-F4** (review) — The wallet's tx-proof path (`proofs_chain_facts.rs`,
  `parse_tx_batch` in the pruned form) and P-scan
  (`engine/pscan/block_source.rs`, `TxBodyForm::Full`, with
  `verify_exhaustive` checking `tx.hash()` from received bytes) also fail
  below the horizon; Round 0's falsifiers covered only refresh. P-scan
  needs `Full` only to bind identity, and the skeleton's `txid()` is the
  same keccak preimage. The prunable-coupled context-free checks `Full`
  adds would catch only an invalid transaction the chain committed — that
  is canonicity, which `engine/pscan/exhaustiveness.rs` (:12, :46)
  explicitly does not claim.
- **SB-F5** (review) — IG-Q55 (RULED 2026-10-19) is a third contract on
  this surface: `SB-Q2` as first posed re-ratified the split / `pruned_flag`
  shape IG-Q55 had deleted.
- **SB-F6** (review) — The pruned form is node-model language in live
  places, all of which go or are rewritten in Brief B: `block_fetch.rs`
  `is_storage_pruned_spend` (:294) and its *"point the wallet at a daemon
  running without `--prune-blockchain`"* error (:271);
  `shekyl-wire/src/transaction/txid.rs` `hash_with_supplied_prunable`'s doc
  (:86, :142, :229: *"a storage-pruned spend … an archival node keeps
  them"*); `read_methods.rs` :555 (*"an archival node serves it"*);
  `shekyl-chain-store/src/store/tx_reads.rs` `wire_bytes`' doc (:245–:253,
  *"fetch the region from an archiver"*).
- **SB-F7** (review) — `GetBlocksByHeightRequest`
  (`shekyl-rpc-types/src/bin_commands.rs` :164) has no `prune` field;
  `block_list` needs a request field, so the first version of §3's "the one
  wire change is an RPC reply field" was wrong: the increment adds a reply
  field (`pqc_auth_hash`), a reply slot form (`archived`), and a request
  field on `block_list`.

---

## 3. Register — what lands where

**Brief A — this PR (#1233), docs only:** the rulings above; `IMPLEMENTATION_INDEX.md`
§2 (`SB-Q` RULED, `SB-F1`…`F7`) and §7; `DAEMON_REDB_STORE.md` — the
`DRS-SB` row, the §7 node label and edge, §11.2's sentence and CONDITIONAL
row; `DRS_X_STORE_FLIP.md` :407 superseded; `ARCHIVAL_PRUNED_DAEMON_MODE.md`
`PDM-Q10` row amended. On #1212, in that PR: its FOLLOWUPS row on
`chain_slot` re-reasoned (*one value, one shape, one binding path; every
daemon discards alike, `PDM-Q9`*) and pointed at `SB-Q2`.

**Brief B — the code increment, landed on #1239 (2026-11-01, after #1212
merged, before the next release cut).** Every row below is landed; the
last column is the commit on that PR.

| Item | Owner | Falsifier | Landed |
| --- | --- | --- | --- |
| `skeleton_of` is the store's (`TxRecord::skeleton_of`, `tx_reads.rs`); `serve.rs` calls it on the arm that serves a skeleton; the archival good is one read, `ArchivalGood::{Retained, Discarded}`, a half state the store fault `SI-42` | pruning lane with CS | `SB-Q2` (iii): `rg -n 'fn skeleton_of' rust/` → one | `741970edc7`, `f7d958bf2f` |
| `TxEntry.pqc_auth_hash` on every pruned entry; `chain_slot` / `transactions` / `blocks_by_height` read the form first; `archived { shard }` per slot for a full-form request past the horizon on `tx_show`/`tx_list`/`block_list`; `tx.pruned_here` deleted; `block_list` gains `prune` (`SB-F7`) and fails only for a height above the tip | pruning lane | `SB-Q2` (ii) | `bc6691628a`, `77ec5f6451` |
| `parse_tx_batch` binds skeletons through `SkeletonTx::bind` into `BoundTx`; `verify_exhaustive` compares the bound txid; `TxBodyForm::Full`, `parse_full_tx`, `fetch_scannable_block_full`, `default_fetch_scannable_block_full`, `is_storage_pruned_spend` and `Transaction::hash_with_supplied_prunable` deleted; refresh, tx proofs and P-scan fetch with `prune`; a non-conformant reply to a `prune` request is an invalid node (`SB-F4`) | wallet lane, in the same increment | `SB-Q2` (i) | `f7d958bf2f` |
| `SB-F6`'s node-model sentences rewritten or deleted | the same increment | `rg -n 'archival node|prune-blockchain' rust/` → nothing outside the daemon table's REJECTED rows (`shekyl-daemon-config/src/table.rs`). `storage-pruned` is not in this check: in `shekyl-wire` and `shekyl-chain-rules` it names the `prunable: None` body shape the `serialize_base` framing parses to, which the validator refuses by `tx_form`; that is a shape name, not a node model, and renaming a consensus-adjacent shape is its own increment | `f7d958bf2f` |
| IG Part C: `pqc_auth_hash` under `tx`; `archived` and `shard` on the tx entry; `prune` on `block_list`'s request (§18, §19) | `IG-` lane, posed here | `SB-Q2` (iv) | `00d6b0a35b` |
| IG §5 REJECTED rows `prune-blockchain`, `sync-pruned-blocks`; `shekyld --prune-blockchain` exits 2 naming the decision | `IG-` lane, posed here (`SB-Q6`) | `SB-Q6` | `00d6b0a35b` |
| #1212's FOLLOWUPS row on `chain_slot` | closes with the increment | the row is gone | `0733810b5a` |
| `entry.pruned = arg.prune;` in `cryptonote_core.cpp`'s `handle_get_objects` shim: the entry is never marked pruned (`SB-Q3`) | the same increment | `rg -n 'arg\.prune' src/` → nothing | `0733810b5a` |
| The falsifiers (i)–(v) as one live-lane test over a real chain whose connect discarded shard 0 (`shekyl-chain-ingest` `rpc_store_facts_tests/below_horizon.rs`) | the same increment | the test | `648f91175d` |

**Docs after #1212 merged (landed in this PR, 2026-11-01):** the `SB-Q5`
re-tense of `ARCHIVAL_PRUNED_DAEMON_MODE.md` (banner pinned at
`dev@9c1fff1f02`; `Q-S0` DISCHARGED; `Q1` body and row name
`journal_horizon` / `SlashLogFloor`; every `DEL-008` annotation gone — the
`SB-Q5` falsifier returns nothing) and of `ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md`'s
retirement notice; the `handle_get_objects` FOLLOWUPS row removed (`SB-Q3`).

Nothing in the register is consensus: no `CEN-` row changes, no store
table changes, no P2P wire format change.

---

## 4. The review-round denominator

What was read to pose and rule this round: `ARCHIVAL_PRUNED_DAEMON_MODE.md`
(banner, `Q1` body, `Q2`, `Q6`, `Q10`, §8, §9's classes, the status
table); `DAEMON_REDB_STORE.md` (§7, the `DRS-SB` row, §11.2, §12);
`DRS_E1_SPRUNE.md` §13–§14 and `prune.rs` with the `prune_tests.rs`
inventory; `DRS_X_STORE_FLIP.md` DX-Q3's register; `INPUT_GRAMMAR.md` §5's
REJECTED table, IG-Q55 and Part C's `tx` rows; the RPC path
(`store_read_facts.rs`, `read_methods.rs`, `read_facts.rs`,
`shekyl-rpc-types/src/transactions.rs`, `bin_commands.rs`); the sync path
(`serve.rs`, `SkeletonTx`, `header_path.rs` `bind_body`); the wallet's
`block_fetch.rs`, `proofs_chain_facts.rs`, `engine/pscan/block_source.rs`
and `exhaustiveness.rs`; `txid.rs`; `tx_reads.rs`; commit `87bde68239`;
`FOLLOWUPS.md` :277, :353 and #1212's row on `chain_slot`. Not read:
`WALLET_SIDE_STORE.md` beyond its FOLLOWUPS rows; the IG generator's code.
