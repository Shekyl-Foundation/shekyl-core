# The store rebuild (DRS-D10's machinery) — Rounds 0 and 1

**Status:** OPEN — Round 1, 2026-11-21, for Rick to rule; then its own brief. Round 1 (at the end) replaces Round 0's corpus (RB-Q1), which S-PRUNE made unbuildable; settles what a rebuild verifies below the body horizon; and carries RB-Q2–Q4. Round 0 below is the record of what was posed on 2026-10-21 and never ruled.

**For:** Rick to rule; then its own brief. **From:** design review, 2026-10-21.
**Ground:** `dev` at `ba0b28379`. The trigger was #1147's S0 (the node opens `chain.db` at every start, and a layout mismatch refuses).

## What is already ruled, and stands

- **DRS-D10** (`DAEMON_REDB_STORE.md:319`, §11): derived state is reconstructible from the local block corpus alone; mandatory for genesis; on the §8.1 genesis checklist.
- **§11.1(a):** a layout mismatch is answered by rebuild, never a migrator; "no migration ladder and none will be written," with the C++ `migrate()` ladder as the cautionary precedent.
- **§11.2:** the corpus is three tables, `blocks`, `txs_pruned`, `txs_pqc_auths`, drawn by table because a boundary one table too small is unrecoverable (the V10/V11 case).
- **DRS-D12:** replay-that-validates — every replayed block passes `validate` before `connect`.
- **The layout is never consensus.** Consensus is the wire and the rules. The one coupling is §11.1(b): a value codec on a digest-folded table is the digest's encoding, so changing it is a digest-version bump, not a consensus change.

**Rick, 2026-10-21:** wipe during development; migrate by replay before genesis, as first-class machinery; the layout is not frozen at genesis, and local shape changes without consensus changes are expected. A rebuild re-verifies proof of work: it is a validation of the whole chain under the current rules, and a tampered or corrupted file cannot replay clean.

## The gap

§11.1(a) also rules "newer refuses; older refuses too" at open. A rebuild needs the new binary to read the old file's three corpus tables. Refusing the old file whole leaves only network resync, which §11 names as the fallback for engines that refuse reconstructibility. So the machinery is unbuildable without one more ruling.

## RB-Q1. The corpus format is frozen, with its own version

> **Stale (S-PRUNE):** `txs_pqc_auths` is discarded below the body horizon, and the set omits `txs_prunable` and four kept rows a rebuild needs. Round 1 redefines it.

**Recommendation.**
- The three corpus tables' keys and value codecs are frozen under a **corpus version**, separate from `schema_version`. Today's encodings are corpus version 1.
- The store exposes a **read-only corpus reader** that opens a file of any past layout by those three tables alone and yields blocks and bodies in height order. It reads nothing else, so no other table's codec is pinned.
- A corpus bump is its own deliberate event, recorded like a redb format move (§11.1(c)), and ships with a reader for the previous corpus version — the only place a two-version reader is ever written, and it is a reader, not a migrator.
- The schema-snapshot gate pins the three tables' `.snap` rows against the corpus version, so a PR that moves them without a corpus bump fails CI.

**Wargame.** A table left out of the frozen set is the V10/V11 failure by construction, so the set is §11.2's and any change to it is a ruling. A frozen codec that later needs a field gets a corpus bump and a reader, never a silent reinterpretation.

## RB-Q2. The rebuild is the replay driver over the corpus reader

> **Stale (S-PRUNE):** below the body horizon the bodies this replay validates are gone. Round 1 settles what it verifies there.

**Recommendation.**
- One path: open the old file read-only through the corpus reader, open a fresh file at `chain.db.rebuild`, replay every block through the production pipeline (`shekyl-chain-ingest`'s driver, `corpus.rs`, the same `form → validate → connect`), then swap: the old file becomes `chain.db.<layout>.replaced`, kept until the operator removes it. The pool file is moved aside and reopened empty (`SPL-Q8`; nothing is deleted).
- Proof of work is verified on every block (Rick, 2026-10-21). The cost is stated: about 1.25 s per block on the floor device, roughly a day per chain-year on four cores. A rebuild is a per-release event.
- The rebuilt tip's `logical_state_digest_v0` is compared with the one the old file recorded. A mismatch is a finding, logged at `error` with both values, and the rebuild still completes: the fresh file is the one the current code stands behind.
- A corpus that ends short of the old file's recorded tip is refused before any block is replayed: the file is missing blocks, and that is the operator's to resolve (resync), not the rebuild's to hide.
- **Triggers:** a `schema_version` mismatch in either direction; a redb file-format move (§11.1(c)); an operator's `chain rebuild` (a grammar row, host-only), for a suspected corruption. Corruption refused at open is **not** a trigger on its own: the reader may still read the corpus, but the operator asks.

## RB-Q3. Where it runs, and when

**Recommendation.**
- `shekyl-node` runs it at open, before the service starts, with progress logged per 1,000 blocks and a `get_info` state (`rebuilding { height, of }`) so a staker's wallet reads "not following" rather than "offline."
- The RPC is up during a rebuild and answers `not ready` for chain reads.
- Pre-genesis, the development posture is the wipe (#1147's S0): the trigger logs the versions and wipes. The rebuild PR flips that to the replay, and the wipe path is deleted with it. A config row is not offered: there is one behaviour per release.

## RB-Q4. Local shape changes after genesis

**Recommendation, as a statement for the record.**
- Adding a table, re-keying an index, or changing a value codec on a table the digest does not fold is a layout bump and a rebuild. No consensus change, no digest change.
- Changing a value codec on a digest-folded table is a layout bump, a rebuild, and a digest version bump. Two nodes on different layouts cannot be compared by digest until both rebuild; the wire does not notice.
- A corpus-table change is RB-Q1's event.

## Sequencing

- #1147 (PR 3n) lands with the wipe (S0 as amended).
- The rebuild PR comes after the flip, before genesis (FLIP-Q2, Rick 2026-10-24). Releases come from `main`, and every pre-genesis release wipes, so the flip is not the first file an operator keeps; the rebuild is on `DAEMON_REDB_STORE.md` §8.1's genesis checklist, not the flip's (`DRS_X_STORE_FLIP.md` §4).
- "DRS-D10 implemented" on the genesis checklist is this PR.

---

# Round 1 (2026-11-21)

**For:** Rick to rule; then its own brief. **From:** the DRS line, on Rick's brief of 2026-11-21. **Ground:** `dev` at `ca7085028a`. Every claim below was read at that tree; the inventory (§R1.2) cites the code it rests on.

## R1.0 Why Round 1

Round 0 freezes a corpus of `blocks`, `txs_pruned` and `txs_pqc_auths` and replays it through `form → validate → connect`. Against the pruned store that is unbuildable, four ways:

- `txs_pqc_auths` is discarded below the body horizon on every node (`rust/shekyl-chain-store/src/store/prune.rs`, `discard_range` over `TXS_PRUNABLE` and `TXS_PQC_AUTHS`), so Round 0's corpus does not exist below the horizon.
- `txs_prunable` is not in Round 0's corpus at all, and a spend without its prunable region is refused by `form` on CEN-H18, the cleartext balance, whose pseudo-outs live there (`g5_the_storage_pruned_spend_is_refused_before_any_block_rule_sees_it`, `shekyl-chain-rules/src/rules/tx_inputs_tests.rs`). So the Round 0 replay refuses every spend, at every height.
- Four tables a pruned node keeps forever are raw chain data or are computed from bytes it no longer holds, and Round 0's corpus omits them (§R1.2).
- No landed code validates a block whose bodies are gone. Chain sync's offered body cannot carry a skeleton (`shekyl-chain-sync/src/protocol.rs`, `OfferedBody`), `Trust` holds only the genesis pin (`shekyl-chain-rules/src/trust.rs`), and `Following` has no producer (`docs/FOLLOWUPS.md`, the bootstrap lane's row).

## R1.1 What Rick's brief settles (2026-11-21), recorded as his

- **A rebuild verifies, below the horizon,** proof of work and every rule whose operands are in the kept data, and recomputes all derived state. The proofs below the horizon go to the bootstrap lane's background verification from archivists (`DAEMON_REDB_STORE.md` §1.3a.5, PB-B1–PB-B4).
- **A rebuild is a bootstrap from the local corpus:** the same pipeline a fresh node runs, with the local file as its source.
- **The corpus is redefined:** headers and pruned transactions always, bodies above the horizon, under its own version.
- **RB-Q2–Q4 carry over with nothing ever wiped:** an old file is moved aside, never removed (`docs/FOLLOWUPS.md`, S3). The operator's rebuild and the rewind are one tool.
- **The pool's pre-v1 seal is recognised** (S3, item 5).

What follows is the inventory the brief asked for and the questions it surfaced. Nothing above is re-posed.

## R1.2 The inventory: every table, kept or not, and what binds it

`S/` is `rust/shekyl-chain-store/src/`. Table types are `rust/shekyl-chain-store/schemas/tables.snap`; classes are `S/accumulator/class.rs` `TABLE_CLASSES`; writers are `S/store/connect.rs` unless named.

**Corpus: what the node received, kept forever.** Each row is bound to proof of work, so a tampered or corrupted row cannot replay clean (Rick, 2026-10-21):

| Table | What it is | Bound by |
| --- | --- | --- |
| `blocks` | header, inline miner transaction, transaction-hash list | the PoW blob: the header, and the Merkle root over the miner transaction and the hash list (`shekyl-wire/src/block.rs`, `pow_blob`) |
| `txs_pruned` | each transaction's prefix and committed base | its txid, which is in the PoW blob's Merkle root |
| `txs_prunable_hash` | the hash of the prunable region | the txid mixes it (`shekyl-wire/src/transaction/txid.rs`, `hash_with_supplied_components`) |
| `txs_pqc_auth_hash` | the hash of the PQC authorizations | the txid mixes it, as above |
| `txs_archival_len` | the archival length, `|prunable| + |pqc_auths|` | the txid mixes it whole, as above |
| `archival_bundle_references` | the block's bundle references, a sidecar beside the block | the header's `section_root`, the root over them (`shekyl-archival-retention/src/bundle.rs`, `section_root`), in the PoW blob |

The three hash and length rows are derived at connect from bytes a pruned node later discards. They are kept forever (`S/store/prune.rs` discards only the bodies), and the txid binds them, so they are corpus, not derived state: a replay cannot recompute them and does not need to.

**Corpus: held above the horizon only.** `txs_prunable` and `txs_pqc_auths`, discarded per shard at the epoch boundary where `close_epoch(k) + 2 ≤ E` (`S/store/prune.rs`). Each is bound by its hash row above.

**Derived: recomputable from the corpus by a replay from genesis.**
- `block_heights`, `block_pow` (a RandomX rehash), `rule_set_in_force`, `tx_indices`, `tx_outputs`, `output_txs`, `output_amounts`, `spent_keys`.
- The curve tree (`curve_tree_leaves`, `output_to_leaf`, `leaf_to_output`, the layers, meta, roots and leaf counts). A leaf is `construct_leaf(O, C, CM)`: `O` and `C` come from the prefix's outputs and committed base, and `CM` from the prefix's admitted leaf field in `extra` (`S/store/leaf_reads.rs`). No prunable or PQC byte is read.
- `block_burn`, and `properties`' chain folds (`total_burned`, `archival_last_slash_epoch`).
- `undo_log`, whose window a replay regenerates.
- The archival family:
  - `archival_bond`: `join` copies the keys from the BondPost input, and the PQC reads in `tx_bond.rs` are checks that write nothing;
  - the release journal, slash log, slash-applied, settlement, support settlement, sigma-work, budget, budget-accruing and `r_market` rows;
  - the issued draws and digests, from the references' kept part (`shekyl-chain-rules/src/archival/bundle.rs`);
  - the block draws and support blocks;
  - the shard cutting, which reads `cumulative_archival_len`: the fold of the kept, txid-bound `txs_archival_len`.

  Intermediates their epoch floors retire are regenerated as the replay passes through them.
- `block_info`, except its weights (RB-Q7).

**Node-local: not chain state, not reproducible, and not owed by a rebuild (§11.2).**
- `alt_blocks` and `alt_block_bodies`;
- the bundle queue and the bundle bodies (`archival_bundle_queue`, `archival_bundle_body`);
- the pool file;
- `properties`' engine cells: `following_degraded`, `apply_policy` and `rule_coverage_gaps` (RB-Q9).

**Findings the inventory makes:**
- **F1.** Round 0's corpus lacks four kept, PoW-bound rows: the three hash and length rows and the bundle references.
- **F2.** The block weights in `block_info` read `|L|` from the prunable region (`shekyl-wire/src/transaction.rs`, `weight`), so below the horizon no landed code derives them (RB-Q7).
- **F3.** Bundle bodies are swept when a block passes the undo retention (`S/store/bundle_holders.rs`, `sweep_section`), which is less than one epoch. Transaction bodies are kept two epochs past their shard's close. So there is a band, above the body horizon, where a node holds every transaction body but no bundle body (RB-Q8).
- **F4.** `following_degraded` is cleared "only [by] a resync, a new file" (`S/codec/property.rs`). That clause was written when a new file meant a resync from the network. A rebuild is a new file that is not a resync: it replays the same local chain the latch was raised on (RB-Q9).
- **F5.** Today a pool file at another version is renamed aside and then wiped (`S/pool/header.rs`, `replace` and `finish_discard`). That contradicts S3's "nothing is deleted" (RB-Q10).

## R1.3 Questions

### RB-Q1′. The corpus, version 1 (replaces RB-Q1)

**Recommendation.**
- Corpus v1 is the six always-kept tables of §R1.2: `blocks`, `txs_pruned`, `txs_prunable_hash`, `txs_pqc_auth_hash`, `txs_archival_len` and `archival_bundle_references`. `txs_prunable` and `txs_pqc_auths` are read where held, each row checked against its hash row before it is used.
- RB-Q1's other parts stand on this set: its own version, a read-only reader that opens a file of any past layout by these tables alone, and the schema-snapshot gate pinning their `.snap` rows against the corpus version.

**Wargame.** Every corpus row is bound to proof of work through the txid or the header (§R1.2). A tampered row therefore fails the replay at the block that carries it, below the horizon as above. Rick's 10-21 property holds for the whole corpus, not only for the bodies. A table left out of the set is still the V10/V11 failure. So the set is this table's, and adding to it is a corpus bump.

### RB-Q5. Skipping the proof rows below the horizon reopens a rejection

Rick's brief sends the proofs below the horizon to background verification. That is the skip `PDM-Q5`'s band 1 described, and S1 rejected it on 2026-11-03 with the coded checkpoints: "no coded checkpoints … the release pins genesis and nothing above it" (`ARCHIVAL_PRUNED_DAEMON_MODE.md` `PDM-Q5`'s banner). `CHAIN_RULES_CRATE.md` names the reopening criterion: a later design that "names a reason to skip proof rows that is not a coded checkpoint." DRS-D12 also stands: every block the store connects passes `validate` first.

**Recommendation: reopen on that criterion, for this reason.**
- The rows skipped are those whose operands the node itself verified, at connect, before it discarded them.
- The release pins nothing above genesis.
- What the rebuild trusts is its own earlier verification. That verification is bound by the hash rows the txid commits, and the bootstrap lane's background verification re-checks it from archivists' bodies.
- DRS-D12 is kept by a skeleton `validate`: every rule whose operands are in the corpus runs; the proof rows (CEN-I15, J26, J27 for FCMP++, H19 for range proofs, I17 and I18 for the PQC signatures) and H18 (the pseudo-outs) are named as background-verified, by row, in the census.
- Rick rules whether this reopens the rejection; the recommendation is that it does.

### RB-Q6. The skeleton pipeline is the bootstrap lane's, and the rebuild waits for it

Neither a skeleton `form`/`validate` nor `Following`'s producer exists. Rick's brief makes the rebuild "the same pipeline", so the rebuild is a source for it, not a second implementation.

**Recommendation.** The order is:
1. this round is ruled;
2. the bootstrap lane builds the skeleton `form`/`validate` and the background verification behind `Following`;
3. the rebuild PR adds the local corpus as a source, then the swap, the tool and the pool's move-aside;
4. S2 (native key order) is the rebuild's first real use, on a testnet store at the previous layout.

The rebuild does not define its own rule subset.

### RB-Q7. Block weight below the horizon

`tx.weight()` is `serialized_len` plus the Bulletproofs+ clawback, and the clawback reads `|L|` from the prunable region. CEN-H19 pins `|L|` to the output count (`shekyl-chain-rules/src/rules/tx.rs`). So from kept data a transaction's weight is `|pruned| + archival_len + clawback(n_out)`.

**Recommendation.**
- Compute it from kept data with one function beside `weight`.
- A test holds the two equal on every full transaction the corpora carry.
- The weight rows are not carried as corpus: they are derived and PoW-unbound, and a corrupted row would otherwise replay as truth.
- If the test cannot hold them equal, the weights join the corpus by ruling.

### RB-Q8. Bundle bodies, swept before the transaction bodies

`validate` needs the body of every bundle reference (`Stale::BundleBody` when it is missing), and bodies are swept at the undo retention (F3).

**Recommendation.** Bundle-body checks join the proof rows: background-verified below the undo window, and named by row like them. The derived state does not read the body: the issued draws come from the references' kept part. So the band between the undo window and the body horizon is a skeleton band for these rows alone.

### RB-Q9. Node-local cells a new file would start without

**Recommendation.**
- The rebuild carries `following_degraded` into the new file, and the property's doc says a resync from the network clears it, not a new file as such. A layout change must not clear the latch: the evidence behind it is about the network, and the local corpus does not answer it.
- `apply_policy` and `rule_coverage_gaps` are recomputed by the rebuild's own run, which re-establishes the facts they record.

### RB-Q10. The pool's pre-v1 seal, and the pool's move-aside

Before 2026-10-17 (`108a3015ea`) the pool file sealed the chain's layout number under the same key, `pool_schema_version`: 12 at the first pool (`cb09a791cf`) through 27. The pool's own version is now 2 (`S/pool/schema_version.rs`). Today the comparison is `!=`, so every pre-v1 file is recreated, and nothing misreads one. The hazard comes with ordering: under the chain's rule, newer refuses and older rebuilds, so a seal of 12–27 reads as newer than 2 and is refused and kept. Once the pool's own version reaches 12, a pre-v1 seal is indistinguishable from a real one.

**Recommendation.**
- The discriminator is a key, not a value band. The next pool bump moves the pool's version to a new key, `pool_layout`. A file whose header has only `pool_schema_version` is pre-layout, whatever its value: it is moved aside and a fresh file is sealed.
- Until that bump, values 12–27 under the old key are pre-v1 by construction, because the pool's version is below 12.
- The pool takes no "newer refuses" arm. It is node-local and recreatable, so a file at any other version, older or newer, is moved aside and kept, and a fresh one is sealed.
- `replace` stops wiping the retired file (F5). It keeps it under a name that states its layout, as the chain file's move-aside does.

### RB-Q2–Q4, carried

- **RB-Q2** stands, with the corpus of RB-Q1′ and the pipeline of RB-Q6:
  - fresh file at `chain.db.rebuild`, then the swap;
  - the old file kept as `chain.db.<layout>.replaced`;
  - the pool file moved aside (RB-Q10);
  - the digest compared, and a mismatch logged at `error`;
  - a corpus short of the old file's recorded tip refused before any block replays;
  - its triggers.

  Nothing is wiped.
- **The tool (Rick's brief: rebuild and rewind are one).** One operator row, the rebuild, takes an optional stop height. Without one it replays to the corpus's tip; with one it replays to that height, which is the rewind. Within the undo window the stop is served by `pop`, without a replay (NI-R8's "rewind N blocks"; `docs/FOLLOWUPS.md`'s rewind row). The row's spelling is the input grammar round's (IG; rule 83), and `dev_chain_pop` leaves the RPC in the same change (`docs/FOLLOWUPS.md`).
- **RB-Q3** stands, with `get_info`'s `rebuilding { height, of }` and the RPC's `not ready`. Its wipe clause is replaced: the rebuild PR deletes the alpha wipe, and a layout the binary cannot read is moved aside and refused, never removed.
- **RB-Q4** stands as written.

## R1.4 Sequencing

- This round is ruled first. Its brief names the bootstrap lane's part (RB-Q6, step 2) and the rebuild's.
- "DRS-D10 implemented" on `DAEMON_REDB_STORE.md` §8.1 is the rebuild PR. S2 follows it (`docs/FOLLOWUPS.md`).
