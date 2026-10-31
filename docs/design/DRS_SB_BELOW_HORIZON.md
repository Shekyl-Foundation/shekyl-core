# DRS-SB — the daemon below the body horizon (Round 0)

**Status: OPEN** — Round 0 posed 2026-10-31; nothing here is ruled. Every
`SB-Q*` carries a recommendation and a falsifier and waits on the
maintainer's ruling; `SB-F*` are findings made while posing them, true at
the pin and edited at their source only once the matching question is
ruled.

**Parent:** [`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) §7 — the `DRS-SB`
node (added 2026-10-10) between `DRS-X` and the D2 diamond, and its row in
the same section. The design it was minted to build is
[`ARCHIVAL_PRUNED_DAEMON_MODE.md`](ARCHIVAL_PRUNED_DAEMON_MODE.md) (`PDM-Q*`,
every question RULED or CLOSED, LIVING CONTRACT).

**Ground:** `dev@78501d2b72`, 2026-10-31. Line numbers carry that sha;
re-verify before relying on one. PR [#1212](https://github.com/Shekyl-Foundation/shekyl-core/pull/1212)
(the DRS-X flip) was read at its head the same day; where this document
says "at the flip" it means that PR's merge.

**Families:** `SB-Q` (questions, `SB-Q1`…) and `SB-F` (findings, `SB-F1`…),
registered at birth in [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md)
§2 (rule 94; `check_index_prefix_uniqueness.py --prefix '**SB-Q1…SB-QN**'
'**SB-F1…SB-FN**'` → DISTINCT against the 150 registered families). Not to
be confused with `PDM-Q-S0`, which is a `PDM-Q` token.

**Process:** [`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
Round 0: questions posed with recommendations, no code. Rule 21 shapes every
recommendation (what is rejected, what reopens it, who re-evaluates); rule
23 governs what each disposition leaves in the tree.

---

## 0. Purpose — what this round is for, and what it is not

The `DRS-SB` row reads *"Set-B discard in the Rust daemon — the design is
`ARCHIVAL_PRUNED_DAEMON_MODE.md` … this row is only its place in the
order"*, and the §7 graph gates both genesis nodes on it: *"genesis does not
precede discard"* (`PDM-Q-S0`, RULED 2026-09-12).

**The discard is built.** S-PRUNE landed 2026-09-25
([`DRS_E1_SPRUNE.md`](DRS_E1_SPRUNE.md) §14;
`rust/shekyl-chain-store/src/store/prune.rs`): at the connect of every
boundary `E·SEB`, `E ≥ 2`, inside the block's own transaction, the store
discards `D(E) = { k : close_epoch(k) + 2 ≤ E ≤ close_epoch(k) + 3 }` —
`txs_prunable` and `txs_pqc_auths` for every transaction of those shards —
and retires the undo journal, the slash log, the release journal, the draw
rows and the per-epoch tables at their own floors. It is `PDM-Q2`'s
predicate verbatim: no per-daemon input, no exceptions (`PDM-Q9`: *all
daemons prune uniformly*), the genesis guard a branch, every epoch
comparison additive, the batch idempotent across a boundary reorg. The
tests are the ruling's falsifiers
(`prune_tests.rs`: `epochs_zero_and_one_run_no_batch`,
`the_hook_is_idempotent_across_a_boundary_reorg`,
`pruned_and_unpruned_stores_place_every_shard_alike`,
`consecutive_boundaries_and_every_batch_match_the_model`). `PDM-Q-S0`
forbade *implementing in C++*, and S-PRUNE did not: it is Rust, in the store
the flip makes the store of record. Nothing of the discard waits on the
flip except being in production.

So the question this round opens with is not *how to build set-B discard*
— that design is ruled and that code is landed — but **what the `DRS-SB`
node still owns**. The answer this round proposes (`SB-Q1`) is: **the
daemon's contract below the body horizon** — what every read surface
answers for a transaction whose bodies every node has discarded — plus
the register of statements made in 2026-09 and 2026-10 about a discard
that "has not landed yet", each of which is now a stale present-tense
claim (rule 91: fix the live sentence, keep the record). The first of those
answers (`SB-Q2`) is the one that makes this a genesis gate still: as
built, **every wallet loses the ability to scan a shard from its daemon
the block that shard is discarded**, and two living contracts disagree
about whether that is the design.

**Out of scope, by prior ruling, and not reopened here:** the archiver
serving-store rebuild (`PDM-Q12`, the wallet lane's `WSS-`); cold sync and
the skeleton band (`PDM-Q5`, `CS-Q2`, landed through CS-4); any node-local
retention knob (`PDM-Q7`, `PDM-Q9`: refuted, deleted, REJECTED); the
retained set's grading (`PDM-Q1` §9); the discard predicate (`PDM-Q2`).

---

## 1. Questions

### SB-Q1 — What `DRS-SB` owns, now that S-PRUNE is the discard

**Finding.** The `DRS-SB` row and node were minted 2026-10-10, fifteen days
after S-PRUNE landed, and name the retained set and the predicate as the
design to build. Both are built. The row's one remaining true sentence is
its place in the order.

**Recommendation.** Re-scope the node, not delete it: `DRS-SB` is **the
below-horizon read contract and its register** — `SB-Q2` (the RPC), `SB-Q3`
(the peer wire, already conformant; one function), `SB-Q6` (the operator
surface: refusals only), and the re-tenses `SB-Q4`/`SB-Q5`. The discard
itself is S-PRUNE's and is **not** rebuilt, wrapped, or given a second
computation site. The row's text and the graph node's label change in the
ruling commit; the §7 edges stay (`SB-Q7`).

**Rejected.** (a) *Close the node as landed.* Rejected because the read
contract is unbuilt on one surface and contradicted on paper (`SB-Q2`); a
node that closes with wallets unable to scan history has closed on the
wrong set. (b) *Mint a `shekyl-chain-prune` increment that "owns discard in
the daemon".* Rejected: a second `D(E)` site is the node-local source §8 of
S-PRUNE forbids. **Reopens** if a reader finds a `PDM-Q1`/`Q2` obligation
S-PRUNE does not discharge — falsify by naming the obligation and the
`prune_tests.rs` test that does not exist for it.

**Falsifier for the recommendation.** `rg -n 'close_epoch\(.*\)\s*\+\s*2|/ W\b|shard_of\(' rust/ --glob '!**/tests*'`
resolves the discard boundary to **one** computation (`prune.rs` over
`shekyl_types::shard_of`). A second hit after this round is the node
having grown a discard it should not own.

### SB-Q2 — The RPC's answer below the horizon: `PDM-Q10` against `DX-Q3`

**Finding (SB-F3).** Two living contracts disagree, and the code follows the
later one.

- `PDM-Q10` (RULED 2026-09-18): *no new RPC — "not retained" is
  `get_transactions`' existing split form with `prunable` empty, hash rows
  present, `pruned_flag` set — identical on every daemon.*
- [`DRS_X_STORE_FLIP.md`](DRS_X_STORE_FLIP.md) DX-Q3's register, line
  "`get_transactions` refuses a transaction whose body this node has
  pruned, naming it: **Design** (the prunable region and `pqc_auths` go
  together, and the wire cannot be recomposed without them; C++ never
  discarded a body)".
- As built (#1165 review, commit `87bde68239`, 2026-10-23):
  `store_read_facts.rs` `chain_slot` (:247) returns *pruned here* on
  `Prunable::Discarded` (:258) and on `PqcAuths::Discarded` (:270) **before
  the request's `prune`/`split` form is read**; `transactions` (:319, :340)
  stops the slot list at that id and `read_methods.rs` (:549) refuses the whole
  request with `tx.pruned_here` — *"this node has pruned the body of
  `<id>`; an archival node serves it"*. `blocks_by_height` (:366) does the
  same through `whole_tx` (:227): a height with one discarded body fails
  the request whatever `prune` says. The entry type
  (`shekyl-rpc-types/src/transactions.rs` :113–136) carries
  `prunable_hash` and `archival_len` and **no `pqc_auth_hash`**.

The consequence is the one #1212's own FOLLOWUPS row names: a wallet that
first refreshes after a boundary cannot scan the discarded shard from that
node — from **any** node, since the discard is uniform. The wallet needs
only the pruned segment (outputs, commitments, `extra`), which every node
keeps forever (`txs_pruned`, `PDM-Q1` KEEP-W: *"restore-from-seed scans
every output ever"*), bound to the txid. What it cannot do today is bind
it: `parse_pruned_tx` (`block_fetch.rs` :214, :486–487) mixes the reply's
`prunable_hash` and `archival_len` and hashes the `pqc_auths` bytes it
expects **inside** `pruned_as_hex` — bytes that are set B (`PDM-Q6`) and
gone. The refusal's stated reason is therefore true of the *wire shape*
and not of the *store*: the store holds everything the binding needs, as
the third operand `txs_pqc_auth_hash`, permanent (`prune.rs` :115–116).

The peer wire already solved this. `shekyl-chain-sync-runtime/src/serve.rs`
(:197) answers a discarded record with `TxBody::Skeleton(skeleton_of(..))`:
the pruned segment and the txid's three operands (`prunable_hash`,
`pqc_auth_hash`, `archival_len`) — `shekyl_wire::SkeletonTx`
(`sync_body.rs` :39), `PDM-Q-F28` as amended by `SHT-Q2`.

**Recommendation.** `PDM-Q10` stands and is **amended to the skeleton**;
DX-Q3's register line is re-tensed from *Design* to *Superseded by
`SB-Q2`*. Concretely:

1. The pruned form of a transaction whose set-B bytes are discarded is the
   skeleton: `body` = the pruned segment exactly (`Transaction::from_pruned_bytes`
   parses it), beside `prunable_hash`, `archival_size` (both already
   fields) and **`pqc_auth_hash`**, a new field under `tx` in
   [`INPUT_GRAMMAR.md`](INPUT_GRAMMAR.md) Part C (§18 tx entry fields; §19
   glossary: `pqc_auth_hash` under `tx`, *the pqc_auths region's digest,
   the txid's third operand*). It is present on **every** entry, retained
   or not — a field whose presence encodes retention is the per-daemon
   state `PDM-Q9` forbids — and `null` where the identity has no third
   component (`TxidParts`' `Option`, RK-D23).
2. A request that needs bytes no node holds — the full form of a discarded
   record (`prune` unset) — is refused with `tx.pruned_here`, **at the id**,
   after the form is read, and the message loses *"an archival node serves
   it"*: there is no archival daemon (`PDM-Q9`), the wallet-side store
   serves bodies and it is not reached by this RPC. The split form answers
   as `PDM-Q10` wrote it: `prunable` empty, hashes present, `pruned_flag`
   set.
3. `block_list` (`get_blocks_by_height.bin`) with `prune` set serves the
   skeleton per transaction the same way; without `prune` it fails the
   height as today.
4. **One function.** `skeleton_of` leaves `serve.rs` for the store
   (`TxRecord::skeleton()` or a free function beside `wire_bytes`), and
   both wires call it (rule 05: a derivation two lanes need is a function).
   The RPC's `TxEntry` and the sync wire's `SkeletonTx` are two encodings
   of one value; neither recomputes an operand.
5. The wallet's `parse_pruned_tx` takes `pqc_auth_hash` as the third
   operand when the body carries no `pqc_auths`, and refuses a pruned body
   that carries neither (R83 keeps its teeth: an unbound pruned half is
   still refused).

**Rejected.** (a) *Keep the refusal; wallets scan history from the
wallet-side store.* Rejected: it reads `PDM-Q1`'s KEEP-W as archiver-served,
which is `PDM-Q5`'s centralisation question, ruled the other way (the
checkpoint band is for *bodies the daemon needs to validate*, not for
wallet scans); and it makes every seed restore depend on a bonded
third party for all but the last two epochs. **Reopens** if the wallet
lane rules that restore-from-seed reads the wallet-side store by design —
re-evaluate in `WSS-`'s round, which then owns this surface. (b) *Carry
`pqc_auth_hash` only on discarded entries.* Rejected under `PDM-Q9`: the
reply would say which shard the node has discarded — public calendar
information today, a per-node fact the day any node is non-conformant.

**Falsifiers.** (i) A `block_fetch_tests.rs` test: a store connected past
one boundary with a real spend in `D(E)`, the wallet's
`fetch_scannable_block` in `TxBodyForm::Pruned` for a block of that shard
**succeeds and binds every body to its hash**; today it is
`tx.pruned_here`. (ii) `rpc_store_facts_tests.rs`: the full form of the
same id is refused at the id, the split form is answered. (iii)
`rg -n 'fn skeleton_of' rust/` → one definition, in the store crate.
(iv) The IG Part C census carries `pqc_auth_hash` and the generated wire
table diff is empty.

### SB-Q3 — The peer wire below the horizon: conformant; one function

**Finding.** The chain-sync serving path (`serve.rs` :177–210, CS-3, landed
by 2026-10-23) answers a discarded body with the skeleton by **the server's
holdings**, with no peer-set flag: `CS-Q3` took F28 in, and a receiver that
cannot bind a skeleton refuses it. The C++ `handle_get_objects` arm that
honoured a peer's `prune` flag (`FOLLOWUPS.md` :274, owner `PDM-Q-F28`)
deletes with `blockchain.cpp` at the flip (#1212's deletion list); the PR
does not touch the row.

**Recommendation.** Nothing to build for the wire. Two things to record:
the FOLLOWUPS row is **resolved by the flip** and is removed in the first
pruning-lane commit after #1212 merges (not before: the arm is live until
then); and `SB-Q2` item 4 makes the skeleton's one function the store's,
which `serve.rs` adopts in the same change.

**Falsifier.** After the flip, `rg -n 'arg\.prune|e\.pruned' src/ rust/`
→ nothing; `FOLLOWUPS.md` has no `handle_get_objects` row.

### SB-Q4 — "No node-variable content until this lands" — premise refuted (SB-F1)

**Finding (SB-F1).** `DAEMON_REDB_STORE.md` :1350 (the `DRS-SB` row): *"The
store carries **no node-variable content** until this lands (§11.2's
note)"*, and §11.2 :2650: *"the Rust store has no node-variable content by
construction until set-B discard lands — so the digest oracle commissions
against a uniform reference … That is the cleanest window there will be,
and it closes the day discard lands."* Both sentences assume the discard
to come is node-variable. It is not: `PDM-Q2` and `PDM-Q9` make every
daemon's store identical below the horizon at the same tip, whether it
discarded, skeleton-synced or booted yesterday (`prune.rs` §4; the test
`pruned_and_unpruned_stores_place_every_shard_alike`). The window did not
close on 2026-09-25 and does not close at the flip; the class *node-local
content created by discarding* that §11.2 graded is **empty by ruling**,
not by timing.

**Recommendation.** Re-tense both sentences in the ruling commit: the row
says what `SB-Q1` rules it owns; §11.2's paragraph keeps its pre-ruling
text as records-was and gains one sentence — *the discard landed uniform
(`PDM-Q2`/`Q9`, S-PRUNE 2026-09-25); the store carries no node-variable
content before or after it.* The `output_metadata` paragraph above it
(dead two levels deep) stands.

**Falsifier.** A digest of two stores at the same tip, one connected
through every boundary and one skeleton-synced to the same tip, that
**differs** on a table S-PRUNE touches. `pruned_and_unpruned_stores_place_every_shard_alike`
is the existing instrument on the partition; the digest form is DRS-E2's.

### SB-Q5 — The PDM contract's present tense (SB-F2)

**Finding (SB-F2).** Four live sentences in
[`ARCHIVAL_PRUNED_DAEMON_MODE.md`](ARCHIVAL_PRUNED_DAEMON_MODE.md) describe
a discard that is landed as one that waits, and one owed function as owed:

1. Banner, *"What this document is for"*: *"Nothing here is built while DRS
   is in progress — the implementation waits on the C++→Rust daemon
   cutover (`DRS-E*`, `PDM-Q-S0`)."* S-PRUNE built it in the Rust store;
   the flip puts that store in production.
2. `PDM-Q-S0` row (:1846): *"after `DRS-E*`; no C++; genesis does not
   precede this design's implementation"* — satisfied: no C++ was written,
   S-PRUNE is after `DRS-E1`, and genesis follows the flip. The row should
   read **DISCHARGED**, with what remains gated (`SB-Q2`) named.
3. `PDM-Q1`'s body (:133–150) and row (:1847): *"the expression has no
   computing function yet … the function is owed with `D_max`'s constant
   (FOLLOWUPS)"*. `shekyl_chain_rules::journal_horizon` exists
   (`reorg.rs` :96), its slash-log instance is `SlashLogFloor`, asserted
   at the retirement site and at the read (`prune.rs` header; SI-26), and
   the FOLLOWUPS row is gone.
4. §8 is correct on S-PRUNE and need not change; the `DRS_E1_SPRUNE.md`
   §13 sentence *"die at `DRS-E*` with the C++ store"* names the right
   event under its old name (the flip).

And, after #1212 merges, `ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md` :20 (the gate
sentence `DX-Q3` moved) joins the list.

**Recommendation.** One re-tense commit, after the ruling and after #1212
merges, that edits each live sentence in place, keeps the posed text as
records-was where it carried a decision (item 2), and bumps the PDM banner's
last-verified pin. No ruling changes; this is rule 91's sweep with the
asserts-is / records-was discrimination applied per sentence.

**Falsifier.** `rg -n 'no computing function yet|Nothing here is built while DRS' docs/design/`
→ nothing after the commit; `git grep -n 'journal_horizon' rust/shekyl-chain-rules/src/lib.rs`
→ the export.

### SB-Q6 — The operator surface: none, and two refusals owed

**Finding.** The daemon has no prune option, no `option show` row and no
runtime lever for the horizon, and should have none: the body horizon is a
rule of the epoch calendar (`prune.rs` header: *"there is no constant to
name and no watermark to store"*), `PDM-Q7` deleted `--prune-blockchain`
and the stripe engine, `PDM-Q5` deleted `--sync-pruned-blocks`. But
[`INPUT_GRAMMAR.md`](INPUT_GRAMMAR.md) §5's REJECTED table carries only the
rows `removed_flags.cpp` held, and those two flags were deleted on
2026-09-21, three weeks before the grammar was ruled, so they have **no
row**. The grammar's own criterion (§5: *"a REJECTED row exists for a
capability a user could reasonably ask for again"*; rule 83) fits them
exactly — pruning is the most-asked-for daemon flag in the lineage, and
an operator who types `--prune-blockchain` today gets edit-distance to
the nearest live name, not the reason.

**Recommendation.** Two `X` rows in the daemon's REJECTED table, in the
`IG-` lane's form, pointing at the decisions: `prune-blockchain` — *every
daemon discards the same bodies at the same boundary (`PDM-Q2`, `PDM-Q9`);
there is no node-local retention to choose (`PDM-Q7`)*; `sync-pruned-blocks`
— *trust-the-txid with no anchor; the skeleton band below the checkpoint is
`PDM-Q5`'s and needs no flag*. No live row, no `dev-` lever, no
`option show` surface. The refusal states what **is** (rule 23): bodies
below the horizon are not held here; the wallet-side store serves them.

**Rejected.** A `dev-` lever to force a discard at a chosen boundary for
tests. Rejected: `Horizons` with a short retention is the test seam the
store already has (`prune_tests.rs` `short_horizons`); a lever on the
binary is a second knob for one job. **Reopens** if the loopback harness
(`CS-Q11`) needs a discarded shard on a running daemon and the store seam
cannot reach it — re-evaluate as an `IG-Q` with the harness as the named
consumer.

**Falsifier.** `shekyld --prune-blockchain` exits 2 with a refusal that
names `PDM-Q7` and the reason, not the nearest live name; the generated
docs table carries both rows; `rg -n 'prune' docs/design/INPUT_GRAMMAR.md`
finds them in §5's REJECTED table.

### SB-Q7 — Genesis sequencing: what the node still gates

**Finding.** The §7 edge `SB → G` reads *"genesis does not precede
discard"*. The discard precedes genesis already (it is in the store the
flip ships). What would ship broken at genesis without this node is
`SB-Q2`: the first discard after genesis — shard 0 closes when the
cumulative archival length reaches `W`, and discards two boundaries later
— is the first block at which no wallet can scan from its daemon.

**Recommendation.** The node stays a genesis gate; its label becomes *"the
daemon below the horizon — the RPC skeleton (`SB-Q2`), the refusals
(`SB-Q6`), the re-tenses"*, and the edge reads *"genesis does not precede
the below-horizon contract"*. Its register (this document's §3) is the
gate's checklist, in DX-Q3's register form.

**Falsifier.** `SB-Q2` (i) green on `dev` and the IG rows landed is the
gate open; the §7 node text and the row then say *landed* with the date.

### SB-Q8 — The attestation witness is corpus, not a CONDITIONAL rebuild

**Finding.** `DAEMON_REDB_STORE.md` §11.2 carries `archival_attestation_witness`
as its one CONDITIONAL row: *reconstructible from the local corpus iff the
node retains that prunable region, and on a pruning node it is not*,
flagged *"for the implementation to confirm at the byte level"*. At the pin
the table is its own height-keyed table, outside every S-PRUNE horizon
(`prune.rs` names none; `rg attestation_witness prune.rs` → 0), read for
every served block body (`serve.rs` :202, `attestation_witness_at`), and
the witness is a wire sidecar that no block replay could rebuild
(`FOLLOWUPS.md` :350). It is retained on every node, never discarded, and
never rebuilt — a corpus table in §9's KEEP-C class, not a derived one
whose inputs a pruning node loses.

**Recommendation.** The CONDITIONAL row is **confirmed and closed** by this
finding: grade it corpus (retained, consensus-bearing, never in set B), and
record in §11.2 that the "iff the node retains the prunable region"
conditional has no instance because the table is not derived from the
prunable region in the Rust store — it is written at connect from the
block's supplement and kept. D10's domain clause (the paragraph that
follows the row) is unaffected: this table is corpus, not derived state.

**Falsifier.** A `prune_tests.rs` assertion that `attestation_witness_at(h)`
for every `h` in a discarded shard's blocks is `Recorded(..)` after the
boundary; a S-PRUNE horizon that ever names the table reopens the row.

---

## 2. Threat-model addenda (A3)

Rule 26's A3 pass, against `SB-Q2`'s recommendation in particular. Each
item names the attacker's objective and why the design does not serve it.

1. **A daemon forges a pruned body for a wallet.** The wallet binds the
   skeleton to the txid it asked for through all three operands; a
   substituted pruned segment, `prunable_hash`, `pqc_auth_hash` or
   `archival_size` changes the hash. Unchanged from today's pruned form;
   the only new thing is *which* operand the wallet reads from a field
   rather than hashes from bytes, and a field is bound exactly as bytes
   are.
2. **A daemon denies history by answering `tx.pruned_here` for a retained
   body.** A refusal the wallet can check: below the horizon every node
   refuses the full form alike, above it none does, and the horizon is the
   calendar's. A wallet seeing a refusal above the horizon has learned the
   daemon is non-conformant and moves on; nothing in the design makes a
   false refusal profitable.
3. **The reply fingerprints the node.** `PDM-Q9` holds: the skeleton is
   served by every node for the same ids at the same tip, `pqc_auth_hash`
   rides every entry, and no field says *this node discarded*. A client
   learns the calendar, which it already has.
4. **Cheaper serving as a DoS lever.** A skeleton is smaller than a full
   body and costs no verification to assemble; the existing per-request
   bounds (`RPC_CHANNEL.md` §6.3) are unchanged. No new amplification.
5. **An operator "re-enables" pruning control through the refused names.**
   `SB-Q6`'s rows are refusals that name the decision; there is no
   accepted spelling and no `dev-` lever, so no mainnet configuration
   reaches a node-local retention (rule 83 IG-8).

---

## 3. Register — what this round leaves, by owner, once ruled

| Item | Owner | Lands | Falsifier |
| --- | --- | --- | --- |
| `TxEntry.pqc_auth_hash`; `chain_slot` / `blocks_by_height` read the form before refusing; the refusal's message | pruning lane (`SB-Q2`) | one increment after the ruling, before genesis | `SB-Q2` (i), (ii) |
| `skeleton_of` moves to the store; `serve.rs` calls it | pruning lane with CS (`SB-Q2` 4, `SB-Q3`) | the same increment | `SB-Q2` (iii) |
| `parse_pruned_tx` takes the third operand | wallet lane (`SB-Q2` 5) | the same increment or the next | `SB-Q2` (i) |
| IG Part C: `pqc_auth_hash` under `tx` (§18, §19) | `IG-` lane, posed by this round | with the wire change | `SB-Q2` (iv) |
| IG §5 REJECTED rows `prune-blockchain`, `sync-pruned-blocks` | `IG-` lane, posed by this round (`SB-Q6`) | the next IG ruling | `SB-Q6` |
| `DAEMON_REDB_STORE.md` :1350 row, §7 node label and edge, §11.2 :2650 sentence, §11.2 CONDITIONAL row | pruning lane (`SB-Q1`, `Q4`, `Q7`, `Q8`) | the ruling commit | `rg` per question |
| `ARCHIVAL_PRUNED_DAEMON_MODE.md` banner, `Q-S0` row, `Q1` :133–150 and row | pruning lane (`SB-Q5`) | after #1212 merges | `SB-Q5` |
| `DRS_X_STORE_FLIP.md` DX-Q3 register line on `get_transactions` | pruning lane, DX-Q3's owner informed (`SB-Q2`) | the ruling commit | the line reads *superseded by SB-Q2* |
| `FOLLOWUPS.md` :274 (`handle_get_objects` prune flag) removed | pruning lane (`SB-Q3`) | after #1212 merges | `SB-Q3` |
| #1212's FOLLOWUPS row on `chain_slot` | closes with the `SB-Q2` increment | — | the row is gone |

Nothing in the register is consensus: no `CEN-` row changes, no store
table changes, no wire *format* changes on the P2P side. The one wire
change is an RPC reply field, additive, under RW-Q4.

---

## 4. The review-round denominator

What was read to pose this round, so a reader can see what was not:
`ARCHIVAL_PRUNED_DAEMON_MODE.md` (banner, `Q1` body :120–150, `Q2`
:151–235, §8, §9's class definitions, the status table :1846–1858);
`DAEMON_REDB_STORE.md` (§7 graph and the `DRS-SB` row, §11.2 :2530–2690,
§12 `DEL-008`); `DRS_E1_SPRUNE.md` §13–§14 and `prune.rs` in full with the
`prune_tests.rs` inventory; `DRS_X_STORE_FLIP.md` DX-Q3's register;
`INPUT_GRAMMAR.md` §5 REJECTED table and Part C's `tx` rows; the RPC path
`store_read_facts.rs` (`whole_tx`, `chain_slot`, `transactions`,
`blocks_by_height`), `read_methods.rs` (`tx.pruned_here`), `read_facts.rs`,
`shekyl-rpc-types/src/transactions.rs`; the sync serving path `serve.rs`
and `shekyl_wire::SkeletonTx`; the wallet's `block_fetch.rs`; commit
`87bde68239`'s message; `FOLLOWUPS.md` :274, :350, :1471 and #1212's row
on `chain_slot`; `IMPLEMENTATION_INDEX.md` §2 for `PDM-Q`, `DX-Q`, `CS-Q`.
Not read: `WALLET_SIDE_STORE.md` beyond its FOLLOWUPS rows (its `WSS-Q1`
axis is not this round's), the wallet's scanner internals below
`parse_pruned_tx`, and the IG generator's code.
