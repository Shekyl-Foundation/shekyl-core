# The store rebuild (DRS-D10's machinery) — Round 0

**For:** Rick to rule; then its own brief. **From:** design review, 2026-10-21.
**Ground:** `dev` at `ba0b28379`. The trigger was #1147's S0 (the node opens `chain.db` at every start, and a layout mismatch refuses).

## What is already ruled, and stands

- **DRS-D10** (`DAEMON_REDB_STORE.md:331`, §11): derived state is reconstructible from the local block corpus alone; mandatory for genesis; on the §8.1 genesis checklist (`:2107`).
- **§11.1(a):** a layout mismatch is answered by rebuild, never a migrator; "no migration ladder and none will be written," with the C++ `migrate()` ladder as the cautionary precedent.
- **§11.2:** the corpus is three tables, `blocks`, `txs_pruned`, `txs_pqc_auths`, drawn by table because a boundary one table too small is unrecoverable (the V10/V11 case).
- **DRS-D12:** replay-that-validates — every replayed block passes `validate` before `connect`.
- **The layout is never consensus.** Consensus is the wire and the rules. The one coupling is §11.1(b): a value codec on a digest-folded table is the digest's encoding, so changing it is a digest-version bump, not a consensus change.

**Rick, 2026-10-21:** wipe during development; migrate by replay before genesis, as first-class machinery; the layout is not frozen at genesis, and local shape changes without consensus changes are expected. A rebuild re-verifies proof of work: it is a validation of the whole chain under the current rules, and a tampered or corrupted file cannot replay clean.

## The gap

§11.1(a) also rules "newer refuses; older refuses too" at open. A rebuild needs the new binary to read the old file's three corpus tables. Refusing the old file whole leaves only network resync, which §11 names as the fallback for engines that refuse reconstructibility. So the machinery is unbuildable without one more ruling.

## RB-Q1. The corpus format is frozen, with its own version

**Recommendation.**
- The three corpus tables' keys and value codecs are frozen under a **corpus version**, separate from `schema_version`. Today's encodings are corpus version 1.
- The store exposes a **read-only corpus reader** that opens a file of any past layout by those three tables alone and yields blocks and bodies in height order. It reads nothing else, so no other table's codec is pinned.
- A corpus bump is its own deliberate event, recorded like a redb format move (§11.1(c)), and ships with a reader for the previous corpus version — the only place a two-version reader is ever written, and it is a reader, not a migrator.
- The schema-snapshot gate pins the three tables' `.snap` rows against the corpus version, so a PR that moves them without a corpus bump fails CI.

**Wargame.** A table left out of the frozen set is the V10/V11 failure by construction, so the set is §11.2's and any change to it is a ruling. A frozen codec that later needs a field gets a corpus bump and a reader, never a silent reinterpretation.

## RB-Q2. The rebuild is the replay driver over the corpus reader

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
- The rebuild PR is briefed after PR 3b, before the flip: the flip is the first release whose file an operator keeps, so the rebuild should exist by then even though every pre-genesis release may still choose to wipe.
- "DRS-D10 implemented" on the genesis checklist is this PR.
