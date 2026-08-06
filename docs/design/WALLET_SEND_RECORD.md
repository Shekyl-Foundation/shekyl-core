# Wallet Send Record — W-D outgoing history + `abandon_tx` (design round 0)

**Status:** Round 0 opened 2026-08-05; **R1 pass 1 folded 2026-08-05**
(review on the round-0 text, findings R1-1..R1-6). Ratified at pass 1:
**C1** (premise corrected per R1-4's check — see §2), **C2** (reworded
to the R1-3 ownership form), **C3**, **C5**, **C7** (new, per R1-2),
the **§5 non-goals**, and the **PR-SJ-1/2/3 decomposition**.
Re-posed against the §1 recoverability table and awaiting R1 pass 2:
**SJ-DQ-1**, **SJ-DQ-4** (reframed per R1-3), **SJ-DQ-5**, **SJ-DQ-6**;
the `abandon_tx` force-path sub-question is pulled up from SJ-DQ-8 into
R1 scope (R1-5). Decisions stamp into the section that carries them,
dated, per the binding-record convention (`DAEMON_SUBMIT_VERDICT.md`
§1 shape). Per R1-6: any deferral R1 creates carries named rule-21
reopen criteria at ratification time, not at PR time.

**Identifier family:** `SJ-DQ-N` (send-journal design questions),
registered at birth in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 (rule 94).

---

## 0. Why this round, and why now

Two open FOLLOWUPS share one validation surface — the **post-dispatch
send-record lifecycle** — and are bundled per rule 19:

- **W-D** (`../FOLLOWUPS.md` "Phase 4b: `get_transfers` OUTGOING filter
  is a no-op"): the Engine ledger holds only receive-side rows;
  `project::transfer_view` projects every row `INCOMING` with
  `fee: "0"`, so `direction: OUTGOING` silently returns an empty list.
  Reopening criterion: *Engine grows a spend-side transfer record*.
- **`abandon_tx`** (`../FOLLOWUPS.md` "Phase 4c rescan refusal needs an
  abandon escape"): `start_rescan` correctly refuses (`-29202`) while an
  in-flight spend record exists, but a broadcast-then-dropped tx keeps
  its `pending_tx_hashes` entry forever, so that wallet can never rescan
  again. Named blocker: an abandon must prove (or safely presume)
  non-exposure before touching the retention record. Reopening arm 2:
  *the retention design gains a "presumed-dead, keys retained" state* —
  which is precisely a state on the record W-D defines.

Both inputs this round needs landed in the last two merges:

- **The must-preserve partition exists in code** (#401,
  `engine/rescan.rs::reset_scan_derived_state`): rescan preserves
  `tx_meta.tx_keys`, payment-request rows, restore height, and bond
  records. A send record is chain-unrebuildable (see §1) and joins that
  set — the wiring point is now a named function, not a design sketch.
- **The dispatch-side vocabulary exists** (#403): the dispatch-time
  persistence seam (`record_retained_tx_key`, pin-1 "before the bytes
  can reach the daemon"), the identity-bearing `SubmitOutcome`, the F14
  awaiting-confirmation lock lifecycle, and the watchdog's
  confirmed-absent horizon — the states a journal row transitions
  through are already produced; today they are simply not recorded.

The GUI's transaction list already documents the gap from the consumer
side: "a faithful send/fee history cannot be reconstructed at this
layer; that waits on engine-side transaction journaling"
(`shekyl-gui-wallet` `engine_session.rs`).

## 1. Grounding (source-verified; R1-1 table verified 2026-08-05 at dev `dbf90ad7a`)

- Send side at dispatch: `ConsumerHeldEntry` already carries everything
  a history row could want — `request` (recipients + amounts), `fee`
  (via meta), `tx_bytes`, the content `fingerprint`, heights — and drops
  it all when the reservation resolves.
- Retention (WI-RPC-3): `tx_meta.tx_keys` + `sync_state.
  pending_tx_hashes` are dispatch-authored and preserved across rescan;
  `reconcile_tx_key_retention` retires entries only against a *chain*
  reference (I-2).

**Per-field recoverability under chain replay** (R1-1; replaces round
0's flat "replay is blind" claim, which overstated the loss — and whose
"the spending txid is dropped once the spend confirms" line was stale:
the WI-RPC-3 spend-quadruple already persists it, and replay re-derives
it).

| Field | Replay recovers? | Source (verified) |
| --- | --- | --- |
| Fact of spend (which of our outputs) | **Yes** | `TransferDetails.key_image` populated at ingest (`shekyl-scanner/src/ledger_ext.rs` `LedgerIndexesExt` doc; `shekyl-engine-state/src/transfer.rs:192`); spend observed by key-image match |
| Spending txid | **Yes** | `KeyImageObserved.containing_tx_hash` (`shekyl-engine-core/src/scan.rs:229`) → `td.spending_tx_hash` written at scan-time mark-spent (`shekyl-engine-state/src/ledger_indexes.rs:184`) |
| Spend height | **Yes** | `spent_height` on the funding row |
| Fee | **Yes** | cleartext varint on the CT wire — grammar `Ct(Fcmp) := 0x01 V(fee) referenceBlock[32]`, `fee: u64` (`shekyl-wire/src/transaction.rs`); readable for any tx identified as ours via the spending txid |
| Change output + amount | **Yes** | our own received output — ordinary receive-side scan |
| Total sent | **Yes (derived)** | Σ(our spent inputs' amounts — known, they are our outputs) − change − fee |
| Recipient addresses | **No** | one-time output keys; nothing on chain links an output to an address without the recipient's view material |
| Per-recipient split | **No** | CT commitments hide non-ours output amounts; without addresses there is no per-recipient attribution |

**Consequence (load-bearing for SJ-DQ-1/4/5):** a journal row with no
recipient addresses forfeits nothing replay cannot rebuild — txid,
height, fee, total sent, and change are all recoverable. The journal's
*unique* contribution is counterparty identity and the per-recipient
split — exactly the field C1 names as the most dangerous thing the
wallet could write. The record is still required (a *usable* history
should not demand a full replay, states like `PresumedDead` are not
chain-derivable, and the dispatched input set must survive the rescan
wipe per the reframed SJ-DQ-4) — but the cost of *not storing
addresses* is convenience, not history.

## 2. Binding constraints (inputs to the round, not open questions)

- **C1 — privacy of the record** *(RATIFIED at R1 pass 1, premise
  corrected per R1-4's check)*. Recipient addresses and the
  per-recipient split are the most sensitive artifact the wallet would
  write locally — and per the §1 table, the only unrecoverable one.
  Premise as verified: a seized wallet file today already discloses
  **user-curated** counterparty data — the address book
  (`bookkeeping_block.rs::AddressBookEntry { address, description,
  payment_id }`, rescan-preserved); payment-request rows carry our own
  receiving side (FA-8), not counterparties. The journal would be the
  first **automatic, comprehensive** counterparty record: the
  disclosure delta is "every send ever made" versus "payees the user
  chose to save." Every field in SJ-DQ-1 carries an explicit
  disclosure-ledger entry, and prune policy (SJ-DQ-5) is first-class
  scope (rule 00 priority 2; rule 82).
- **C2 — one owner per fact; the journal owns dispatch facts**
  *(RATIFIED at R1 pass 1 in this wording, per R1-3)*. The journal
  **owns** what the wallet authored at dispatch — the selected input
  set, the realized recipients/fee, the dispatch height. Everything
  else it **references**: the F14 awaiting-confirmation state is
  *derived from* the journal's dispatch facts, never stored a second
  time; the `tx_keys` lifecycle stays where WI-RPC-3 put it; and
  `PresumedDead` **never** deletes a retained `TxSecretKey` (the
  FOLLOWUP's named hazard: deleting proof material for a tx that later
  confirms).
- **C3 — inform-never-drive** (`DAEMON_SUBMIT_VERDICT.md` §5). Journal
  states inform users and gate *user-initiated* actions (abandon,
  rescan); no journal state drives lock release or settlement. Refresh
  and the watchdog remain the only settlement authorities.
- **C4 — rule 42, with the placement exclusion named** *(reworded per
  R1-2)*. The row lives in a **dispatch-authored persisted block**
  (`tx_meta` / `bookkeeping` class) and is **excluded from
  `LedgerBlock` by C7** — `LedgerBlock` is reset wholesale by
  `reset_scan_derived_state` ("total reconstruction, not a
  field-by-field clear", `engine/rescan.rs`), so placing the row there
  is not a schema choice but data loss. Schema change ⇒
  version-constant bump + snapshot update, atomically in the landing
  PR.
- **C5 — v3-from-genesis (rule 60).** No backfill exists as a problem:
  pre-genesis there are no historical mainnet sends, and wallet2 import
  is out of scope permanently. Rows exist from feature-landing forward.
- **C6 — rescan contract (#401)** *(reworded per R1-2: the old "joins
  the preserve set" phrasing was vacuous-or-unsatisfiable depending on
  SJ-DQ-6's answer)*. The journal survives rescan **by construction**:
  it lives outside `LedgerBlock` (C4/C7), and reset reconstructs only
  `LedgerBlock` + its indexes — nothing needs to remember to preserve
  it. `-29202` keeps refusing on a live in-flight record until the
  user abandons (never auto); the reframed SJ-DQ-4 names what the
  journal must carry for the refusal's harm to stay closed across the
  wipe.
- **C7 — `LedgerBlock` holds only scan-derived types** *(NEW at R1
  pass 1, RATIFIED per R1-2)*. Enforced by a marker trait (named in
  PR-SJ-1), so a dispatch-authored row cannot be added to
  `LedgerBlock` without failing to compile — converting #401's
  reset-by-construction guarantee from comment-dependent to
  compiler-enforced. Honest current-state caveat: the trait bounds
  *types*, and one **field-level** exception exists today —
  `TransferDetails.awaiting_confirmation` (and the dispatch-time spent
  marking) are dispatch-authored state on a scan-derived row, safe
  only because `-29202` refuses to wipe while they are live. The
  R1-3 inversion (F14 state derived from the journal's dispatch facts,
  C2) is what retires that exception; PR-SJ-1 documents it at the
  trait until then.

## 3. Design questions

- **SJ-DQ-1 — record shape and its disclosure ledger** *(re-posed
  against the §1 table, R1-1/R1-4)*. The table inverts round 0's
  cost/benefit: a no-addresses row (`txid`, `dispatched_at_height`,
  `fee`, `state`, total, change) forfeits nothing replay cannot
  rebuild — the choice is about counterparty identity alone. R1
  leaning on record: **addresses not stored by default** — the
  asymmetry argument (a user lacking the record loses convenience; a
  seized user loses their counterparties irreversibly, while the rest
  of the history survives either way). The counter, held as genuinely
  strong: a wallet that cannot say who you paid is a poor wallet;
  users will enable the knob universally, and an opt-in everyone
  enables is protection theater plus a knob — the exact rule-81
  failure mode. **The decisive test is empirical, and runs before
  ratification, not during:** mock the reduced GUI transaction row
  (date / total / fee / txid, plus an address-book join where a
  counterparty happens to be a saved payee) and judge whether the list
  is usable. Usable ⇒ default-off is right; unreadable ⇒ opt-in is
  theater and the honest answer is store-by-default with a serious
  SJ-DQ-5 prune story. Option opened by the C1 premise check: rows
  could store an **address-book entry reference** instead of a raw
  address (user-curated indirection — deleting a contact anonymizes
  their history); evaluate alongside, not instead of, the default
  question.
- **SJ-DQ-2 — write point and crash window.** Dispatch-time beside
  `record_retained_tx_key` under the same guard (extending the I-2
  atomic-write pattern: record exists before the bytes can reach the
  daemon), vs. finalize-accept. What does a crash between dispatch and
  verdict leave, and is the residue reconciled by the same paths that
  reconcile retention?
- **SJ-DQ-3 — state machine and per-edge authority.**
  `Dispatched → Confirmed{height} | TerminalRejected | PresumedDead |
  Abandoned`, plus reorg back-edges (`Confirmed → Dispatched`-class).
  Produce the per-edge authority table (refresh / watchdog / submit
  verdict / user) and audit each edge against C3.
- **SJ-DQ-4 — the spend marking survives the wipe; `PresumedDead` is a
  display state** *(REFRAMED per R1-3; round 0 asked the wrong
  question)*. Round 0 treated `PresumedDead` as an evidence threshold
  whose effect is "rescan unblocks" — which makes the evidence bar
  carry the entire `-29202` harm (wipe destroys the spend marking →
  inputs return to selection → two transactions provably spending one
  input self-link the wallet, §7.1), so the bar had to be near-proof,
  and without a daemon pool query no such evidence exists. That is why
  arm 2 felt unreachable. **Inverted:** the journal row carries the
  **dispatched input set** across the wipe (a dispatch fact the wallet
  authored — C2's ownership), and after rescan the spend markings are
  **re-applied from the journal**. A wrong `PresumedDead` is then not
  catastrophic: the inputs stay locked either way, and a late
  confirmation is a state flip, not a self-link. The evidence bar
  collapses from "prove non-exposure" to "good enough to show the
  user" (watchdog confirmed-absent horizon + F31 status-query outcome
  + breaker state), and abandon becomes fully self-contained — arm 2
  reached without a daemon feature. Remaining questions for pass 2:
  the re-application mechanics (post-rescan join of journal input sets
  onto replayed rows; what happens when replay already re-derived the
  spend via key image — idempotent re-mark), the crash ordering of the
  late-confirmation flip, and which `-29202` refusals this retires
  versus keeps.
- **SJ-DQ-5 — prune and deletion policy** *(re-posed against the §1
  table)*. Pruning a no-addresses row is low-stakes — its content is
  replay-equivalent — so the question sharpens to the fields that are
  not: the address field (if SJ-DQ-1 stores one, in raw or
  book-reference form) and the row's relationship to the retained
  `TxSecretKey` (C2: prune must not cascade into proof material; do
  they share a lifetime or not — decide explicitly). State the
  seized-file story before and after prune, per C1's disclosure
  ledger.
- **SJ-DQ-6 — schema placement and migration** *(re-posed under C7)*.
  `LedgerBlock` is excluded by C7, so the candidates are a sibling
  dispatch-authored block beside `tx_meta`/`bookkeeping` vs. a new
  block; version bump + snapshot (C4); KAT for the persisted form; and
  PR-SJ-1 lands the C7 marker trait with the documented
  `awaiting_confirmation` field-level exception and its planned
  retirement.
- **SJ-DQ-7 — projection contract.** OUTGOING rows have no
  output index: id scheme (`txid`-keyed vs. the receive rows'
  `txid:index`), fee population, INCOMING/OUTGOING interleave ordering
  in `get_transfers`, additive OpenAPI deltas, and the CLI/GUI
  enablement that closes W-D end to end.
- **SJ-DQ-8 — `abandon_tx` contract.** `-291xx` code allocation,
  idempotency, the crash-ordering test the FOLLOWUP names
  (drop-then-confirm window), and the `start_rescan` interplay (keeps
  refusing until the user abandons — never auto-abandon). **The force
  path is NOT deferred** *(pulled into R1 per R1-5)*: whether abandon
  requires `PresumedDead` or admits an explicit double-confirm force
  is a safety decision that rewrites SJ-DQ-4's calculus, and it will
  be exercised under support pressure, not in the happy path. Note for
  the R1 pass-2 decision: the SJ-DQ-4 inversion also defuses it — with
  the spend marking journal-carried and re-applied, a forced abandon
  bypasses only the display evidence, not the self-link safety; decide
  whether that makes a force path acceptable or merely tempting.

## 4. Shape of the work (decomposition RATIFIED at R1 pass 1)

R1 pass 1 ratified the decomposition below and C1/C2/C3/C5/C7 + §5;
pass 2 ratifies the re-posed SJ-DQ-1/4/5/6 (unblocked by the §1 table)
plus the force-path sub-question; the rest of SJ-DQ-7/8 ratifies with
its PRs. The SJ-DQ-1 GUI-usability test (mock the reduced row) runs
before pass 2. Per R1-6, every deferral pass 2 creates carries named
rule-21 reopen criteria at ratification. Then:

1. **PR-SJ-1** — journal record + schema bump + preserve-set wiring +
   state machine on the dispatch/verdict/refresh/watchdog edges
   (engine-core + engine-state; closes nothing yet, enables both).
2. **PR-SJ-2** — projections: `transfer_view` OUTGOING + fee, CLI, GUI
   list. Closes the W-D FOLLOWUP.
3. **PR-SJ-3** — `PresumedDead` entry + `abandon_tx` Engine API + RPC +
   crash-ordering test. Closes the abandon FOLLOWUP.

Rounds run standard (not rule-26 opt-in): no consensus surface, no FFI
widening, single-team.

## 5. Non-goals

- wallet2 history import (rule 60) and any Monero-compat history shape.
- Multi-device journal sync or export formats.
- Retroactive reconstruction of pre-journal sends (impossible under CT;
  C5 makes it moot).
- Any change to settlement authorities or the F14 lock lifecycle (C3).
