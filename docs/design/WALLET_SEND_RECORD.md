# Wallet Send Record — W-D outgoing history + `abandon_tx` (design round 0)

**Status:** Round 0 OPEN (2026-08-05). This document poses the round's
questions with their grounded constraints; nothing here is ratified.
Decisions stamp into the section that carries them, dated, per the
binding-record convention (`DAEMON_SUBMIT_VERDICT.md` §1 shape).

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

## 1. Grounding (source-verified, 2026-08-05, dev @ `353880c1f`)

- Receive side: `TransferDetails` rows are outputs we received; a spend
  surfaces only as `spent`/`spent_height` on the funding row. The
  spending txid is dropped once the spend confirms.
- Send side at dispatch: `ConsumerHeldEntry` already carries everything
  a history row could want — `request` (recipients + amounts), `fee`
  (via meta), `tx_bytes`, the content `fingerprint`, heights — and drops
  it all when the reservation resolves.
- Retention (WI-RPC-3): `tx_meta.tx_keys` + `sync_state.
  pending_tx_hashes` are dispatch-authored and preserved across rescan;
  `reconcile_tx_key_retention` retires entries only against a *chain*
  reference (I-2).
- **CT makes replay blind:** under FCMP++/CT a chain rescan cannot
  recover recipients, amounts, or fee for our own sends. Any outgoing
  history is therefore dispatch-authored, must-preserve class — there is
  no "rebuildable" design available, which is why W-C could not answer
  W-D and a distinct record is required.

## 2. Binding constraints (inputs to the round, not open questions)

- **C1 — privacy of the record.** Recipient addresses and amounts are
  the most sensitive artifact the wallet would ever write locally; a
  seized or exfiltrated wallet file currently discloses *no*
  counterparty data, and this feature is the first that could change
  that. Every field in SJ-DQ-1 carries an explicit disclosure-ledger
  entry, and prune policy (SJ-DQ-5) is first-class scope (rule 00
  priority 2; rule 82).
- **C2 — one owner per fact.** The journal must not duplicate the
  `tx_keys` lifecycle or the F14 lock state; it references, never
  copies, and `PresumedDead` **never** deletes a retained
  `TxSecretKey` (the FOLLOWUP's named hazard: deleting proof material
  for a tx that later confirms).
- **C3 — inform-never-drive** (`DAEMON_SUBMIT_VERDICT.md` §5). Journal
  states inform users and gate *user-initiated* actions (abandon,
  rescan); no journal state drives lock release or settlement. Refresh
  and the watchdog remain the only settlement authorities.
- **C4 — rule 42.** The row lives in the persisted `WalletLedger`
  block: schema change ⇒ version-constant bump + snapshot update,
  atomically in the landing PR.
- **C5 — v3-from-genesis (rule 60).** No backfill exists as a problem:
  pre-genesis there are no historical mainnet sends, and wallet2 import
  is out of scope permanently. Rows exist from feature-landing forward.
- **C6 — rescan contract (#401).** The journal joins the
  `reset_scan_derived_state` preserve set; `-29202` keeps refusing on a
  live in-flight record until the user abandons (never auto).

## 3. Design questions

- **SJ-DQ-1 — record shape and its disclosure ledger.** Candidate
  minimal row: `txid`, `dispatched_at_height`, `fee`, `state`,
  `recipients[{address, amount}]`, change amount. The source is the
  already-held `ConsumerHeldEntry` summary, so the question is not
  availability but *retention*: are recipient addresses stored always,
  opt-out, or reduced (amount-only rows)? What does the OpenAPI
  `TransferView` for an OUTGOING row promise, and what does rule 81
  require the default to be so users never manage this knob to be safe?
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
- **SJ-DQ-4 — `PresumedDead` safe entry.** The abandon blocker's arm 2,
  defined without a daemon pool query: candidate entry evidence =
  watchdog confirmed-absent horizon reached + F31 status-query outcome
  + breaker state. Entry effects: `start_rescan` unblocks; keys and the
  I-2 reference are retained. What flips it back on late confirmation,
  and is that path crash-ordered?
- **SJ-DQ-5 — prune and deletion policy.** User-initiated row deletion?
  Bounded retention? Does a journal row's deletion interact with the
  OUTBOUND proof surface (whose secret lives in `tx_keys`, C2)? State
  the seized-file story before and after prune.
- **SJ-DQ-6 — schema placement and migration.** Sibling block beside
  `tx_meta` vs. a new block; version bump + snapshot (C4); preserve-set
  wiring (C6); KAT for the persisted form.
- **SJ-DQ-7 — projection contract.** OUTGOING rows have no
  output index: id scheme (`txid`-keyed vs. the receive rows'
  `txid:index`), fee population, INCOMING/OUTGOING interleave ordering
  in `get_transfers`, additive OpenAPI deltas, and the CLI/GUI
  enablement that closes W-D end to end.
- **SJ-DQ-8 — `abandon_tx` contract.** `-291xx` code allocation,
  idempotency, precondition (`PresumedDead` only, or an explicit
  double-confirm force path?), the crash-ordering test the FOLLOWUP
  names (drop-then-confirm window), and the `start_rescan` interplay
  (keeps refusing until the user abandons — never auto-abandon).

## 4. Proposed shape of the work (for R1 to ratify)

R1 ratifies SJ-DQ-1..6; SJ-DQ-7/8 are contract details that can ratify
with their PRs. Then:

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
