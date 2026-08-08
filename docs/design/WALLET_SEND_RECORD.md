# Wallet Send Record — W-D outgoing history + `abandon_tx` (design round 0)

**Status:** Round 0 opened 2026-08-05; **R1 pass 1 folded 2026-08-05**
(review on the round-0 text, findings R1-1..R1-6). Ratified at pass 1:
**C1** (premise corrected per R1-4's check — see §2), **C2** (reworded
to the R1-3 ownership form), **C3**, **C5**, **C7** (new, per R1-2),
the **§5 non-goals**, and the **PR-SJ-1/2/3 decomposition**.
**R1 pass 2 folded 2026-08-05**: **C1 REPLACED** (the envelope is the
boundary — the pass-1 form was wrong twice over, see §2), **SJ-DQ-1
DECIDED** (full row, addresses stored, no knob; the reduced-row GUI
mock and its gate are **withdrawn**, not downgraded — findings M-1..M-4
die with the instrument), **SJ-DQ-5 re-scoped** (user control, not
seizure defense), **SJ-DQ-7 widened by scope ruling** (the dormant
`tx_notes` annotation surface folds in and ships with PR-SJ-2), and
the `attributes` bag gets its **own disposition** (deletion-leaning,
below). **Pass-2 amendment (2026-08-05):** the §1 table gains the
FA-10 label row — payment-request linkage (`LABEL_KIND_REQUEST` rid in
`enc_label`) is **conditionally** replay-recoverable via the OUTBOUND
re-derivation chain given the retained tx key and a candidate
recipient address; checked against SJ-DQ-1 before its ratification
finalizes, and it does not disturb the decision (see the table's
amendment note). **Roadmap fold (2026-08-06):** the C++-retirement
roadmap review adds two edges — SJ-DQ-1 gains the R-4 fee-provenance
clause (realized fee of the built tx, never an estimator value), and
SJ-DQ-3's ratification is gated on the roadmap's A4 cold-bundle
decision (R-2). Still open for pass 3: SJ-DQ-4's remaining mechanics,
SJ-DQ-5's control design, SJ-DQ-6, and the `abandon_tx` force-path
sub-question (pulled up from SJ-DQ-8 at pass 1, R1-5).
**Pass 3 RATIFIED (2026-08-06; P3-1..P3-5 stamped inline, two
refinements at ratification):** P3-1a is **split, pre-committed** —
PR-SJ-1 lands the reclassification, the journal facts sufficient to
derive `awaiting_confirmation`, and a **both-agree equivalence
invariant** against the live field (making PR-SJ-1b a deletion, the
interim state redundant-but-consistent, and C7's exception provably
vacuous from PR-SJ-1); PR-SJ-1b lands the 91-reference retirement as
its own graded PR. P3-4's reopen criterion is tightened to match the
code: reopen if a blocked flow emerges **that discard cannot clear**
(the reservations half of `-29202` still refuses). Proposal record: P3-1 rescan re-application mechanics + the
`-29202` split (unconfirmed half retires, reservations half stays;
sub-question P3-1a poses the `awaiting_confirmation`
derived-cache/retirement scope call); P3-2 two-tier deletion with
independent `tx_keys` lifetime; P3-3 dedicated `send_journal` block
with append-only state enum (the A4 clause-(2) pin); P3-4 no force
path + abandon reframed to the retention-reference migration; P3-5
`attributes` deletion ratified as posed. Decisions stamp
into the section that carries them, dated, per the binding-record
convention (`DAEMON_SUBMIT_VERDICT.md` §1 shape). Per R1-6: any
deferral R1 creates carries named rule-21 reopen criteria at
ratification time, not at PR time.

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
- **The envelope** (`../WALLET_FILE_FORMAT_V1.md` §1): every persistent
  wallet mutation outside the keys file lives in the AEAD-sealed
  `.wallet` container (Argon2id → wrap key → random file KEK → HKDF
  per-region keys; cross-bound to `.wallet.keys`). Stance Minimum-Leak:
  a sealed file discloses nothing — no balance, no history, not even
  network or capability mode. The journal lands inside this envelope by
  construction, beside the transfers cache; the companion file already
  holds the spend seed.
- **FA-10 labels** (`shekyl-crypto-pq/src/label.rs`; §5.7.11, adopted
  2026-05-31): every output carries a fixed 8-byte plaintext
  XOR-encrypted under per-output `k_label` + a 1-byte `label_tag`,
  same discipline as amounts. Sentinel `[0xFF; 8]` when nothing is
  said; on-wire bytes differ per output even for sentinel sends (no
  cleartext-constant path); slot presence is not optional on wire
  (`../POST_QUANTUM_CRYPTOGRAPHY.md` — gating means a wallet feature
  flag for meaningful tags, never slot absence). `LABEL_KIND_REQUEST`
  echoes a payment-request rid; `k_label` is one branch of the single
  per-output `OutputSecrets` HKDF tree the OUTBOUND proof already
  re-derives from the retained tx key.
- **A dormant annotation surface already exists**:
  `tx_meta.tx_notes: BTreeMap<[u8;32], String>` ("user-authored
  free-text notes, keyed by txid") and the untyped `attributes` bag
  (`shekyl-engine-state/src/tx_meta_block.rs:183–191`) — persisted,
  sealed, schema-versioned, rescan-preserved (`engine/rescan.rs`
  preserve list), and promised to clients in the published contract
  (`../api/wallet_rpc.yaml` `rescan_blockchain`: "user-authored
  records (retained tx keys, notes, …) survive") — with **zero
  production readers or writers** (verified: the only other mention
  deliberately excludes them from an invariant). The WI-RPC-3-F-1
  dormancy class: contract-referenced state no user can reach.

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
| Payment-request linkage (rid echoed in `enc_label`, FA-10 `LABEL_KIND_REQUEST`) | **Conditional** — retained `tx_key` ∧ candidate recipient address | every output carries the uniform 8-byte label slot (`shekyl-crypto-pq/src/label.rs`, §5.7.11/FA-10; sentinel or tag, wire-indistinguishable); the sender re-derives `k_label` exactly as the OUTBOUND proof does — `rederive_combined_ss(tx_key_secret, recipient_x25519_pk, recipient_ml_kem_ek, idx)` (`shekyl-proofs/src/tx_proof.rs`) → `derive_output_secrets(...).k_label` (`derivation.rs`) → decrypt + `classify_label_plaintext`. Needs the recipient's *address material* as input, so it is trial-derivation against known addresses (journal rows post-SJ-DQ-1, or the address book) — never blind |

**Consequence (load-bearing for SJ-DQ-4, and for honesty about what
the journal adds):** replay rebuilds txid, height, fee, total sent,
and change; the journal's *unique* content is counterparty identity,
the per-recipient split, and the non-chain-derivable states
(`PresumedDead`, the dispatched input set that must survive the rescan
wipe per the reframed SJ-DQ-4). At pass 1 this table was also carrying
SJ-DQ-1's retention question; pass 2 settled that on different ground —
the envelope frame (C1) — so the table no longer arbitrates a storage
default. It remains the authority on what must ride the journal versus
what replay provides for free.

**FA-10 amendment (2026-08-05, checked before SJ-DQ-1's ratification
finalizes):** the label row above was missing at pass 1. Two
consequences, neither disturbing the SJ-DQ-1 decision. (1) Honesty:
request-linkage is *not* journal-unique — it is conditionally
replay-recoverable, and the condition (a candidate address) is exactly
what the decided full row stores, so the decision is self-consistent
with its own recoverability story. (2) PR-SJ-1: the journal stores the
echoed rid **directly at dispatch** (the send path computes it —
`encode_request_plaintext` behind the FFI URI-pay path; a dispatch
fact under C2's ownership), so surfacing "paid request #N" never
requires the trial re-derivation; the derivation chain is the *replay*
story, not the read path.

## 2. Binding constraints (inputs to the round, not open questions)

- **C1 — the envelope is the boundary** *(REPLACED at R1 pass 2; both
  pass-1 forms were wrong)*. Pass 1 called recipient addresses "the
  most sensitive artifact the wallet would write locally" and reasoned
  from a seized file. Neither premise survived §1's grounding: the
  journal lands inside the AEAD-sealed `.wallet` envelope by
  construction — the same container that holds the transfers cache,
  beside a keys file holding the **seed**, which is strictly more
  sensitive than any address — and the wallet already commits to
  user-authored counterparty-bearing records inside that envelope
  (`tx_notes`: an invoice number ties a payment to a named business
  relationship, an amount owed, and a date; rescan-preserved and
  contract-promised). A sealed file discloses *nothing* (Minimum-Leak);
  in the only world where the journal is readable — seized file **plus
  password** — the adversary holds the spend keys and the complete
  incoming history, and withholding a payee address protects no one.
  Privacy-by-omission also *displaces* rather than deletes: the record
  moves to a notes app or spreadsheet — no Argon2id, no AEAD, no
  anti-swap binding, likely cloud-synced — a measurable privacy loss.
  A rule that fires only against the feature under discussion is a
  preference, not a principle. **The binding constraint:** the journal
  inherits the envelope's guarantees and never leaves it except at
  named, disciplined boundary crossings, which is where the
  disclosure ledger points —
  - **the RPC wire**: `get_transfers` OUTGOING puts addresses in
    responses, and the contract permits a TCP listener
    (`shekyl-wallet-rpc/src/server.rs` `ListenAddr`), not only the
    0600-UDS spawn path;
  - **process memory** (rules 35/36): zeroize discipline, no `Debug`
    that renders addresses, no path into error strings (the
    WI-RPC-2a precedent that stopped internal errors echoing paths);
  - **logs, crash dumps, backups**: cheap at PR-SJ-1, expensive later.
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

- **SJ-DQ-1 — DECIDED at R1 pass 2: full row, addresses stored, no
  knob.** The row records the send the wallet actually made:
  `recipients[{address, amount}]`, fee, change, heights, state.
  Settled by C1's envelope frame, not by the §1 table: inside the
  sealed container that already holds the seed and commits to
  `tx_notes`, there is no coherent policy that admits the seed and
  excludes a payee address — and not writing the record displaces it
  to unprotectable storage. The pass-1 leaning (default-off) is
  reversed; the pass-1 "counter" was simply correct — an opt-in
  everyone enables is protection theater plus a knob, the exact
  rule-81 failure mode. **The reduced-row GUI mock and its
  ratification gate are withdrawn, not downgraded** (its findings
  M-1..M-4 die with the instrument): it was apparatus built to answer
  a question the envelope had already answered. The
  address-book-reference option is demoted to what it is —
  normalization (one place to rename a contact), evaluated on
  convenience merits in PR-SJ-2, carrying no privacy argument. The
  disclosure ledger's remaining work is C1's boundary crossings, not
  field selection. **Fee provenance (folded 2026-08-06, roadmap
  review R-4):** the recorded fee is the realized fee of the built
  transaction (`PendingTx.fee_atomic_units` — the same value the wire
  tx pays and the chain sees in cleartext, §1 table), never an
  estimator output. This keeps the row correct through the
  stub-estimator era: a stub-informed *choice* still yields a real
  on-chain fee, and the journal records what happened, not what was
  predicted — durable wrong data being worse than a display bug.
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
  verdict / user) and audit each edge against C3. **Pass-3 gate
  (added 2026-08-06, roadmap review R-2):** ratifying this machine is
  gated on the C++-retirement roadmap's **A4 decision** (air-gapped
  `UnsignedTxBundle`/`SignedTxBundle` in or out of scope). In scope ⇒
  the machine grows exported-unsigned / signed-elsewhere states and
  `build_pending_tx` grows an export path — the same function PR-SJ-1
  modifies; descoped ⇒ neither exists. Deciding A4 after ratification
  would mean reopening a ratified design, so A4 resolves before pass 3
  freezes this. **B2 is DECIDED (2026-08-06: delete the hardware-device
  C++ surface with Phase 5, rule-21 clause in `FOLLOWUPS.md` — and it
  touches no journal state, so it never gated this machine).**
  **A4 is DECIDED (2026-08-06: cold bundles DESCOPED from V3.0 —
  clause in `FOLLOWUPS.md` "A4 DECIDED"): the V3.0 machine ships
  WITHOUT `ExportedUnsigned`, and the GATE IS CLEARED — pass 3 is
  unblocked.** One obligation transfers into PR-SJ-1 from the A4
  clause, item (2): verify the persisted state-machine encoding
  admits a future `ExportedUnsigned` variant (a new variant and a
  field) **additively** — no version break, no schema migration —
  and pin that with a test while it is cheap.
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
  user" (watchdog confirmed-absent horizon + F31 status-query
  outcome + breaker state), and abandon becomes fully self-contained
  — arm 2
  reached without a daemon feature. Remaining questions for pass 2:
  the re-application mechanics (post-rescan join of journal input sets
  onto replayed rows; what happens when replay already re-derived the
  spend via key image — idempotent re-mark), the crash ordering of the
  late-confirmation flip, and which `-29202` refusals this retires
  versus keeps.
  **P3-1 RATIFIED (2026-08-06).**
  *Re-application:* after `reset_scan_derived_state` + replay, for
  every journal row in a **non-terminal or `Abandoned` state**, for
  each input in its carried set: if replay already marked the funding
  row spent (key-image observed — confirmed evidence supersedes),
  skip; else re-derive the awaiting-confirmation lock from the journal
  facts. `Abandoned` is terminal for the display machine, but
  late-confirmation still flips `Abandoned → Confirmed` (P3-4); the
  wipe must re-lock those inputs or SJ-DQ-4's self-link defence fails
  for abandoned-but-still-landable sends. The re-application set
  therefore matches P3-4's I-2 reference list
  ("non-terminal-or-abandoned"), not "non-terminal" alone.
  Set-union semantics — deterministic and idempotent by construction;
  pinned by a test that runs re-application twice and diffs nothing.
  *Crash ordering:* every journal edge is written inside the same
  wallet-ledger guard as the state change that triggers it (the
  finalize / refresh / watchdog write sites), and persistence is a
  single atomic envelope replace (`engine-file` `atomic.rs`;
  `drive_persistence` under one exclusive hold — the rescan path's
  own comment pins the pattern), so a crash never splits a trigger
  from its edge. *`-29202` splits:* the check is
  `reservations > 0 || unconfirmed > 0` (`rescan.rs:213`). The
  **unconfirmed half retires** in PR-SJ-1 — journal re-application is
  strictly stronger than refusing. The **reservations half keeps
  refusing**: a pre-dispatch build has no journal row, its output
  locks are in-memory indices into the very rows the wipe destroys,
  and the remedy (discard, then rescan) is cheap and in-session. Code
  `-29202` stays allocated; its message narrows to the reservations
  case. *P3-1a RATIFIED AS SPLIT, PRE-COMMITTED (2026-08-06):* the
  conditional "iff proportionate" form was rejected at ratification —
  that judgment would be made mid-PR under momentum, and the measured
  surface says it will not stay proportionate: **91 references across
  27 files, 17 production** — the balance hot path (7 refs,
  iai-instruction-gated: a reclassification there carries a
  performance-gate risk unrelated to the journal), `shekyl-engine-rpc`
  (2 refs that evaporate for free when B1 lands), and two committed
  schema snapshots (whose delta would stack a third independent
  change onto a schema review already carrying
  `SEND_JOURNAL_BLOCK_VERSION = 1` and the C7 marker). So: **PR-SJ-1**
  lands the derived-cache reclassification, journal facts sufficient
  to derive `awaiting_confirmation`, and a **both-agree equivalence
  invariant** (journal-derived locks == live field, checked with the
  ledger invariants) — making the interim state
  redundant-but-consistent and C7's documented exception **provably
  vacuous from PR-SJ-1**; **PR-SJ-1b** (pre-committed, not
  conditional) lands the field's retirement as a deletion graded on
  its own, sequenced so PR-SJ-2 does not land before it.
- **SJ-DQ-5 — prune is user control over their own history** *(re-scoped
  at R1 pass 2; seizure defense is the envelope's job, C1)*. The
  honest, smaller question: what deletion the user gets — a row, a
  counterparty's rows, the whole journal — with the C2 rule intact
  (prune never cascades into `tx_keys` proof material; decide the
  shared-or-independent lifetime explicitly) and the boundary story
  stated: a pruned row is gone from wallet-controlled storage and
  backups; storage the user copied elsewhere is their own.
  **P3-2 RATIFIED (2026-08-06).**
  two-tier deletion, `tx_keys` lifetime **independent**. Tier 1
  (default): delete journal row(s) — one row, all rows for a
  counterparty (a filter over the same operation), or the whole
  journal. Never touches `tx_meta.tx_keys` (C2: proof material has
  its own lifecycle; a deleted row's OUTBOUND proof still works,
  stated plainly in the UX). Tier 2 (explicit, rule-82 warned):
  full scrub — row plus retirement of the retained `TxSecretKey`,
  destroying the OUTBOUND-proof capability for that txid; requires
  the same class of explicit confirmation as seed display. Honest
  boundary line in both tiers: a seized file after tier-1 deletion
  still shows `tx_keys` membership (txid-was-ours), only tier 2
  removes that — and neither reaches copies the user made outside
  the wallet's storage. No retention time-bound in V3.0 (no
  auto-expiry knob — rule 81; deletion is a user act).
- **SJ-DQ-6 — schema placement and migration** *(re-posed under C7)*.
  `LedgerBlock` is excluded by C7, so the candidates are a sibling
  dispatch-authored block beside `tx_meta`/`bookkeeping` vs. a new
  block; version bump + snapshot (C4); KAT for the persisted form; and
  PR-SJ-1 lands the C7 marker trait with the documented
  `awaiting_confirmation` field-level exception and its planned
  retirement.
  **P3-3 RATIFIED (2026-08-06).** a
  **dedicated block** — `send_journal` on `WalletLedger` beside
  `tx_meta`/`bookkeeping`, with its own `SEND_JOURNAL_BLOCK_VERSION
  = 1` (the `BOOKKEEPING_BLOCK_VERSION` precedent: per-block
  versioning, no coupling to `tx_meta`'s bump history), its own
  snapshot + KAT, preserved across rescan by construction (outside
  `LedgerBlock`). C7's marker trait lands in the same PR; the
  `awaiting_confirmation` exception follows P3-1a's resolution. The
  A4 clause-(2) pin lands here concretely: the row's state enum is
  **append-only** (a doc-pinned rule at the enum plus a
  discriminant-stability KAT), so the future `ExportedUnsigned`
  variant and its field are additive — old files read forward, no
  version break, no migration.
- **SJ-DQ-7 — projection contract, widened to cover annotations**
  *(scope ruling at R1 pass 2, run against rule 19)*. The journal
  half: OUTGOING rows have no output index — id scheme (`txid`-keyed
  vs. the receive rows' `txid:index`), fee population,
  INCOMING/OUTGOING interleave ordering in `get_transfers`, additive
  OpenAPI deltas, and the CLI/GUI enablement that closes W-D end to
  end. The annotation half: the dormant `tx_notes` surface (§1)
  shares exactly this projection surface — a note attaches to a
  transfer row of either direction — and none of the record surface
  (no lifecycle, no crash window, no state machine). Ruling: **fold
  annotation exposure in here and ship it with PR-SJ-2** — a
  `set_tx_note` / note-on-`TransferView` pair plus the OpenAPI delta,
  no engine work beyond read/write — so the projection contract is
  designed once. It is not gated on the journal; pull it into its own
  small PR only if wanted sooner than PR-SJ-2.
- **`attributes` — its own disposition, not a ride-along** *(posed at
  R1 pass 2; ratify at pass 3)*. The untyped `String → String` bag is
  wallet2-lineage shape by its own docstring ("Wallet2 used an
  `unordered_map<string, string>`"), with no reader, no writer, no
  defined semantics — an inherited forward-compat reservation that
  never earned a consumer. Rules 60/81 point at deletion, not
  exposure. Disposition to ratify: **delete in PR-SJ-2's schema
  touch** (the rule-42 bump is already being paid there); rule-21
  reopen criterion = a named, typed UX-state need that `tx_notes`
  cannot carry.
  **P3-5 RATIFIED (2026-08-06), as posed** — delete `attributes` in PR-SJ-2's schema bump, with the
  stated reopen criterion. No counter-argument surfaced across three
  passes; zero consumers verified twice.
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
  **P3-4 RATIFIED (2026-08-06): no force path — and abandon's job
  reframes.** With P3-1 retiring the
  unconfirmed half of `-29202`, abandon is no longer load-bearing for
  rescan — the "support pressure" scenario that would exercise a
  force path dissolves, because nothing is blocked waiting on an
  abandon. The inversion defuses the *safety* half of force, but its
  only remaining product is hiding a row early, which SJ-DQ-5's
  tier-1 deletion already provides through the honest door — so a
  force path is a knob with no unique capability (rule 81): decline.
  Reopen criterion, worded to match what P3-1 actually delivers
  (the reservations half of `-29202` still refuses, with
  discard-then-rescan as the in-session remedy): reopen if a blocked
  flow emerges **that discard cannot clear**. *Abandon's remaining real job* —
  the retention wedge: `reconcile_tx_key_retention` retires entries
  only against a chain reference, so a dead tx's
  `pending_tx_hashes` entry lives forever. `abandon_tx` becomes: the
  journal edge `Dispatched|PresumedDead → Abandoned` (user-authored,
  C3-clean) **plus migrating the I-2 live reference from
  `sync_state.pending_tx_hashes` to the journal row itself** — keys
  retained per C2, the pending set stays a true live-work set, and
  the I-2 invariant extends its reference list with "journal row in
  a non-terminal-or-abandoned state". The crash-ordering test the
  FOLLOWUPS entry names (drop-then-confirm) pins the reference
  migration + the late-confirmation flip `Abandoned → Confirmed`
  (which un-abandons loudly rather than staying wrong).

## 4. Shape of the work (decomposition RATIFIED at R1 pass 1)

R1 pass 1 ratified the decomposition below and C2/C3/C5/C7 + §5; pass
2 replaced C1, decided SJ-DQ-1, re-scoped SJ-DQ-5, and widened
PR-SJ-2's scope with the annotation exposure and the `attributes`
disposition. Pass 3 ratifies what remains: SJ-DQ-4's re-application
mechanics, SJ-DQ-5's control design, SJ-DQ-6, the force-path
sub-question, and the `attributes` deletion. The rest of SJ-DQ-7/8
ratifies with its PRs. Per R1-6, every deferral carries named rule-21
reopen criteria at ratification. Then:

1. **PR-SJ-1** — journal record (`send_journal` block, own version,
   append-only state enum with the A4 clause-(2) additive pin) +
   state machine on the dispatch/verdict/refresh/watchdog edges plus
   rescan re-application (retiring the unconfirmed half of `-29202`)
   and the C7 marker trait; the `awaiting_confirmation`
   derived-cache reclassification + the both-agree equivalence
   invariant land here; field retirement is **PR-SJ-1b**
   (pre-committed; PR-SJ-2 does not land before it)
   (engine-core + engine-state; closes nothing yet, enables both).
2. **PR-SJ-2** — projections: `transfer_view` OUTGOING + fee, CLI, GUI
   list; the annotation exposure (`set_tx_note` + note on
   `TransferView`, both directions); the `attributes` deletion (if
   pass 3 ratifies it — the rule-42 bump is shared). Closes the W-D
   FOLLOWUP.
3. **PR-SJ-3** — `PresumedDead` entry + `abandon_tx` Engine API + RPC +
   crash-ordering test. Closes the abandon FOLLOWUP.
   **LANDED 2026-08-07 (`feat/wallet-abandon-sj3`)** — the
   `PresumedDead` entry had landed with PR-SJ-1's confirmed-absent
   release; this PR appended `SendState::Abandoned` (append-only pin
   held: v1 discriminants byte-identical), `WalletLedger::abandon_send`
   (edge + I-2 reference migration, journal leg added to I-2 and the
   retention reconcile), the P3-1 re-application extension to Abandoned
   rows, `Engine::abandon_tx_persisted`, RPC `abandon_tx` (`-29108`,
   idempotent, no force path per P3-4), and the drop-then-confirm
   crash-ordering test (`Abandoned → Confirmed` flips loudly, keys
   intact).

Rounds run standard (not rule-26 opt-in): no consensus surface, no FFI
widening, single-team.

## 5. Non-goals

- wallet2 history import (rule 60) and any Monero-compat history shape.
- Multi-device journal sync or export formats.
- Retroactive reconstruction of pre-journal sends (impossible under CT;
  C5 makes it moot).
- Any change to settlement authorities or the F14 lock lifecycle (C3).
