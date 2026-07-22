# F-D2 drain-send subsystem — design round (Gate-6 R4's last open item)

**Status: SCOPING — review rounds 1–4 applied (threat-model axis closed,
maintainer-accepted 2026-07-19); opened 2026-07-19. No implementation has
begun; this document is the scoping artifact rule 26 requires before
code.**

Charter: `ARCHIVAL_FIREWALL_GATE6.md` §12.4 names F-D2's remaining half a
**whole unbuilt `P`-value-out (drain-send) subsystem in
`shekyl-gui-wallet`**, and Gate-6 §12.9's re-formed R4 close condition
(which supersedes the §12.8 line) is down to F-D1 (BUILT) + F-D2.

**Seal-path note** (2026-07-19, PR #337 scope
review, merged before this round's first review): the GF-4/F-D1+F-D2
`K_COVER` seal seat was **REMOVED** (`ARCHIVAL_REWARD_GATE_M1.md` §4 —
the drain is not an on-chain observable per F-W10, and the exit-timing
observable is a ratified phantom per F-W7/F-W8), so this subsystem is
**not** seal evidence and does not gate the `K_COVER` seal act *(moot as of 2026-07-19,
PR #346: there is no seal act — the gate is retired; this subsystem's scoping is unaffected,
it was never seal evidence either way)*. It
remains pre-genesis work on its own Gate-6 track: R4 is open on F-D2
alone, and the FOLLOWUPS "P-drain mechanism re-walk" riders are V3.0.

Process: this round cites **`26-sub-pr-design-discipline.mdc`**
explicitly — the work is a multi-sub-PR subsystem crossing an FFI-adjacent
boundary (Tauri GUI ↔ engine crates) with firewall-class (priority-2)
properties. A pre-flight pass (rule 26 §"Pre-flight pass") is owed between
this round's closure and the first production commit; the **core-side
half (DS-PR-1/DS-PR-2) was run early 2026-07-19** — substrate re-check +
artifact execution at `28870bd61`, one errata (R0-D1), all 24 core
artifacts green — recorded in `ARCHIVAL_DRAIN_SEND_FD2_AUDIT.md`. The
GUI-side half (DS-PR-3/4/5) is carried to each GUI sub-PR's open
(R0-D3-B). Design questions
mint the **DS-N** family (registered at birth in
`IMPLEMENTATION_INDEX.md` §2 per rule 94; prefix `DS-` passes the
uniqueness check — no registered family's tokens parse as `DS<digits>`).

---

## 1. Close condition (what "F-D2 landed" means)

F-D2 is recorded as landed when **all three layers exist and the arms
hold** (Gate-6 §12.4 build notes, verified at source 2026-07-19):

1. **A `P`-scan data source in the GUI process** — `plan_drain` needs
   `&[PFundingOutputRecord]` from `PScanState.funding_outputs`.
   *(UPDATE 2026-07-19, review round 2: the P-scan task itself now runs
   in the GUI process — GUI-PR1 starts `start_pscan_if_staker` at every
   engine open, §2.4; the layer's remainder is the aggregate read
   surface over it.)*
2. **A drain tx-assembly path** — `plan_drain` returns a `DrainPlan`
   (amount, input gindices, change), not a signed/broadcast transaction;
   the assemble→sign→broadcast follow-on (the claim-assembly analog) is
   wired nowhere.
3. **The wallet-flow default on top** — never seed a reward-derived
   amount; offer round-number / random-split; aggregate-only balance
   surface. **Incl. the F-D4 §16.4 funding default** (ACCEPTED as
   F-D2-class at Gate-6 §12.9 decision 3): the §12.9 R4 close wording —
   "F-D1 + F-D2 **(incl. funding default)** + deletion PR + F-D5 §14.4
   disposition", carried verbatim through the 07-17 UPDATEs — writes it
   into the close as a **gating** item (see DS-6).

Riders that land **before/with** this subsystem (`docs/FOLLOWUPS.md`
"P-drain mechanism re-walk", V3.0): (a) fee/change mechanics decision,
(b) shape-era language sweep of drain docs/comments, (c) confirmation
that the default is specified against the **amount channel only** — the
one surviving channel (timing phantom per F-W7, output-count phantom per
F-W10).

Closing F-D2 closes Gate-6 R4 — the gate's own close, not a `K_COVER`
seal input (seat removed 2026-07-19; see the charter note above).

## 2. Substrate — verified at source, 2026-07-19

### 2.1 Core-side landed surface (the planner with no data source and no consumer)

- `shekyl-engine-core/src/engine/drain_orchestrator.rs` — the F-D1 trust
  boundary. `drain_balance(records, reference_height) -> DrainBalance`
  (aggregate scalar only, `:218`); `plan_drain(request, records,
  reference_height) -> DrainPlan` (`:243`); `DrainPlan { amount, inputs:
  Vec<GlobalOutputIndex>, input_total, change }` (`:80`, Debug redacts
  `inputs`). Maturity = `spendable_height <= reference_height` (`:177`).
- **The planner is fee-agnostic** — no fee operand anywhere in the three
  stages; `change = input_total − amount` exactly. Sweep, as built, is
  the `target == spendable` boundary (largest-first takes every mature
  output, zero change) — no separate primitive (FOLLOWUPS re-walk
  finding, ratified 2026-07-19).
- The F-D1 arms are live as `fd1_arm_*` unit tests inside
  `drain_amount.rs` / `drain_select.rs` (self-grep + signature assert);
  the orchestrator is deliberately excluded (it must hold the record).

### 2.2 The assembly/dispatch analog (the claim path shape this subsystem mirrors)

- `claim_orchestrator.rs` (module doc `:6–:63`) — the six-step pipeline:
  fetch over **`PersonaIsolatedTransport` only** (§7.4 transport pin,
  structural) → two-sided reference anchor → designate backing → fee
  sweep → assemble membership paths against ONE reference snapshot
  (`CurveTreeHandle::assemble_tx`) → hand to the **`StakeEngine` actor**
  (signing stays inside the actor, rule 36; reply returned unbroadcast).
- `claim_dispatch.rs` (module doc) — the CB-3 seam: one explicit caller
  intent in, one assembled claim out through the audited
  posture→submitter choke point; **persist-before-dispatch** (no bytes
  reach a submitter unless a sealed pending record already holds them,
  feeding the shared `reserved_gindexes` union so concurrent sweeps
  cannot double-spend in-flight inputs); scheduling stays external.
- A drain spends `P`-attributed outputs, so its fetch/broadcast are
  `P`-side network acts: the transport pin applies with full force — a
  drain assembled or dispatched on the principal's network identity is
  the exact linkage GF-7/GF-4 exist to prevent.

### 2.3 `P`-scan state: persistence + lifecycle precedent

- `PScanState` is durable engine state: postcard payload
  `PayloadKind::PScanStatePostcard = 0x02` in the engine wallet file
  (`shekyl-engine-file/src/payload.rs:126`, `handle.rs:594–:650`).
- Lifecycle precedent: `Engine::start_pscan_if_staker`
  (`engine/pscan/start.rs:520`) — quiet `None` for a non-staker; a live
  handle only when **the open path found `staking_enabled`** (the fn's
  own docstring, `start.rs:504`). `shekyl-wallet-rpc`'s tenant calls it
  unconditionally at open and parks the handle (`lifecycle.rs:441–:463`).
  This is the adoption shape WI-1 landed.
- **`staking_enabled` production setter — landed on `dev`** (verified
  2026-07-19; supersedes the SP-R0 §0 F-1 "zero production callers"
  state): the stake-activation entry (2026-07-18,
  `feat/stake-activation-entry`) wired wallet-rpc `"stake"`
  (`handlers.rs:51`, via `lifecycle::stake`) → `Engine::first_stake`
  (`bond_orchestrator.rs:537`)
  / `open_full_with_first_stake_intent` → `persist_bond_record`, which
  flips `staking_enabled = true` (`stake_persist.rs:150`).
- **GUI-side activation surface — landed on gui-wallet `dev`**
  (re-verified 2026-07-19, review round 2; supersedes this round's
  earlier "wallet-rpc-only caller" state): GUI-PR3 (`c73444c`) wires the
  Tauri `activate_staker` command (`commands.rs:623`) →
  `EngineSession::activate_staker` (`engine_session.rs:352`) →
  `Engine::first_stake` (`:403`), with the optional intent reopen via
  `open_full_with_first_stake_intent` (`:461`). The
  `staking_enabled`-reachability edge DS-PR-3 was gated on **exists in
  production** for GUI-held engine wallets (see DS-2 and §4).

### 2.4 GUI substrate (`shekyl-gui-wallet`) — **engine-first as of gui-wallet `dev` 2026-07-19; re-verified review round 2**

**Crate-role correction first (review round 2), because a misreading
here propagated:** the GUI links two engine crates with entirely
different natures. `shekyl-engine-rpc` is the **wallet2 FFI shim
crate** — its `create_wallet`/`open_wallet`/
`restore_deterministic_wallet`/`get_address`/`get_transfers`
(`engine-rpc/src/engine.rs:195`/`:210`/`:222`/`:287`/`:323`) are Rust
names over `ffi::wallet2_ffi_*` C++ calls (`:104`/`:205`/`:288`); it is
not a native wallet. The **native wallet lifecycle lives in
`shekyl-engine-core::Engine`** (create via `EngineCreateParams`,
`open_full`, restore, `primary_address` at `engine/mod.rs:981`, ledger
balance, pending-tx send, refresh), wallet2-free (zero `wallet2`/FFI
references outside comments), operating on its own `.wallet`/
`.wallet.keys` envelope (`shekyl-engine-file`), production-consumed by
`shekyl-wallet-rpc`'s lifecycle. Reading engine-rpc's Rust method names
as a native wallet was the error; the two wallet worlds are distinct
file formats and code paths.

**Current state (gui-wallet `dev` at `c73444c`, GUI-PR0…GUI-PR3 landed
2026-07-19):**

- The GUI backend now embeds `shekyl-engine-core::Engine` **directly
  in-process** via `EngineSession` (`engine_session.rs`, GUI-PR1
  `c7da109`) — create / restore-from-BIP-39 / open / close /
  `primary_address` / ledger balance / one-shot transfer
  (`build_pending_tx_async` → `submit_pending_tx_async`,
  `engine_session.rs:601`) / fee estimate / transfer history
  (GUI-PR2 `03eb868`). No `wallet2_ffi` on this path.
- The engine backend is **default-on** (`SHEKYL_ENGINE_BACKEND` env,
  default true — `engine_session.rs:922`; held in
  `AppState.engine_backend`, `state.rs:117`). Tauri commands branch
  engine-first: `create_wallet` (`commands.rs:671`), `open_wallet`
  (`:728–:759`, opens engine files when they exist, refuses to
  silently fall back when the flag is on), `import_wallet_from_seed`
  (`:846`), `transfer` (`:1052`).
- **The WI-1 P-scan lifecycle shape is already adopted:** every engine
  open path runs `wrap_and_start_pscan` → `Engine::start_pscan_if_staker`
  and parks the `PScanHandle` (`engine_session.rs:854–:870`; fail-closed
  at open, degrade-to-`None` on restore re-arm `:873`).
- The **wallet2 path survives as the legacy fallback only**
  (`wallet_bridge.rs` `Option<Wallet2>` handle `:51`; `.keys` stems;
  reached when the engine flag is off or only legacy files exist). Its
  retirement rides the wallet2-retirement track (the `transfer_details`
  C++→Rust migration, `docs/FOLLOWUPS.md` V3.1 queue), which is now
  **orthogonal to this subsystem** — the drain path never touches
  wallet2.
- **Still true: no `P`-side read surface exists.** `EngineSession::balance`
  reads the principal ledger only (`engine_session.rs:579`); nothing
  surfaces `drain_balance`'s aggregate scalar. That remainder — not
  engine adoption — is DS-PR-3's content.

*Superseded Round-1 state (recorded 2026-07-19 at round open, accurate
for the pre-GUI-PR0…3 tree):* wallet object was C++ `wallet2` via FFI;
`shekyl-engine-core` imported only for `DaemonClient` in the scanner
sync loop (`wallet_bridge.rs:36`, `:341`); `Engine` not constructed
anywhere; principal send was `Send.tsx` → `commands::transfer` →
`Wallet2::transfer_native`. All four claims are now stale for the
engine-backend default path; they remain accurate for the legacy
fallback. The "exactly one type — `DaemonClient`" line in particular is
superseded: `engine_session.rs:28–:32` imports the full `Engine`
surface, and `DaemonClient` is also constructed there (`make_daemon`,
`:843`).

### 2.5 What the substrate implies

The three §1 layers are **not GUI-local features**. Layer 1 is *engine
adoption in the GUI process* (the GUI must hold an `Engine` for staker
wallets — `PScanState` lives in the engine wallet file and is maintained
by the engine's P-scan task) — **substantially landed** as of
GUI-PR0…GUI-PR3 (§2.4): the GUI holds an `Engine`, starts the P-scan at
open, and can activate a staker; the layer's remainder is the aggregate
`P`-balance read. Layer 2 is *engine-core work*
(secrets + membership proofs + persona transport — Rust per rule 20;
new code originates in `shekyl-core` per rule 10; the GUI is a
consumer). Only layer 3 is genuinely GUI work.

## 3. Design questions (DS-N) — proposed dispositions, review pending

### DS-1 — Assembly locus: engine-core drain pipeline mirroring the claim path

**Proposal.** A drain assembly + dispatch pair in
`shekyl-engine-core/src/engine/` mirroring the claim shape: an
orchestration that loads the sealed `P`-scan state, projects through the
existing `plan_drain`, maps the plan's gindices back to full records at
the single trust boundary, assembles membership paths against one
reference snapshot, signs **inside the `StakeEngine` actor**, persists a
sealed pending record (feeding `reserved_gindexes`) before any submitter
sees bytes, and dispatches through the posture→submitter choke point on
persona-isolated transport. The GUI calls one engine entry point; no
drain logic lives in Tauri commands.

**Rejected alternative.** Assembling in the GUI process outside the
engine (a `wallet_bridge` composition over raw engine-state reads) —
spreads the F-D1 trust boundary into a second repo and hands per-output
records to UI-adjacent code; contradicts the §12.3 single-trust-boundary
pin. Reopen only if the engine entry point is structurally unable to
serve a GUI progress/cancellation need (named criterion; none known).

### DS-2 — GUI data source: staker-mode engine adoption — **RATIFIED engine-first (review round 2, 2026-07-19)**

**Proposal (ratified).** The GUI adopts the WI-1 lifecycle for staker
wallets: open the engine wallet, call `start_pscan_if_staker`, park the
`PScanHandle` (quiet `None` keeps non-staker wallets zero-cost). The
`P`-balance surface the UI reads is `drain_balance`'s aggregate
scalar — the decomposition never crosses into the GUI (F-D2 core-side
contract).

**Ratification (review round 2).** Engine-first / native-in-process —
option (b) — is **ratified**; dual-open (a) is **rejected** (dead: the
wallet-file pairing rule it would need has no consumer, and the landed
substrate below makes the split moot). The ratification does *not* rest
on the retracted "the engine already has the principal core, so
engine-first is mostly a swap" claim (see the retraction note below);
it rests on the source-verified state of gui-wallet `dev`, which
adopted the engine-first shape while this round was in review (§2.4):
`EngineSession` embeds `Engine`, the engine backend is default-on with
wallet2 as legacy fallback, every engine open runs
`start_pscan_if_staker` and parks the handle, and GUI-PR3's
`activate_staker` closes the `staking_enabled`-reachability edge. What
remains of DS-2's adoption is only the aggregate `P`-balance read —
DS-PR-3's actual content.

**Retraction note (review round 2), so the record doesn't inherit the
error:** an earlier review-round claim read `shekyl-engine-rpc`'s Rust
method names (`create_wallet`/`open_wallet`/`get_address`/…) as a
native wallet lifecycle. Retracted: that crate is the **wallet2 FFI
shim** (`ffi::wallet2_ffi_*`, §2.4). What is native is (i) the scan
path (`shekyl-scanner`), (ii) the **engine send surface** —
`Engine::build_pending_tx` / `submit_pending_tx`
(`engine/pending.rs:836`/`:845`, async variants `:861`/`:870`),
production-consumed by `shekyl-wallet-rpc`'s send handlers and now by
`EngineSession::transfer` — and (iii) the `engine-core` wallet
lifecycle itself (create/open/restore/address/balance/history on the
`.wallet` envelope, §2.4), which is a **separate wallet world from
wallet2**, not a migration of it. Named caveats on (iii), verified at
source: mid-session seed re-display is unavailable by design
(`EngineSession::seed_unavailable_message`, mnemonic retained only
until the create response is delivered), and no subaddress surface
exists. The C++ `wallet2` retirement (`transfer_details` migration,
FOLLOWUPS V3.1) governs the *legacy fallback's* deletion timeline and
is orthogonal to this subsystem.

**Superseded pre-flight items** (Round-1 review, accurate pre-GUI-PR0…3,
kept for the record): "the GUI's principal path is wallet2-only today"
and "no principal surface executes against an engine `.wallet`" — both
now false on the engine-backend default path (§2.4); "the full
principal-surface inventory remains a pre-flight item" — discharged by
GUI-PR1/PR2 for create/open/restore/address/balance/send/fee/history,
with the two named caveats above.

**Rejected alternative.** Read-only parse of the persisted
`PScanStatePostcard` payload without running the P-scan task — a stale
snapshot with no cursor discipline; drains would plan against outputs
already spent or miss matured ones. No reopening criterion (this is
delete-now-shaped: the option is wrong, not premature).

### DS-3 — Destination: pinned to the wallet's own principal address

**Proposal.** The drain is the `P`→principal value-out (Gate-6 §12.1);
the destination is **derived** (the wallet's own principal address),
never a user-typed address. This removes an entire mis-send class (a
typo'd external address is unrecoverable), keeps the drain UI's surface
minimal (amount + confirm), and matches the seam re-homing (§12.9: the
surviving exposure is the principal↔user crossing — the `P`→principal
hop itself is wallet-internal). A user who wants value at a third party
sends principal→external afterward through the existing audited send
path.

**Reopening criterion:** a ratified product decision that `P`→external
direct drains are a required flow — re-evaluated in a fresh design round
against the amount-channel arms (an external destination hands the
counterparty the exact drain amount, sharpening §18.12's off-chain
aggregate; the round would need a new coverage-boundary entry).

### DS-4 — Fee/change mechanics (FOLLOWUPS re-walk item (a))

The planner is fee-agnostic (verified §2.1); a real drain pays a fee, so
somebody must reconcile `target`, fee, and change.

**Proposal.** An **assembly-side fee carve**: the caller hands the
user's intent (`target` or drain-all); the assembly, which is the first
site that knows the concrete fee (it knows input count, output count,
and the fee snapshot), computes the on-chain outputs. For drain-all the
assembly sets `target = spendable − fee` — a **first-class sweep entry**
on the engine API rather than each caller computing the
`target == spendable` boundary by hand (one definition; the boundary is
load-bearing for the change-free property). `plan_drain`'s carve is
untouched: fee is a maturity/cost axis, not a reward-sequence
coordinate, and it enters *after* the guarded stages.

**Rejected alternative.** Caller-side `target = spendable − fee` — the
caller (GUI) would need a fee quote before planning, duplicating the
estimate path and creating a stale-quote failure mode (fee moves between
quote and assembly ⇒ spurious `Unaffordable`). Reopen if the assembly
carve proves unable to express a fee-bumping/replace flow (named
criterion; no such flow exists for `P`-side txs today).

**Interaction registered (2026-07-19, merged mid-round; not decided
here).** The `P`-lane fee-uniformity ratification
(`V3_WALLET_DECISION_LOG.md` 2026-07-19 "`P`-lane fees") landed on `dev`
during this round. Its enumeration ("all five bond-post kinds and the
emission claim") does not name the drain tx, but the drain spends the
same typed `P`-space pool (cover + claim outputs) the decision governs,
so three of its consequences bind or plausibly bind the DS-4 assembly:
(i) the **canonical-floor fee derivation** (no estimator multiplier, no
user knob) should be the drain's fee function too — one fee rule per
lane; (ii) the **typed `P`-space pool selector** the rider lands is the
same source-set type the drain selector wants (principal outputs
unrepresentable — DS-1's re-map is the drain-side face of the same
hygiene); (iii) the **`EXIT_FEE_RESERVE_ATOMIC` spend-floor** applies to
"every mid-life constructor" — whether a *partial* drain from a live
persona is a mid-life constructor in that sense (it should be: draining
the pool below the exit reserve strands the `Unbond`) vs. a
post-retirement sweep (reserve moot) needs one sentence of disposition
when DS-PR-1 lands the assembly. Carried into the DS-PR-1 scope cell;
the fee-uniformity rider itself rides the `Unbond` constructor family
and is not blocked on this round. *(UPDATE 2026-07-21, DS-PR-2 impl:
disposition landed — a partial live-persona drain reserves
`EXIT_FEE_RESERVE_ATOMIC` (`shekyl-standoff`, `50_000_000` atomic),
enforced in `orchestrate_drain` (`DrainOrchestrationError::ReserveBreached`);
a retired persona's sweep is reserve-moot. See the §5 composite-arm
"UPDATE 2026-07-21 (DS-PR-2 impl)" note.)*

**Weight-uniformity cross-reference (2026-07-19).** Consequence (i)'s
uniformity holds **given weight**: the fee is `f(weight, daemon-rate)` — a
pure function of tx shape (input/output counts + curve-tree depth) and the
daemon rate snapshot, with **no** capital/cover/earnings term. The
"canonical fee from persona working capital" wording names the *funding
source* (cover outputs first, then earnings), never the *amount* — the fee
is the standard weight-priced floor, capital-independent. Verified in the
landed WI-RPC-1 fee surface (`shekyl-engine-core`
`tx_fee_model::{predict_weight, converge_fee, fee_from_weight}` and
`fee_query::{estimate_tx_size_and_weight, quote_fee_tiers}`; wallet-RPC
`fees.rs`): the only client input beyond the tx-shape counts is the fee
field's own `varint(fee)` width, and the reserved staking wire carries no
`FeePriority`/amount/cover-amount param (contract pin 3d22d1e), so a
capital-dependent fee is **unrepresentable**, not merely discouraged.
Consequence: the fee leaks nothing beyond weight, so the sole fee-adjacent
distinguisher that remains is weight/input-count itself — that is **GF-4b's
funding-input-count territory, not the fee's**, and the drain fee rule
deliberately does not launder it through the fee heading. A later reader
should not re-litigate weight-uniformity under this fee heading.

### DS-5 — The default itself (the §12.4 affordance, re-walk item (c))

**Proposal.** The drain-amount field defaults **empty**; the two offered
affordances are **round-number** (round the user's intent down to one
significant digit in SKL) and **random-split** (draw a uniform fraction
of spendable from wallet RNG, then round). Both read only `{user intent,
aggregate scalar, RNG}` — specified against the **amount channel only**:
no input reads a reward-sequence coordinate, epoch count, or per-output
amount, so the affordance structurally cannot re-introduce shape
machinery (re-walk item (c) discharged by construction, then confirmed
by the arm below). No send-max-style reward pre-fill exists anywhere in
the flow; drain-all is the DS-4 sweep entry, whose amount is
`spendable − fee` — the §18.12 lifetime-aggregate floor, already
irreducible, never a subsum.

**Arm (F-D1-sibling, pre-code).** The default-computation module gets
the same self-grep + signature discipline as `drain_amount.rs`: it takes
`DrainBalance` (the scalar), never `&[PFundingOutputRecord]` /
`DrainCandidate`; the `fd1_arm_*` template extends to it.

### DS-6 — The F-D4 §16.4 funding default: in-scope and **gating** (ANSWERED, review round 2026-07-19)

Gate-6 §12.9 decision 3 accepted the funding default as F-D2-class:
**self-fund by default via GF-4b lineage; external growth-funding is a
loud override routed through the entry standoff**, with its growth-gating
cost (portfolio expansion gated on accumulated rewards ≥ FLOOR) stated
up front. This is a *funding-path* (value-in) default, not a drain
default — it rides the same subsystem PR chain because both are
`shekyl-gui-wallet` wallet-flow defaults under the F-D2 label.

**Disposition: in-scope and gating for the R4 close.** The §12.9 R4
decision-round text writes the re-formed close as "F-D1 + F-D2 **(incl.
funding default)** + deletion PR + F-D5 §14.4 disposition," and the
07-17 UPDATEs carry it verbatim ("remaining: F-D1, F-D2 (incl. funding
default)" → "R4 open on F-D1 + F-D2 only"). §12.9's close wording is
authoritative — later, ratified, decision-round text beats the §12.4
build-note enumeration, which listed the three drain layers without
restating the funding default (a §12.4↔§12.9 split: anyone reading
§12.4 alone under-scoped R4 — the close condition existed only in the
join). Reconciled 2026-07-19 by a dated §12.4 amendment adding "(incl.
the §16.4 funding default)" to the build note, so R4's scope reads
correctly from one section.

Two orthogonal properties, both true: DS-6 is **slice-independent**
(it can land in its own sub-PR, DS-PR-5, without blocking
DS-3/DS-4/DS-5, and vice versa) and **close-gating** (R4 does not close
without it). Separable ≠ optional.

### DS-7 — Shape-era language sweep (re-walk item (b))

Rider, docs-only: sweep drain docs/comments for CryptoNote-era
assumptions (decorrelation, consolidation visibility, split-the-exit)
and re-walk each against the FCMP++ threat model per method note 5
("carry from X" is a re-walk trigger). The FOLLOWUPS ratification
already names the finding; the sweep executes with the subsystem's doc
updates so the new code never cites retired discipline.

## 4. Proposed slicing (each sub-PR inside the 5-day/10-commit ceiling)

| Slice | Repo | Content | Depends on |
|-------|------|---------|-----------|
| DS-PR-1 | shekyl-core | Drain assembly: record re-map at the trust boundary, membership paths, actor signing, sealed pending record + `reserved_gindexes`; DS-4 fee carve + sweep entry (fee function = the canonical floor per the 2026-07-19 fee-uniformity ratification; one-sentence exit-reserve disposition for partial drains — see the DS-4 interaction note); **threat-model forward-actions T-DS-4 (map each drain shape to an F-D4 §16 crossing class, confirm none new) + T-DS-5 (input selection inherits the GF-4b funding-input discipline, no drain-specific selector) + T-DS-3 change-output arm (change → persona `P`-space pool, change-to-principal unrepresentable) + the T-DS-6 ∧ T-DS-7 composite wire-shape arm (drain's full wire serialization byte-identical to a modal 2-out confidential transfer modulo hidden/committed values — routed through the shared `sign_bridge` path, verified by diffing a real drain tx against a real transfer tx, not by separate count/`tx_extra`/`unlock_time` checks; `0x07` leaf-hash confirmed unconditional at `sign_bridge.rs:283`)** per §5; **composition arm: free-function drain orchestrator over a `DrainCtx` (never `&Engine`), no new `Engine` generic/inherent method, drain code in its own `drain_*` module set — §4 Composition discipline** | round closure + pre-flight *(core-side pre-flight run 2026-07-19, AUDIT §Round 0; thin re-confirm at open)* |
| DS-PR-2 | shekyl-core | Drain dispatch seam (claim-dispatch sibling): choke-point submit on persona transport, retirement wiring; **T-DS-2 arm: self-grep the drain submit routes through `PersonaIsolatedTransport`, never a default `DaemonClient`** (§5); **composition: dispatch is a `claim_dispatch`-sibling driver, not an `Engine` inherent method (§4)** | DS-PR-1 |
| DS-PR-3 | shekyl-gui-wallet | Aggregate `P`-balance read surface (the DS-2 remainder — the adoption shape itself landed as GUI-PR1/PR3, §2.4: open + `start_pscan_if_staker` + parked handle + `activate_staker`) | DS-PR-1 (aggregate-read API exists). *Former second edge — a `staking_enabled` production path reachable from the GUI — closed 2026-07-19 by GUI-PR3 `activate_staker` → `Engine::first_stake` (§2.3); former "native wallet lifecycle" edge closed by the same landing (GUI-PR1 `EngineSession`, §2.4)* |
| DS-PR-4 | shekyl-gui-wallet | Drain-send UI: amount entry + DS-5 defaults + confirm; calls the one engine entry point — **a thin façade delegate over the drain service, not a fat `Engine` workflow method (§4)** | DS-PR-2, DS-PR-3 |
| DS-PR-5 | shekyl-gui-wallet | DS-6 funding default (separable) | DS-PR-3 |
| DS-PR-6 | shekyl-core | DS-7 doc sweep + Gate-6/M1/FOLLOWUPS close-out lines | last |

Cross-repo note (rule 10): every engine-side API lands in `shekyl-core`
first; the GUI consumes released surface, never the reverse.

### Composition discipline (`ENGINE_COMPOSITION_DECOMPOSITION.md` alignment)

`ENGINE_COMPOSITION_DECOMPOSITION.md` (dev, 2026-07-19) names the one
remaining monolith as **orchestration ownership on `Engine`** and pins
the fix: workflow *services* that take an explicit Caps/Ctx — **not**
more `Engine<…>` generics, **not** new inherent multi-step methods on
`Engine`; file-split the god-modules first, façades second, Stage-4
actors last. The drain-send subsystem is a **workflow** (the doc lists
"bond / claim / **drain**" under `StakeWorkflow`), so the discipline is
load-bearing here. This subsystem adopts it **by construction**, not by
a later refactor:

- **DS-PR-1/DS-PR-2 mirror the claim path, which is already the target
  shape.** `orchestrate_emission_claim<R: PersonaIsolatedTransport>`
  (`claim_orchestrator.rs:222`) is a **free function** over an explicit
  `ClaimAssemblyContext<'a>` (`:132` — borrowed `&StakeEngineHandle`,
  `&CurveTreeHandle`, funding records, reserved set, fee), never
  `&Engine`; signing stays in the actor; dispatch is the separate
  `claim_dispatch` driver (`:182`). The drain orchestrator/dispatch copy
  that shape verbatim: a free-function drain orchestrator over a
  `DrainCtx` (the drain analog of `ClaimAssemblyContext`), actor-held
  signing, a `claim_dispatch`-sibling submit seam. **No new `Engine`
  type parameter; no new inherent multi-step method on `Engine`.**
- **God-file guardrail.** Drain code stays in its **own** module set —
  the F-D1 landing already put it there (`drain_orchestrator` /
  `drain_amount` / `drain_select` as separate files, not inside
  `stake_engine.rs`); DS-PR-1/DS-PR-2 extend that set (assembly +
  dispatch modules, e.g. an `engine/drain/` tree). It must **not** swell
  the two god-files the doc flags — `stake_engine.rs` (4.7k) or
  `local_pending_tx.rs` (5.4k). "Split by workflow, not by noun;
  file-split first."
- **DS-PR-4's "one engine entry point" is a thin façade delegate**, not
  a fat workflow method — the GUI calls a small stable surface that
  delegates to the drain service (the doc's §3 façade shape, a drain
  view over shared Caps), keeping workflow logic off the `Engine`
  inherent impl.

**Armed as an acceptance property (F-D1-sibling, pre-code).** DS-PR-1's
tests self-grep that the drain orchestrator/assembly names a
`DrainCtx` / handle set and **never `Engine`**, and that the change adds
no `Engine` generic — the same make-bad-states-unrepresentable
discipline the `fd1_arm_*` guards and the fee-contract pin already use,
so a monolith regression is caught mechanically, not by review vigilance.

## 5. Threat-model addenda (Rounds 3–4 — rule 26 A3)

Late-round adversarial pass against named attacker objectives, run now
that the shape survived review rounds 1–2 (A3 timing: after feature
completeness, before closure). Grounded in the §2 substrate and the
DS-1…DS-7 dispositions; no new substrate read is required. Each
objective is graded and routed per A3 to **(a)** in-scope absorption,
**(b)** discipline note, or **(c)** named forward-action. This is a
design-round pass — the impl-time **pre-flight** (Part B: substrate
re-check + artifact execution) is not discharged in this section. *(The
core-side pre-flight subsequently ran 2026-07-19 — Round 0, §7 round log
and `ARCHIVAL_DRAIN_SEND_FD2_AUDIT.md`; the GUI-side half is carried to
each GUI sub-PR's open.)*

The firewall the drain-send subsystem defends is the `P`-lane privacy
boundary: an on-chain or network observer must not recover the
persona's capital/earnings magnitude, link the persona to the
operator's principal identity, or gain a fresh linking key from the
drain that Gate-6's firewall doesn't already model.

**Scope boundary.** This firewall defends against the **on-chain or
network** observer only. The local/wallet-file adversary is out of scope
**by design**: a self-drain inherently knows the persona↔principal
linkage — it *is* the wallet performing the crossing — so no
on-chain/network defense can or should hide it from the local host.
At-rest secret exposure is `36-secret-locality.mdc`'s jurisdiction, not
this subsystem's.

| # | Attacker objective | Surface | Defense (substrate) | Disposition |
|---|--------------------|---------|---------------------|-------------|
| T-DS-1 | **Amount-channel recovery** — read the persona's capital/earnings magnitude or reward-sequence structure from the drain's amount / change / fee | DS-4 fee carve, DS-5 default affordances, drain-all | DS-5 defaults read only `{user intent, aggregate scalar, RNG}` (amount channel only — no reward-sequence coordinate, epoch, or per-output amount); drain-all `= spendable − fee`, the §18.12 lifetime-aggregate floor (irreducible, never a subsum); fee `= f(weight, daemon-rate)` with no capital term (this round, impl-verified §DS-4); CT hides on-chain amounts; the aggregate scalar never crosses into the GUI decomposed (F-D2 core-side contract) | **(a) in-scope** — defended by construction; no residual in the amount/fee dimension |
| T-DS-2 | **Transport linkage** — link the drain's `P`-space spend to the operator's principal identity via broadcast transport (IP, timing correlation with other `P`-lane txs) | DS-PR-2 drain dispatch seam | DS-PR-2 is the claim-dispatch sibling: choke-point submit on the **persona** transport (`PersonaIsolatedTransport`, §2 transport pin), the same isolation bond-post / claim dispatch already use; the drain introduces no new broadcast path | **(a) in-scope** — reuses the established persona-transport choke-point. **Arm (→ DS-PR-2):** acceptance includes a self-grep that the drain submit routes through the persona transport, never a default `DaemonClient` |
| T-DS-3 | **Mis-send / destination substitution** — cause drain funds to land at an attacker-chosen or externally-linkable output (wrong-destination bug, or a re-map binding a linkable principal output) | DS-1 record re-map at the trust boundary, DS-3 destination pin, DS-PR-4 confirm | Destination is pinned engine-side to the wallet's **own principal address** (DS-3), never caller-supplied; DS-1 re-map sits at the trust boundary under the F-D2 core-side contract (only the aggregate crosses to the GUI); DS-PR-4 surfaces the destination at confirm | **(a) in-scope**. **Discipline note:** the drain entry point MUST NOT accept a destination-address argument — a caller-supplied destination is unrepresentable on the surface (same make-bad-states-unrepresentable shape as the fee contract pin), and is the named reopening trigger. **Change-output arm (→ DS-PR-1):** the drain's *change* output (`DrainPlan.change`) is a **second** output whose destination DS-3 does not cover — DS-3 pins the *payment* to the principal. The transfer assembly's default (`signing_assembly.rs:126`: `Change { subaddress_index: 0 }`) directs change to the **principal** change address; a drain inheriting it would land change at the principal — a second principal-linked output *and* a mis-typed pool. The drain assembly MUST direct change back into the persona **`P`-space** pool and make change-to-principal unrepresentable |
| T-DS-4 | **Crossing-class inflation** — use the drain to create a new observable `P`→principal crossing class beyond Gate-6 F-D4 §16's enumeration, yielding a fresh linking key | The drain is a `P`→principal value crossing; partial-drain-from-live-persona vs post-retirement sweep | F-D4 §16 already enumerates the mandatory/optional crossings; the drain must **map onto an existing class**, not add one. The DS-4 exit-reserve disposition (partial drain = mid-life constructor and so reserves `EXIT_FEE_RESERVE_ATOMIC`; post-retirement sweep = reserve moot) is the one-sentence disposition already owed at DS-PR-1 | **(c) forward-action → DS-PR-1** — DS-PR-1 states which F-D4 §16 crossing class each drain shape maps to and confirms none is new; closes with the exit-reserve sentence already in the DS-PR-1 scope cell. Cross-link: Gate-6 F-D4 §16, DS-4 interaction note |
| T-DS-5 | **Funding-input-count leak** — infer the persona's UTXO granularity / capital structure from the drain's input count / weight | Drain input selection (`n_in`) → weight → fee, publicly visible | This is **GF-4b's funding-input-count territory** (cross-referenced this round under the fee heading); the drain fee rule deliberately does not launder it. The drain's input selection inherits the GF-4b funding-input discipline rather than defining a drain-specific selector | **(c) forward-action → DS-PR-1 / GF-4b** — DS-PR-1's input selection follows the GF-4b funding-input discipline. **Named reopening:** a drain-specific input-count policy distinct from GF-4b is a Gate-6 change, not a DS decision |
| T-DS-6 | **Structural distinguishability of the drain *tx*** (Round 4) — fingerprint the drain by output *count/shape*, which is public under CT/FCMP++ even when amounts are hidden, splitting the anonymity set by shape before amount or destination matter (e.g. a change-free drain-all as a rare 1-output tx against a 2-output norm) | Output count (`vout`) — public even when amounts are CT-hidden | A spend with `n_out < 2` is **consensus-invalid** (`shekyl-wire/src/transaction.rs:1868` — "spend has N output(s), needs >= 2"), so a change-free 1-output drain-all is *unrepresentable on the wire*. DS-4's "change-free" is an **economic** property (no value returns), not a wire 1-output property: on the wire the drain is 2-out (principal payment + change; drain-all's change carries zero value but is a real committed output), identical in output count to the modal single-recipient confidential send. The drain's output shape mirrors the **transfer** path (2-out, all-confidential), not the claim path's loud reward vout | **(a) in-scope** — absorbed by the consensus 2-output floor + the standard payment+change assembly (settled at source this round). **Arm:** folded into the composite wire-shape arm below (→ DS-PR-1). **Named reopening:** any drain assembly that could emit an output count/shape distinct from an ordinary confidential send |
| T-DS-7 | **Monero-era field distinguisher** (Round 4) — a legacy prefix/extra field survives as a *variable* the drain sets and ordinary sends don't (or set differently), tagging the drain by wire vocabulary | `TransactionPrefix.unlock_time`, `tx_extra`, `ct_type`/version, `payment_id` | Substrate re-walk this round: `payment_id` is **absent** from the wire (no `TransactionPrefix` field; none in `shekyl-tx-builder`) — closed by absence. `ct_type` has a **single** accepted spend type at genesis (rule 60) — version/proof-variant trivially uniform. `unlock_time` is a **live** wire field (`transaction.rs:1202`) but the tx-builder emits `0` (`shekyl-tx-builder/src/wire.rs`) and the timestamp form is consensus-rejected — it is **builder-zeroed, not removed** (corrects "already rejected from genesis"). `tx_extra` is present but **structural** (tx pubkey + per-output KEM blobs + `0x07` PQC leaf-hash, `sign_bridge.rs`; opaque round-trip), with no payment-id sub-field | **(c) forward-action → DS-PR-1 (home: DS-7 shape-era re-walk)** — DS-PR-1 confirms the drain emits **byte-identical** `unlock_time` (0), `tx_extra` structure, and `ct_type`/version to an ordinary confidential send, no Monero-era field surviving as a variable distinguisher. Closed sub-surfaces: `payment_id` absent, single `ct_type`; confirm-at-build (**folded into the composite wire-shape arm below**): `unlock_time`/`tx_extra`/`0x07` leaf-hash |

**Composite wire-shape arm (T-DS-6 ∧ T-DS-7 — the distinguisher can live
in the join; → DS-PR-1).** T-DS-6 and T-DS-7 are not independent guards.
The drain is claim-*plumbed* but must be transfer-*shaped*, so a
distinguisher can survive both sub-checks and live in their **join**: the
claim plumbing setting one `tx_extra` field a transfer doesn't, or
ordering/encoding the KEM blobs differently, while `n_out >= 2` (T-DS-6)
and each individual `unlock_time`/`tx_extra` field (T-DS-7) still pass in
isolation. Green-checking each sub-surface separately is exactly the
"true condition exists only in the join" failure the project names
elsewhere. So DS-PR-1's shape arm is a **single**
make-the-distinguisher-unrepresentable check: the drain's **full wire
serialization is byte-identical to a modal 2-out confidential transfer,
modulo the hidden/committed values** (encrypted amounts, commitments,
one-time keys, KEM payloads, proof scalars) — enforced by routing the
drain through the **shared `sign_bridge` transfer-signing path** (not a
bespoke drain serializer) and **verified by diffing an actual drain tx
against an actual transfer tx** at the same arity, not by separately
green-checking output count, `tx_extra` fields, and `unlock_time`.
*Preliminary substrate (this round)* for the sub-surface flagged
most-likely-to-diverge — the `0x07` PQC leaf-hash: it is appended
**unconditionally** by the shared path (`sign_bridge.rs:283`,
`push_pqc_leaf_hashes`, per output in vout order — a curve-tree-leaf
requirement, not a reward marker; a prior transfer-path gap was closed in
PR-4b, `sign_bridge.rs:278-280`), so it is **uniform** across transfer
and drain rather than a reward-only tag. The byte-diff remains the guard:
it fires at DS-PR-1 (a real drain tx must exist to diff), and any
drain-specific divergence — including a regression that re-opens the
leaf-hash gap or a bespoke serializer that bypasses the shared path —
fails it.

**UPDATE 2026-07-20 (DS-PR-1 impl — post-closure substrate pin, not a
round reopen).** The T-DS-6 row's mechanism ("drain-all's change carries
zero value but is a real committed output") is **not realizable through
the shared prover**: `shekyl-tx-builder`'s `validate.rs:63`
(`ZeroOutputAmount`) rejects a zero-value output, and both
`sign_transaction` and `sign_transaction_with_terms` run that check — so
a zero-value change output cannot be built through the shared transfer
path at all. The **wire property is unchanged** (two nonzero confidential
outputs, byte-identical in count/shape to a modal 2-out send); only the
*mechanism* differs. DS-PR-1 realizes it by regime:
- **partial** (`change > 0`): `[principal payment, P-space change]` — both
  nonzero, change to `P` (T-DS-3);
- **drain-all** (`change == 0`): the principal payment is **split into two
  nonzero principal outputs** `[principal a, principal b]` (a sweep to
  self) — there is no residual `P` value to return, and the distinguishable
  1-out shape the row worried about is prover-rejected anyway.
Because Pedersen commitments are perfectly hiding, both regimes serialize
to the same two-confidential-output wire shape, so T-DS-6's absorption is
*strengthened*, not weakened: the shape is uniform across partial drain,
drain-all, and an ordinary 2-out transfer. A net-payment `< 2` drain-all
(a single atomic unit after fee — pathological, the fee dwarfs it) cannot
form two nonzero outputs and is refused **loudly**
(`DrainAssemblyError::PaymentUnsplittable`) rather than shaped into a
1-out tx; a zero payment is refused up front
(`DrainAssemblyError::PaymentZero`) before any output construction, rather
than deferred to the shared prover's opaque `ZeroOutputAmount`. The drain
owns a dedicated `DrainAssemblyError` taxonomy wrapped by
`StakeEngineError::DrainAssembly`, so a value-out failure never mis-reports
as "bond assembly" (the borrowed `BondAssemblyError` is retired from the
drain path). Impl: `drain_assembly.rs` §"the composite wire-shape arm";
covered by `stake_engine.rs` `drain_assembly_shape::{drain_is_transfer_shaped,
drain_all_still_emits_two_outputs, drain_all_net_below_two_is_refused,
drain_zero_payment_is_refused}`.
The byte-diff arm (a real drain vs a real transfer) is unchanged and
still carried to the DS-PR-2 regtest e2e.

**UPDATE 2026-07-21 (DS-PR-2 impl — the core-side dispatch half; not a
round reopen).** DS-PR-2 lands the orchestrator + dispatch seam + the
composite arm's final leg, all on `shekyl-core`:
- **Orchestration (composition §4).** `orchestrate_drain` is a
  free function over an explicit `DrainCtx` (borrowed handles + records +
  reserved set + destination + amounts + `chain_tip`; **never `&Engine`**),
  the `orchestrate_emission_claim` sibling — anchor → scope/plan →
  path-assemble → delegate to the actor's `assemble_drain`. No new `Engine`
  generic or inherent multi-step method (`drain_orchestrator.rs`).
- **T-DS-4 exit-reserve disposition (the one sentence owed at DS-4).**
  `EXIT_FEE_RESERVE_ATOMIC` lands as a **real constant**
  (`shekyl-standoff/src/reserve.rs`, `50_000_000` atomic = 0.05 SKL,
  `0 < reserve < COVER_RUNG_ATOMIC` asserted at compile time — re-grounded
  post-#350 as a corner-fraction bound vs the tiling cover draw,
  `ARCHIVAL_BOND_CONSTRUCTION.md` §7.2) and
  is **enforced in the orchestrator**: a **partial** drain from a **live**
  persona is a mid-life constructor and may not spend the pool below the
  reserve (refused with `DrainOrchestrationError::ReserveBreached`); a
  **retired** persona's sweep is reserve-moot (the `Unbond` already fired),
  so it may drain to zero. The `retired` flag rides `DrainCtx`, resolved
  engine-side from `PScanState::pending_unbonds` (the authoritative "no future
  `Unbond` owed" signal) — deliberately not `retired_records`, which is
  funded-gated and omits a persona throughout the drain-all that empties its
  slot, deadlocking the reserve gate against the sweep.
- **T-DS-2 transport arm (self-grep, now live).** `submit_drain`
  (`drain_dispatch.rs`, the `claim_dispatch` sibling) dispatches **only**
  through the audited persona-transport choke point
  (`BroadcastSubmitter::local` → `submit_bound`), never a bare submitter and
  never a default `DaemonClient`; a comment-stripped self-grep test
  (`seam_routes_through_the_pipeline_and_the_submit_choke_point`) enforces it
  mechanically, plus a persist-before-dispatch ordering pin (the
  `PendingDrain` seal textually precedes the send).
- **T-DS-6 ∧ T-DS-7 composite arm — final leg (the byte-diff owed here).**
  `regtest_e2e.rs::e2e_drain_wire_shape_matches_a_real_transfer` builds a
  **real** 1-in/2-out confidential transfer (the `sign_tx` path) and a
  **real** 1-in/2-out `P`→principal drain (`submit_drain`), both
  daemon-accepted (consensus verify at submit), and asserts their normalized
  wire skeletons are **byte-identical** while their raw bytes differ
  (non-vacuous). `flatten_tx_shape` is the `stake_engine` in-slice
  `normalize_shape` plus the public `fee` varint (a weight-priced transfer
  and a caller-priced drain price the fee independently). This discharges
  the arm's "a real drain tx must exist to diff against a real transfer"
  condition that DS-PR-1 could only stage.
- **Deferred (named, WI-3 sibling slice).** Retirement wiring — the drain
  dispatch driver (confirmation-observe / terminal-reject prune,
  byte-identical resubmit) — is **not** in DS-PR-2; the `PendingDrain`
  record shape this seam seals already serves it, and it lands with the
  bond/claim retirement driver family.
- **Schema.** No new schema in DS-PR-2 — the `dev` `PENDING_POST_VERSION`
  (v6, post-`entry_offset_blocks` removal) already carries `PendingDrain`
  from DS-PR-1.

The DS-PR-2 slice row above (§4) is thus **LANDED** for its core-side
scope; the GUI-side halves (DS-PR-3/4/5) remain per the slice table.

**GF-7 disposition (drain vs the entry seam).** GF-7 grades the *entry*
seam (bond-post dispatch timing; persona↔principal unlinkability). The
drain is the *value-out* crossing, **not a GF-7 event**: its
persona↔principal **timing** channel is disposed by the exit-timing
**phantom** finding (F-W7/F-W8 — no principal-side observable within the
seam; WI-4 §18.13 re-home) and F-W10 (the drain is not an identifiable
transaction under FCMP++), not carried as a live GF-7 measurement. The
drain's **transport** timing vs other `P`-lane txs is the separate
T-DS-2 (persona-transport choke-point). So: timing-correlation →
phantom (F-W7); transport-linkage → T-DS-2; no GF-7 re-grade is owed.

**Coverage note.** T-DS-1…T-DS-3 are the three objectives §6 named as
owed (amount channel, transport isolation, mis-send); T-DS-4 and T-DS-5
are the two the substrate surfaces once the shape is stable (the
crossing-class and funding-input distinguishers Gate-6 already governs,
which the drain must not re-open). No pure-orchestration exemption
applies (A3 reopening criteria): the drain touches untrusted-input
(caller intent), value assembly, and network transport, so the pass is
non-optional.

**Round 4 additions (2026-07-19).** T-DS-6 (output-shape meta-observable)
and T-DS-7 (Monero-era field distinguisher) close the
structural-distinguishability axis the first five left implicit, and the
T-DS-3 change-output arm closes the change destination DS-3 didn't cover.
All three were settled **at source** this round (consensus 2-out floor
`transaction.rs:1868`; `payment_id` absent / `unlock_time` builder-zeroed
/ `tx_extra` structural; `signing_assembly.rs:126` change default) —
T-DS-6 absorbed, T-DS-7 + the change-arm forward-actioned to DS-PR-1. On
Round-4 close, T-DS-6 and T-DS-7 were **folded into one composite
wire-shape arm** (see the composite-arm paragraph above) — the join, not
the isolated sub-surfaces, is what DS-PR-1's byte-diff makes
unrepresentable. The GF-7 disposition line above records the drain as
disposed by the
exit-timing phantom finding, not a live GF-7 event; the scope-boundary
paragraph excludes the local/wallet-file adversary by design.

**Forward-actions (A5).** T-DS-2 arms DS-PR-2 (persona-transport
self-grep); T-DS-4, T-DS-5, the **T-DS-6 ∧ T-DS-7 composite wire-shape
arm** (single byte-diff of a real drain tx against a modal transfer, via
the shared `sign_bridge` path — replaces the two separate sub-surface
arms), and the T-DS-3 change-output arm carry into the DS-PR-1 scope cell
(crossing-class mapping, GF-4b funding-input discipline, composite
wire-shape byte-diff, change-to-`P` pin) alongside the exit-reserve
disposition already recorded there. Close each carry when the target
sub-PR lands.

## 6. What this round does not decide

- *(DS-2's dual-open-vs-engine-first sub-question, previously listed
  here, is RATIFIED engine-first — review round 2; see DS-2. DS-6's
  close-scope question is ANSWERED — in-scope/gating per §12.9; see
  DS-6.)*
- UI visual design (page placement, staking-page integration) — product
  surface, not firewall surface; falls out at DS-PR-4.
- ~~Threat-model addenda (rule 26 A3) — owed as a late-round pass~~ —
  **discharged in §5** (Round 3, extended Round 4, **Round 4 closed
  maintainer-accepted 2026-07-19**): seven attacker objectives
  (T-DS-1…T-DS-7) graded and routed — amount channel, transport
  isolation, mis-send (+ change-destination arm), crossing-class,
  funding-input, output-shape, and Monero-era field distinguisher — plus
  the GF-7 disposition and the local-adversary scope boundary. T-DS-6 ∧
  T-DS-7 fold into a single composite wire-shape arm (byte-diff vs a modal
  transfer, via the shared `sign_bridge` path) at DS-PR-1.

## 7. Round log

- **2026-07-19 — Round 1 opened (this document).** Substrate enumerated
  at source (§2); DS-1…DS-7 drafted with proposed dispositions; slicing
  proposed (§4). Awaiting review.
- **2026-07-19 — Review round 1 (three findings, all applied).**
  (1) **DS-6 ANSWERED in-scope/gating** — §12.9's ratified close
  wording ("F-D2 (incl. funding default)") is authoritative over the
  §12.4 enumeration; §12.4 reconciled by dated amendment; the
  separable-vs-optional conflation in §6 untangled. (2) **DS-2 gained
  its missing dependency edge** — `start_pscan_if_staker` requires
  `staking_enabled` at open (`start.rs:520`); the production setter
  chain landed on `dev` (stake-activation entry, wallet-rpc-side), but
  GUI reachability is unestablished; folded into DS-PR-3's dependency
  cell and the pre-flight. GUI pre-flight source checks run and
  recorded (principal path wallet2-only; engine principal send exists,
  production-consumed by wallet-rpc). (3) §2.3's `start.rs:500` cite
  corrected to `:520`.
- **2026-07-19 — Review round 2 (retraction applied + substrate
  re-verified; DS-2 ratified).** (1) **Crate-role retraction applied**:
  `shekyl-engine-rpc`'s lifecycle methods are wallet2 FFI shims
  (`ffi::wallet2_ffi_*`), not a native wallet — the round-1 review's
  "engine already has the principal core" reading is retracted; the
  DS-2 pre-flight record now scopes the native claim to the **engine
  send surface** plus the separately-verified `engine-core` lifecycle
  (§2.4, DS-2). (2) **GUI substrate re-verified and found moved**:
  GUI-PR0…GUI-PR3 landed on gui-wallet `dev` 2026-07-19 (`3f01f2d`,
  `c7da109`, `03eb868`, `c73444c`) — `EngineSession` embeds
  `engine-core::Engine` in-process, engine backend default-on,
  `start_pscan_if_staker` runs at every engine open, and
  `activate_staker` → `Engine::first_stake` closes the
  `staking_enabled`-reachability edge; §2.4 superseded with a dated
  rewrite (including the `DaemonClient` "exactly one type" correction).
  (3) **DS-2 RATIFIED engine-first** on the landed substrate (not on
  the retracted claim); dual-open rejected; DS-PR-3 re-scoped to its
  remainder (aggregate `P`-balance read) with its former dependency
  edges recorded closed (§4).
- **2026-07-19 — Round 3 (threat-model addenda, rule 26 A3; §5).** Late-
  round adversarial pass run now that the shape survived rounds 1–2.
  Five attacker objectives graded (T-DS-1…T-DS-5): amount-channel
  recovery, transport linkage, mis-send, crossing-class inflation,
  funding-input-count leak. Dispositions: T-DS-1/2/3 **(a) in-scope**
  (defended by construction — DS-4/DS-5 amount-channel-only affordances +
  impl-verified weight-only fee; persona-transport choke-point; engine-
  side destination pin), T-DS-4/5 **(c) forward-action** into the DS-PR-1
  scope cell (F-D4 §16 crossing-class mapping + GF-4b funding-input
  discipline). Discipline notes: drain entry point carries no
  destination-address arg (T-DS-3) and no drain-specific input selector
  (T-DS-5) — both make-bad-states-unrepresentable, matching the fee
  contract pin. §6 A3 line marked discharged; DS-PR-2 gains the persona-
  transport self-grep arm (T-DS-2). The impl-time **pre-flight** (Part B)
  remains owed at DS-PR-1 open — A3 is a design-round pass, not the
  pre-flight.
- **2026-07-19 — Round 0 pre-flight, core-side (Part B; run early at
  maintainer direction).** Substrate re-check + artifact execution for
  the DS-PR-1/DS-PR-2 `shekyl-core` surface at pin `28870bd61`, recorded
  in `ARCHIVAL_DRAIN_SEND_FD2_AUDIT.md`. **R0-D1 (B6):** §2.3 `"stake"`
  route cite `handlers.rs:48` → actual `:51` (dev-merge line-shift);
  errata applied, chain terminus (`first_stake:537` → `stake_persist:150`)
  verified exact so the disposition stands. **R0-D2 (A2):** every core
  disposition holds at its cited line — fee-agnostic planner, `fd1_arm_*`
  guards, claim-path transport/assemble/actor/persist pins, P-scan
  persistence + staker-gate lifecycle. **R0-D3 (B9 frame):** no
  measurement-gated budget in this subsystem; 24 behavioral artifacts
  (18 engine-core + 5 engine-file + 1 doctest) all green. **R0-D3-B
  (A5):** GUI-side pre-flight (DS-PR-3/4/5, separate repo, gated on the
  native-wallet buildout) carried to each GUI sub-PR's open. Thin
  re-confirmation at DS-PR-1 open post-#342-merge remains standing.
- **2026-07-19 — Composition-discipline pass (`ENGINE_COMPOSITION_DECOMPOSITION.md`
  alignment).** Maintainer flagged the risk of the drain subsystem
  re-growing the `Engine` monolith. Verified at source that the claim
  path this subsystem mirrors is already the doc's target shape
  (free-function `orchestrate_emission_claim` over `ClaimAssemblyContext`,
  actor-held signing, separate `claim_dispatch` driver — never `&Engine`)
  and that the F-D1 drain code already lives in its own `drain_*` module
  set, not in the flagged god-files (`stake_engine.rs` 4.7k /
  `local_pending_tx.rs` 5.4k). Added §4 "Composition discipline"
  pinning DS-PR-1/DS-PR-2 to a free-function drain orchestrator over a
  `DrainCtx` with no new `Engine` generic/inherent method, the god-file
  guardrail, and DS-PR-4's entry point as a thin façade delegate; armed
  as an F-D1-sibling self-grep acceptance property (drain orchestrator
  never names `Engine`). No design decision reopened — the subsystem was
  already aligned by construction; this records and locks it pre-code.
- **2026-07-19 — Round 4 (threat-model, structural-distinguishability
  axis; maintainer adversarial pass).** Reviewer raised the drain-*tx*
  meta-observable the first five objectives missed (output shape, change
  destination, Monero-era fields), plus two completeness items. Settled
  **at source** rather than carried as assumptions: **T-DS-6** (output
  count/shape) — **absorbed**: a spend with `n_out < 2` is
  consensus-invalid (`shekyl-wire/src/transaction.rs:1868`), so a
  change-free 1-out drain-all is unrepresentable; every drain is 2-out
  like the modal confidential send (DS-4 "change-free" is economic, not
  a wire 1-output property; drain output shape mirrors the *transfer*
  path, not the claim's loud vout). **T-DS-3 change-output arm** —
  forward-action: the transfer assembly defaults change to
  `subaddress_index: 0` (principal; `signing_assembly.rs:126`), so the
  drain must direct change to the persona `P`-space and make
  change-to-principal unrepresentable. **T-DS-7** (Monero-era field
  distinguisher) — forward-action + substrate correction: `payment_id`
  absent (closed), single `ct_type` at genesis (closed), but
  `unlock_time` is a live wire field builder-zeroed (`shekyl-tx-builder`),
  *not* removed (corrects the reviewer's "rejected from genesis"), and
  `tx_extra` is present-but-structural — DS-PR-1 confirms byte-identical
  extra/`unlock_time`/version vs an ordinary send (home: DS-7 re-walk).
  Completeness: **GF-7 disposition** line added (drain is not a GF-7
  event — its persona↔principal timing is the F-W7/F-W10 phantom, its
  transport is T-DS-2); **scope-boundary** paragraph added (local/
  wallet-file adversary out of scope by design, rule-36's jurisdiction).
  T-DS-6/T-DS-7/change-arm folded into the DS-PR-1 scope cell; §5 table +
  coverage/forward-action notes + §6 discharge line updated. No prior
  disposition reopened.
- **2026-07-19 — Round 4 close (maintainer-accepted; composite fold).**
  Grades and source refinements accepted (incl. the `unlock_time`
  live-field / builder-zeroed correction and the claim-plumbed /
  transfer-shaped distinction). Per maintainer direction, T-DS-6 and
  T-DS-7 are **folded into a single composite wire-shape arm** rather than
  two isolated sub-surface guards — because the drain is claim-plumbed
  with transfer output shape, a distinguisher can live in the *join*
  (each sub-check passing while the composite still differs), the
  project's "true condition exists only in the join" failure. The arm is
  a single make-unrepresentable check: the drain's full wire serialization
  is byte-identical to a modal 2-out confidential transfer modulo
  hidden/committed values, enforced by routing through the shared
  `sign_bridge` path and verified by diffing a real drain tx against a
  real transfer tx (§5 composite-arm paragraph). Cheap source check on the
  flagged-most-likely-to-diverge sub-surface: the `0x07` PQC leaf-hash is
  appended **unconditionally** by the shared path (`sign_bridge.rs:283`;
  a prior transfer-path gap closed in PR-4b) — uniform across transfer and
  drain, not a reward-only tag. #4 accepted with the closure rationale
  (the principal-receipt output is stealth-hidden, so the F-W7 T-class
  stays empty even for a real drain tx). **Threat-model axis (T-DS-1…
  T-DS-7 + GF-7 disposition + scope boundary) closes clean;** the three
  impl-time arms (composite wire-shape, change→`P`-space, `unlock_time`/
  `tx_extra` re-walk) are forward-actions that gate DS-PR-1, not this
  round. Standing rule-26 thin re-confirm at DS-PR-1 open remains the only
  threat-adjacent item outstanding — which is where those arms fire.
- **2026-07-20 — DS-PR-1 landed (drain assembly, `shekyl-core`).** The
  actor-side assembly slice: `AssembleDrain` handler in `stake_engine.rs`
  (thin validate-and-delegate shell) over the free-function
  `assemble_drain_tx` in the new `drain_assembly.rs`; `PendingDrain` durable
  record + `reserved_gindexes` fold + schema bump (v4 → v5) in
  `engine-state`. Forward-action arms discharged at source:
  - **T-DS-6 ∧ T-DS-7 composite wire-shape arm** — realized *by
    construction*, now compile-time-enforced: the drain's whole `WireEncodeInput`
    is built by the **single shared constructor** `sign_bridge::
    assemble_transfer_wire`, the exact one `sign_bridge::sign_tx` calls, so
    transfer-parity is one-constructor-two-callers rather than a property a test
    re-establishes (outputs still via `build_output`, inputs via
    `prepare_funding_inputs`, prefix/proving/PQC-auth by the plain transfer calls
    with empty `extra_inputs` + spend-only `pqc_auths`). **The ratified
    zero-value-change mechanism was found unrealizable through the shared prover**
    (rejects `ZeroOutputAmount`) — recorded as the §5 post-closure substrate pin
    (2026-07-20): drain-all now **splits the payment into two nonzero principal
    outputs**, so the two-nonzero-output wire shape is uniform across partial
    drain / drain-all / ordinary transfer (T-DS-6 absorption *strengthened*).
    The one degree of freedom the shared constructor does not pin —
    split-on-drain-all reshaping the amounts without perturbing the skeleton — is
    guarded **in-slice** by a whole-tx normalized byte-diff
    (`drain_partial_and_drain_all_are_wire_identical`: partial and drain-all
    serialize identically modulo hidden/committed leaves; a non-vacuous diff, the
    raw bytes are asserted to differ). The **full transfer-vs-drain** byte-diff
    still rides the DS-PR-2 regtest e2e (a real end-to-end transfer tx must exist
    to diff against). Covered by `drain_assembly_shape::{drain_is_transfer_shaped,
    drain_all_still_emits_two_outputs, drain_all_net_below_two_is_refused,
    drain_partial_and_drain_all_are_wire_identical}`.
  - **T-DS-3 change→`P`** — partial-drain change pays `P`'s own base spend
    key (`keys.spend_pk`); the entry point carries **no** destination-address
    arg (principal is engine-resolved), so change-to-principal is
    unrepresentable. Drain-all leaves no residual `P` value to return.
  - **T-DS-4 crossing-class mapping (confirm none new)** — both drain shapes
    map onto an **existing** F-D4 §16 class, adding none. Under F-W10 the
    drain is **not an identifiable transaction** on-chain (spend set
    unenumerable; no `P`-typing on the wire — FD4 §16.1), so its output
    count/shape is not an observable; the value-out leg re-homes to the
    principal↔user crossing (WI-4 §18.13), not a fresh `P`→principal
    observable. Partial-drain-from-live-persona and post-retirement sweep
    differ only in the (hidden) amount, not in class.
  - **DS-4 exit-reserve disposition (the one sentence owed)** — a **partial
    drain from a live persona IS a mid-life constructor**: it MUST leave
    `EXIT_FEE_RESERVE_ATOMIC` in the `P` pool (draining below it would strand
    the future `Unbond`); a **post-retirement sweep** has no future `Unbond`,
    so the reserve is **moot** and drain-all may take the pool to zero. The
    reserve is a **funding-selection** constraint (Engine-side, DS-PR-2:
    `assemble_drain_tx` consumes an already-selected `payment_amount`/`fee`),
    so DS-PR-1 records the disposition and DS-PR-2's selector enforces it.
  - **T-DS-5 funding-input discipline** and the **composition self-grep**
    (§4): `assemble_drain_tx` is a free function that never names `Engine`
    and reuses the GF-4b funding-input leg (`prepare_funding_inputs`), no
    drain-specific selector; the god-files (`stake_engine.rs`,
    `local_pending_tx.rs`) gain only a thin handler, not the assembly body.
  Remaining DS-PR-1-adjacent carries: the persona-transport self-grep
  (T-DS-2) and the real-tx byte-diff both ride **DS-PR-2**; GUI-side arms
  ride their sub-PRs.
