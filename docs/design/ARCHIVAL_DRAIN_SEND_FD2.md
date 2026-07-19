# F-D2 drain-send subsystem — design round (Gate-6 R4's last open item)

**Status: Round 1 DRAFT (scoping) — opened 2026-07-19. No implementation
has begun; this document is the scoping artifact rule 26 requires before
code.**

Charter: `ARCHIVAL_FIREWALL_GATE6.md` §12.4 names F-D2's remaining half a
**whole unbuilt `P`-value-out (drain-send) subsystem in
`shekyl-gui-wallet`**, and Gate-6 §12.8's re-formed R4 close condition is
down to F-D1 (BUILT) + F-D2. Seal-path note (2026-07-19, PR #337 scope
review, merged before this round's first review): the GF-4/F-D1+F-D2
`K_COVER` seal seat was **REMOVED** (`ARCHIVAL_REWARD_GATE_M1.md` §4 —
the drain is not an on-chain observable per F-W10, and the exit-timing
observable is a ratified phantom per F-W7/F-W8), so this subsystem is
**not** seal evidence and does not gate the `K_COVER` seal act. It
remains pre-genesis work on its own Gate-6 track: R4 is open on F-D2
alone, and the FOLLOWUPS "P-drain mechanism re-walk" riders are V3.0.

Process: this round cites **`26-sub-pr-design-discipline.mdc`**
explicitly — the work is a multi-sub-PR subsystem crossing an FFI-adjacent
boundary (Tauri GUI ↔ engine crates) with firewall-class (priority-2)
properties. A pre-flight pass (rule 26 §"Pre-flight pass") is owed between
this round's closure and the first production commit. Design questions
mint the **DS-N** family (registered at birth in
`IMPLEMENTATION_INDEX.md` §2 per rule 94; prefix `DS-` passes the
uniqueness check — no registered family's tokens parse as `DS<digits>`).

---

## 1. Close condition (what "F-D2 landed" means)

F-D2 is recorded as landed when **all three layers exist and the arms
hold** (Gate-6 §12.4 build notes, verified at source 2026-07-19):

1. **A `P`-scan data source in the GUI process** — `plan_drain` needs
   `&[PFundingOutputRecord]` from `PScanState.funding_outputs`; the GUI
   today has no `P`-scan state at all.
2. **A drain tx-assembly path** — `plan_drain` returns a `DrainPlan`
   (amount, input gindices, change), not a signed/broadcast transaction;
   the assemble→sign→broadcast follow-on (the claim-assembly analog) is
   wired nowhere.
3. **The wallet-flow default on top** — never seed a reward-derived
   amount; offer round-number / random-split; aggregate-only balance
   surface. Plus the **F-D4 §16.4 funding default** (ACCEPTED as
   F-D2-class at Gate-6 §12.9 decision 3).

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
  (`engine/pscan/start.rs:500`) — quiet `None` for a non-staker
  (staker ⇔ `stake_handle()` present, set at open); `shekyl-wallet-rpc`'s
  tenant calls it unconditionally at open and parks the handle
  (`lifecycle.rs:441–:463`). This is the adoption shape WI-1 landed.

### 2.4 GUI substrate (`shekyl-gui-wallet`, verified 2026-07-19)

- The GUI is a Tauri app whose backend links the engine crates
  **in-process** (`src-tauri/Cargo.toml:32–36`: `shekyl-engine-rpc`
  path-dep with `rust-scanner`/`native-sign`, `shekyl-engine-core`
  path-dep). No wallet-RPC server is involved (Gate-6 §12.4: "the
  blocker is not RPC").
- Today's wallet object is **C++ `wallet2` via FFI** (`wallet_bridge.rs`
  `Option<Wallet2>` handle, `:51`); `shekyl-engine-core` is imported
  for exactly one type — `DaemonClient` in the scanner sync loop
  (`wallet_bridge.rs:36`, `:341`). **`Engine` is not constructed anywhere
  in the GUI.** Wallet files are wallet2 `.keys` stems under the wallet
  dir (`commands.rs:386–:403`); no engine `.wallet` file is opened or
  created.
- **No `P`-side surface exists**: zero hits for
  pscan/persona/bond/`funding_outputs` in GUI code. The existing
  `Staking.tsx` page is the *principal accrual-pool* stake/claim surface
  (a different product axis), not archival `P`-scan.
- The principal send path: `Send.tsx` amount `useState("")` (blank, no
  pre-fill of any kind) → `invoke("transfer")` → `commands::transfer`
  (`commands.rs:802`) → `Wallet2::transfer_native` (C++ prepare → Rust
  sign → C++ finalize, `wallet_bridge.rs:770–:788`).

### 2.5 What the substrate implies

The three §1 layers are **not GUI-local features**. Layer 1 is *engine
adoption in the GUI process* (the GUI must hold an `Engine` for staker
wallets — `PScanState` lives in the engine wallet file and is maintained
by the engine's P-scan task). Layer 2 is *engine-core work*
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

### DS-2 — GUI data source: staker-mode engine adoption, wallet-rpc shape

**Proposal.** The GUI adopts the WI-1 lifecycle for staker wallets: open
the engine wallet, call `start_pscan_if_staker`, park the `PScanHandle`
(quiet `None` keeps non-staker wallets zero-cost). The `P`-balance
surface the UI reads is `drain_balance`'s aggregate scalar — the
decomposition never crosses into the GUI (F-D2 core-side contract).

**Open sub-question for review (the round's largest unknown):** the GUI
today manages wallet2 `.keys` files only. Does staker-mode adoption mean
(a) dual-open (wallet2 for principal ops + engine wallet for `P`-side)
with the wallet-file pairing rule pinned, or (b) engine-first for
staker wallets (staker wallets are engine wallets, period, and the GUI's
wallet2 path never learns about `P`)? (b) is cleaner and matches the
rewrite direction (Phase 5 deletes the C++ wallet), but its cost —
whether the GUI's principal surfaces work against an engine wallet
today — needs the pre-flight substrate check before this round can
close. **Not decided here.**

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

### DS-6 — The F-D4 §16.4 funding default (accepted rider)

Gate-6 §12.9 decision 3 accepted the funding default as F-D2-class:
**self-fund by default via GF-4b lineage; external growth-funding is a
loud override routed through the entry standoff**, with its growth-gating
cost (portfolio expansion gated on accumulated rewards ≥ FLOOR) stated
up front. This is a *funding-path* (value-in) default, not a drain
default — it rides the same subsystem PR chain because both are
`shekyl-gui-wallet` wallet-flow defaults under the F-D2 label, but it is
a separable slice (DS-6 can land in its own sub-PR without blocking
DS-3/DS-4/DS-5, and vice versa). Whether Gate-6 counts it inside "F-D2
landed" for the R4 close is a **review question for this round** — §12.4
build notes don't name it; §12.9 decision 3 attaches it to F-D2.

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
| DS-PR-1 | shekyl-core | Drain assembly: record re-map at the trust boundary, membership paths, actor signing, sealed pending record + `reserved_gindexes`; DS-4 fee carve + sweep entry | round closure + pre-flight |
| DS-PR-2 | shekyl-core | Drain dispatch seam (claim-dispatch sibling): choke-point submit on persona transport, retirement wiring | DS-PR-1 |
| DS-PR-3 | shekyl-gui-wallet | Staker-mode engine adoption (DS-2 shape as ratified): open + `start_pscan_if_staker` + parked handle; aggregate `P`-balance read | DS-PR-1 (API exists) |
| DS-PR-4 | shekyl-gui-wallet | Drain-send UI: amount entry + DS-5 defaults + confirm; calls the one engine entry point | DS-PR-2, DS-PR-3 |
| DS-PR-5 | shekyl-gui-wallet | DS-6 funding default (separable) | DS-PR-3 |
| DS-PR-6 | shekyl-core | DS-7 doc sweep + Gate-6/M1/FOLLOWUPS close-out lines | last |

Cross-repo note (rule 10): every engine-side API lands in `shekyl-core`
first; the GUI consumes released surface, never the reverse.

## 5. What this round does not decide

- The DS-2 sub-question (dual-open vs engine-first) — pre-flight
  substrate check owed, then maintainer ratification.
- Whether DS-6 is inside the R4 close's "F-D2 landed" — maintainer
  ratification against Gate-6 §12.9 decision 3's text.
- UI visual design (page placement, staking-page integration) — product
  surface, not firewall surface; falls out at DS-PR-4.
- Threat-model addenda (rule 26 A3) — owed as a late-round pass (Round
  2–3) once the shape above survives review; the objectives are already
  named (amount channel, transport isolation, mis-send).

## 6. Round log

- **2026-07-19 — Round 1 opened (this document).** Substrate enumerated
  at source (§2); DS-1…DS-7 drafted with proposed dispositions; slicing
  proposed (§4). Awaiting review.
