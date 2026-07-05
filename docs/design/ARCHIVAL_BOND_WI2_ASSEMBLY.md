# WI-2 — Production bond assembly + pending-post persistence

> **Status: design addendum (round 1), 2026-07-05.** The short spec-first
> round the WI-2 implementation anchors on (rule `05-system-thinking`:
> specification first). This is an *addendum* to
> [`ARCHIVAL_BOND_2D2_SP_T4_BROADCAST.md`](ARCHIVAL_BOND_2D2_SP_T4_BROADCAST.md)
> (the P-1/P-2 provenance pins this doc discharges) and
> [`ARCHIVAL_BOND_CONSTRUCTION.md`](ARCHIVAL_BOND_CONSTRUCTION.md) §7.3/§10
> (the funding-input and orchestration rules) — not a fresh 4–6-round design
> cycle. Index row: `WI-2` in
> [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md).
>
> **Timeframes (rule 05):** *now* — the production assemble path for the
> genesis JoinMarket bond. *Mining-era end* — no coupling; the path consumes
> typed terms and generic tx-builder surfaces. *V4* — the hybrid signature
> and ML-KEM ciphertext surfaces are already hybrid; lattice-only migration
> replaces primitives behind the same seams.

## 1. Scope

Promote the KAT-only bond assembly
(`local_pending_tx.rs::join_market_bond_post_signs_and_verifies_over_real_tree`)
to a production path, ending at a **sealed pending-post record** that WI-3's
block-timed dispatch driver consumes. In scope:

1. Per-output **funding-output discovery records** in the P-scan (the
   "steady-state funding-output discovery" reader named in
   `ARCHIVAL_BOND_PR2_CHAIN.md` §3.6 reader (a) — today only epoch *sums*
   exist).
2. **Funding selection** policy over those records.
3. The **assemble→sign→prove→encode** production flow, secret-locality
   preserving.
4. The **`PBoundBytes` mint site** (SP-T4 §3.1.1 pin P-1).
5. The **durable pending-post record** (SP-T4 §3.1.1 pin P-2).
6. Failure modes (rule 82).

Out of scope (WI-3): the dispatch due-check, `BroadcastSubmitter` wiring,
entry-event coordination (D1), retry/re-anchor semantics, live
`BondPostDispatched` emission. Out of scope (2d-2): posture-aware
`PBlockSource`, key-image-based external-spend reconcile (see §3.4 limitation).

## 2. Substrate (verified at `feat/pscan-lifecycle`, 2026-07-05)

| Fact | Where |
| --- | --- |
| `SignBond` returns `SignedBondPost { vin, plan }`; caller drops it | `stake_engine.rs` handler (`TODO(2d)` comment in step 5) |
| Wire `BondPost` prefix input carries **no signature** — the vin's hybrid signature rides tx-level auth, outside the prefix | `shekyl-wire/src/transaction.rs` `BondPost::write` |
| `tx_prefix_hash_for_signing` computes the signable hash from prefix parts only, **before** signing | `shekyl-tx-builder/src/wire.rs` |
| KAT flow: prefix hash → `build_join_market_vin` → `sign_transaction_with_terms` → `encode_final_tx`; credit rule `funding == change + fee + credit` (`verify_credit_funding`) | `local_pending_tx.rs` real-tree bond KAT |
| P-scan persists only per-epoch sums (`accruals`) + `BondPostRecord`s; per-output data is dropped in the offload closure | `pscan/scan_step.rs` `run_dual_extractor`, `pscan_state.rs` v3 |
| Curve-tree path assembly needs `AssembleInput { gindex, output_key, commitment }` | KAT's `assemble_tx` call |
| Spend-secret re-derivation from public identity: `derive_primary_source_secrets_bundle(&ciphertext, output_index)` — **principal keys only**; no P analog exists | `local_keys.rs` |
| `ArchivalPKeys` carries `view_sk`/`spend_sk`/`ml_kem_dk` — everything the P analog needs; bundles never leave the actor (rule 36) | `shekyl-crypto-pq/src/archival_p.rs` |
| `PBoundBytes` / `BroadcastSubmitter::for_posture` / `submit_bound` built, tests-only, with P-1/P-2 pins | `transaction_submitter.rs`, SP-T4 §3.1.1 |
| PScanState seal is single-writer via `PScanSlot` (the pscan task); sealed via `PScanStore` (`.wallet.pscan`) | `pscan/task.rs` |
| Bond floor: `n(holdings)`; timing defaults: ≥ 1 settlement-epoch spacing, fund-from-earnings ramp | `shekyl-archival-retention`, `ARCHIVAL_TIMING_CONSTANTS.md` §7 |

## 3. Design decisions

### 3.1 D-A1 — Per-output funding records, public-identity-only

**Decision.** Extend the dual extractor's reader (a) to emit, and
`PScanState` to persist, one record per recovered P-owned output:

```text
PFundingOutputRecord {
    p_slot:               u32          // owning persona slot (re-derivation selector)
    tx_hash:              [u8; 32]     // containing tx (public)
    index_in_transaction: u64          // KEM derivation index (public position)
    gindex:               u64          // global output index (curve-tree leaf)
    output_key:           [u8; 32]     // O (public, on-chain)
    commitment:           [u8; 32]     // C (public, on-chain)
    source_ciphertext:    x25519 ‖ ml_kem bytes (public, on-chain)
    amount:               AtomicUnits  // recovered cleartext amount
    height:               BlockHeight
    epoch:                SettlementEpoch
}
```

**No derived secrets are persisted** — `y`, `z`, `k_amount`,
`combined_shared_secret` drop in the offload closure exactly as today. This
is the M3a–M3e architectural-inheritance discipline (rule 16) applied at
design time: the record stores the same *public identity* shape post-M3d
`TransferDetails` stores (`source_ciphertext` + index), and the spend
bundle is re-derived at assemble time inside the StakeEngine actor (§3.3).

**Why store identity at scan time instead of re-fetching at assemble
time:** a targeted per-output fetch at assemble time is a probe-shaped
network event on whatever circuit carries it — fetching exactly the tx that
funds the imminent bond post is a correlation gift (GF-7's class of
adversary). The P-scan already holds the full block during the sweep; wide
block fetches are the cover. Record everything assembly needs while the
block is in hand, and assembly never touches the network.

**Privacy discipline at rest and in logs:** the record set ties amounts to
persona slots — persona-activity history, the same class as
`BondPostRecord`. Same treatment: redacted `Debug` (contents *and* count),
sealed at rest under the existing `.wallet.pscan` seal.

**Schema.** `PSCAN_STATE_VERSION` bumps 3 → 4 (rule 42). Pre-genesis: no
migration shim — a v3 seal fails the existing fail-closed version gate and
the operator re-scans (`rm -rf ~/.shekyl` posture, rule 15). The
`from_state`/`to_state` round-trip in `PScanAccrual` carries the new table
unchanged; ingest appends records in the same pass that accumulates the
epoch delta (one scan, two artifacts — the "one sweep, two readers" shape
of PR2_CHAIN §3.6 now materialized as data).

### 3.2 D-A2 — Funding selection policy

**Decision.** Selection runs Engine-side (public data only), reading the
sealed `PScanState`:

1. **Eligibility.** Every persisted record is already final: the pscan
   ingest horizon is `tip − ARCHIVAL_REORG_DEPTH_BLOCKS`, so nothing
   sub-horizon is in the state. Additionally exclude records **reserved**
   by a live pending post (§3.5) — the pending record is the single source
   of reservation truth; there is no separate spent-flag mutation to race.
2. **Ramp.** Fund-from-earnings (`ARCHIVAL_TIMING_CONSTANTS.md` §7): the
   spendable set is P's own scan-discovered outputs; if their sum is below
   `n(holdings) + fee`, assembly refuses with
   `InsufficientFunding { available, required }` — the caller waits for
   more earnings; no reach-across to principal outputs (that reach-across
   is the funding-seam linkage the whole architecture firewalls).
3. **Order.** Oldest-first (height, then gindex) greedy accumulation until
   `sum ≥ floor + fee`. Deterministic and auditable; these are P-local
   outputs spent to P's own bond, so input-selection unlinkability
   pressure (which drives randomized selection on the principal transfer
   path) does not apply — the bond post names `P` in cleartext anyway.
4. **Balance rule.** `funding == change + fee + credit` exactly
   (`verify_credit_funding`, CONSTRUCTION §7.3); one change output back to
   P's own address via the existing `construct_output` path.

### 3.3 D-A3 — Assembly flow and secret locality

**Decision.** One Engine-side orchestrator + one actor message. The
Engine-side half handles everything public; the actor half touches
`ArchivalPKeys` and never lets them out (rule 36; GATE6 firewall).

Engine-side `assemble_bond_post` (public):

1. Read sealed `PScanState`; select funding per §3.2.
2. Curve-tree `assemble_tx` → membership paths for the selected gindexes.
3. Build the change output (`construct_output` to P's address) and fee
   estimate; derive the prefix parts — key images come back from the actor
   (step 5), so the prefix assembly completes there.
4. Build the wire `BondPost` prefix-input fields from P's *public* identity
   (`PersonaIdentity`) + holdings + `n(holdings)`.
5. Send the actor message; receive `PBoundBytes` + `EntrySeamPlan`.
6. Persist the pending-post record (§3.5) **before** returning —
   persist-before-dispatch; WI-3 never sees bytes that aren't durable.

Actor message `AssembleBond` (extends the `SignBond` shape — same handle +
ticket typed contracts, same RNG preflight, same draw + `plan_entry_seam`
consumption, same GF-7 hook emissions), carrying the selected funding
records, paths, change/fee terms, and prefix parts. Inside the handler
(CPU + secrets offloaded to `spawn_blocking`, the SP-5 pattern):

1. **Derive per-output spend bundles** from the held `ArchivalPKeys` — the
   P analog of `derive_primary_source_secrets_bundle` (same
   `recover_combined_ss` → `derive_output_secrets` → `x = ho + b` pipeline,
   with P's `view_sk`/`ml_kem_dk`/`spend_sk`). New helper, lives with the
   actor; bundles are `Zeroizing` stack values that die in the closure.
2. Compute key images; complete the prefix; compute
   `tx_prefix_hash_for_signing`. No circularity: the wire `BondPost` input
   carries no signature (§2), so the prefix is fully determined before
   signing.
3. `build_join_market_vin(keys, holdings, &prefix_hash)` → signed vin +
   `credit_term`.
4. **Invariant A-1 (fail closed):** the vin's wire-encoded `BondPost`
   fields must be byte-identical to the prefix's `BondPost` input from
   Engine-side step 4. A mismatch means the signature binds a different
   post than the hash covered — a build defect, never a recoverable state.
5. `sign_transaction_with_terms(prefix_hash, spend_inputs, tree_ctx,
   credit_term, …)` → proofs; `encode_final_tx` → wire bytes.
6. **Mint `PBoundBytes::bind(persona, bytes)` here** — discharging pin
   P-1: the constructor moves to (or becomes private-to) this assemble
   module, so possession is proof of provenance and no re-wrap site
   exists.
7. Reply: `PBoundBytes` + `EntrySeamPlan` (+ the funding gindexes for the
   reservation record). Secrets never cross the boundary.

`SignBond` (the vin-only message) remains for the request-path composition
KAT; `AssembleBond` is the production superset. If review prefers a single
message, `SignBond` collapses into it — resolved at PR review, not
load-bearing either way.

### 3.4 Named limitation — external-spend detection is 2d-2 scope

Reservation (§3.2.1) covers the only spender that exists pre-2d-2: this
wallet's own bond path. Detecting an on-chain spend of a P funding output
that this wallet did not author (key-image watch) is the 2d-2 full-scan
reconcile's job; until it lands, a record could in principle go stale if
the seal is restored from backup onto a diverged history. Fail-shape: the
membership proof or daemon submit rejects (stale/spent input), assembly
fails loud, nothing is persisted. Accepted for WI-2; the reconcile closes
it structurally. (Reopen criterion, rule 21: 2d-2 SP-R0 lands → the
reconcile GC also prunes spent funding records.)

### 3.5 D-A4 — The durable pending-post record (pin P-2)

**Decision.** A **sibling sealed block** (`PendingPostBlock`) beside the
pscan seal — *not* a field inside `PScanState`:

- **Writer separation.** The pscan seal is rewritten every sweep batch by
  the pscan task under `PScanSlot` single-flight; pending posts are written
  by the assemble path (a different writer on a different cadence). Two
  writers racing one read-modify-seal cycle is the bug class the slot
  exists to prevent — separate blocks keep each seal single-writer.
- **Content** (postcard, own `PENDING_POST_VERSION = 1`, rule 42):

```text
PendingBondPost {
    p_slot:            u32
    persona:           PCanonicalId       // matches the PBoundBytes binding
    bound_tx:          PBoundBytes        // the value itself, per pin P-2 —
                                          // retries re-send the stored value
    plan:              EntrySeamPlan      // relative offsets, kept intact
    anchor_t0:         BlockHeight        // tip height at assemble time
    funding_gindexes:  Vec<u64>           // the reservation set (§3.2.1)
    state:             Pending            // WI-3 adds Dispatched{..}/Confirmed
}
```

- **`anchor_t0` semantics.** The plan is relative to the private intent
  anchor `t0` (`shekyl_standoff::plan` discipline); anchoring at assemble
  time keeps the draw's decorrelation intact and gives WI-3 a pure
  computation: `due = anchor_t0 + plan.bond_post_offset_blocks`.
- **Redaction.** The record is a persona-activity row (persona, plan,
  amounts implied by gindexes): redacted `Debug`, sealed at rest — the
  `BondPostRecord` discipline.
- **One live post per persona.** JoinMarket-only at genesis: a second
  assemble for a persona with a live pending post refuses
  (`PendingPostExists`) — the four-kind future (Rebond etc.) reopens this,
  per CONSTRUCTION §9's provisional table.

#### 3.5.1 At-rest threat model: the record as a linkability artifact

The sealed record holds a **fully-signed, broadcast-ready** bond
transaction plus its timing plan — a funds-and-linkage-bearing seal (the
top tier of the four-tier model; rule 36 territory). Threat-modeled
against disk seizure explicitly:

- **Seizure without the wallet passphrase** yields ciphertext:
  `.wallet.pending` is sealed under the same `file_kek` AEAD envelope
  family as `.wallet.keys` (`PayloadKind::PendingPostBlockPostcard`).
  The record's at-rest tier is exactly the keys file's tier — no new
  cleartext surface.
- **Seizure with the passphrase (open-wallet compromise)** must be
  assessed as *marginal* disclosure, because the adjacent seals under the
  same kek already fall: `.wallet.keys` yields `ArchivalPKeys` (from
  which every P output, bond, and signature is re-derivable — the wallet
  is broadcast-capable regardless), and `.wallet.pscan` yields the
  funding records and `bond_post_matches` (persona ↔ amount history).
  The pending record's genuinely **new** leak is the *pre-execution
  timing plan*: `EntrySeamPlan` + `anchor_t0` reveal the intended
  relative placement of a post that has not happened yet. That is
  intent-disclosure to an adversary who has already fully compromised
  the wallet — accepted, with the retention bound below as the
  mitigation.

**Why the fully-signed bytes, not minimum-to-re-derive (P-2 rationale).**
Sealing only re-derivation inputs (funding refs + plan + anchor) was
considered and rejected:

1. **Re-derivation cannot reproduce the bytes.** FCMP proof construction
   and the hybrid signature both draw fresh randomness by design; a
   re-derived transaction is a *different* transaction spending the same
   key images. After a dispatch attempt with unknown outcome (submit
   timeout; daemon accepted-then-crashed; partial propagation), re-sending
   different bytes creates a same-key-image conflict wherever the first
   copy landed — the retry is rejected as a double-spend and the wallet
   cannot distinguish "original confirmed" from "conflict" without a full
   reconcile. Byte-identical resend is idempotent under partial
   propagation; that idempotence *is* pin P-2.
2. **The tier doesn't drop.** The re-derivation inputs alone still name
   persona → funding set → timing plan (the linkage the finding worries
   about), and under the same-kek compromise above the adversary holds
   `ArchivalPKeys` and can produce broadcast-ready bytes anyway. Removing
   the signed bytes shrinks convenience for the attacker, not the tier of
   the seal.

**Retention bound.** The record lives from assemble to terminal state:
WI-3 retires it on `Confirmed` (and reservation-release on terminal
failure). The window is bounded by the seam plan's offsets plus
confirmation depth — days, not indefinite — and **one live post per
persona** caps exposure to at most one broadcast-ready bundle per persona
at any time. A record that never reaches terminal state is surfaced by
WI-3's resume-from-restart path, not silently retained.

### 3.6 D-A5 — Failure modes (rule 82)

| Failure | Shape | State after |
| --- | --- | --- |
| Funding sum < floor + fee | `InsufficientFunding { available, required }` — typed, expected during ramp | nothing persisted, nothing reserved |
| Live pending post for persona | `PendingPostExists` | unchanged |
| Prefix ↔ vin byte mismatch (A-1) | fail-closed defect error; `debug_assert` loud in dev | nothing persisted |
| Spend-bundle derivation / prove / encode failure | typed propagate (`StakeEngineError::BondBuild` family) | nothing persisted — no partial state, funding never reserved |
| Seal write failure after assemble | error to caller; bytes dropped | safe: persist-before-dispatch means nothing was broadcast; a retry re-runs the whole assemble (fresh draw, fresh plan — the old bytes never left the process) |
| Restart with pending post sealed | not a failure: WI-3 resumes from the record | reservation holds |

The persist-before-dispatch ordering is the load-bearing invariant: **no
transaction bytes reach any submitter unless the sealed record already
holds them.** WI-3 inherits it as its resume-from-restart guarantee.

## 4. Test plan (WI-2 gates)

- Dual-extractor emits per-output records matching the epoch sums it
  already emits (sum(records) == delta per epoch); redaction test extends
  the existing no-leak rendering proofs.
- `PScanState` v4 round-trip; v3 seal fails closed on version.
- Selection: ramp refusal boundary, reserved-exclusion, oldest-first
  determinism, exact balance rule.
- P spend-bundle derivation: byte-identical to scanner-derived secrets for
  the same output (the M3b property-test shape, P edition).
- End-to-end assemble over the real tree (the KAT flow, production path):
  assemble → verify vin accept + `verify_credit_funding` + proofs verify;
  A-1 mismatch injection fails closed.
- Pending record: sealed round-trip, `PendingPostExists` refusal,
  reservation excludes funding from a second assemble.

## 5. Round-1 closure

Dispositions D-A1..D-A5 are the addendum's output; open-for-review items
are (a) `SignBond`/`AssembleBond` message unification and (b) the exact
placement of the P spend-bundle helper (actor-local vs `shekyl-crypto-pq`).
Neither changes the seams above. Per the plan's 1–2-round budget, round 2
(if any) is the PR review itself.
