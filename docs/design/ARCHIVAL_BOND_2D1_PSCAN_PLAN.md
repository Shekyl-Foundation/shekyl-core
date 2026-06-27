# Bond-PR 2d-1 — the `P`-scan layer (Round 0 scoping pre-flight)

**Arc / numbering authority:** [`ARCHIVAL_BOND_PR2_CHAIN.md`](ARCHIVAL_BOND_PR2_CHAIN.md)
§3.6 (2d-1 is 2d's first sub-part; this doc is the architecture round nested under it).
**Status:** ROUND 0 — scoping for review. The architecture DQs are enumerated and
resolved-at-source; no code. **Process rule:** `26-sub-pr-design-discipline.mdc`
(firewall-load-bearing — getting the isolation boundary wrong is a privacy break, not
a refactor, so the boundary is decided *first* and the rest derived from it).

---

## 0. Why this is a real architecture round, not implementation-under-§3.6

§3.6 gives 2d-1 its *architecture in prose* — a firewalled `P.view_sk` sweep inside
StakeEngine, "one sweep, two readers." But from landed code, three of those phrases are
**claims the codebase does not yet make true**, and each is firewall-load-bearing:

1. **"Scan isolation" is asserted, not built.** `shekyl-scanner` is a single ledger
   scan with **zero** `view_sk`/archival/firewall/persona hooks (greenfield). *How* the
   `P`-scan stays isolated is the boundary itself — and the cheap option dissolves the
   property §3.6 names.
2. **"One sweep, two readers" may conflate two different scans** with opposite
   "what-does-a-miss-cost" profiles — and, it turns out, **different data and different
   key material**.
3. **The cover's `C_min` depends on a quantity 2d-1 is not yet specced to produce** (the
   earnings ramp), so it has to be named a deliverable or it becomes a rediscovery.

So this round decides the **isolation boundary first** (DQ1) and derives the reader
split, the deliverables, and the secret/cursor pins from it. The tell of under-scoping
would be a plan that jumps to "add a scan loop to StakeEngine."

---

## 1. The landed substrate (grounded, not §3.6's description)

| Surface | What's actually there | Cite |
| --- | --- | --- |
| Scanner ownership test | **Pure function of `(output, ViewPair)`** — ML-KEM decap + FA-6 pre-filter + ECDH + spend-key compare; reads/writes no wallet state | `shekyl-scanner/src/scan.rs:626–648` |
| `ViewPair` | `Zeroize`/`ZeroizeOnDrop`; carries `spend`, `view`, `x25519_sk`, `ml_kem_dk` (+ parsed dk) | `scan.rs`/`view_pair.rs:32–111` |
| Cursor (`synced_height`) | In **`LedgerBlock::tip` (`BlockchainTip`)**, engine-state — **not** the scanner; crash-atomic via `atomic_write_file` | `engine-state/src/ledger_block.rs:100–124` |
| Owned outputs / balance | `TransferDetails`; `BalanceSummary` — **no earnings rate** | `engine-state/src/transfer.rs`, `scanner/src/balance.rs` |
| Per-block accrual | `AccrualRecord`/`StakerPoolState` (chain-wide reward accrual; **not persisted**, rebuilt by replay) | `engine-state/src/staker_pool.rs:15–32` |
| `P.view_sk` | `ArchivalPKeys.view_sk: ViewSecret` (per-field `ZeroizeOnDrop`); deterministic re-derive from seed — **no `combined_ss` field exists** | `crypto-pq/src/archival_p.rs:321–351, 308–320` |
| Held personas | StakeEngine holds the **derive-forward bonded-union** (`BTreeMap<PSlot, HeldPersona>`) of *full* `ArchivalPKeys` (incl. `view_sk`), **resident** open→close; ephemerals wiped on rotation, bonded never | `stake_engine.rs:16–41, 197–217` |
| Actor lifecycle | `on_start` tags bundles + self-cert; **purely message-driven — no tick / periodic loop** | `stake_engine.rs:606–660` |
| Seal precedent | `StakingBlock` — postcard, AEAD-sealed, `tmp→fsync→rename→fsync(parent)`, versioned (`STAKING_BLOCK_VERSION`) | `engine-state/src/staking_block.rs:80–88` |
| Bond-post on-chain | `ArchivalBondPostVin` carries `p_canonical_id`, `bond_floor` **cleartext** — bonds are **public** | `archival-retention/src/bond_wire.rs:73–82` |

**The two facts that drive everything:** the scanner's decode+ownership-test is **pure
and view-key-parametric** (so it is safe to *reuse* with a second key), and **bond-posts
are public** (so the reconcile reader needs no view key at all).

---

## 2. Architecture decision questions (DQ1 first; the rest derive from it)

### DQ1 — the isolation boundary (decide this first; everything sits on it)

**The false dichotomy §3.6 invites:** "second independent scan pass (true isolation,
double cost) **vs** piggyback on the ledger scan's decode (cheap, but shared code path =
cross-contamination)." Landed code dissolves it: **the decode is a *pure* function**, so
sharing the *code* leaks nothing. The firewall boundary is **not the code — it is the
keys, the cursor, the output set, and the network**:

- **Keys:** `P.view_sk` lives only in StakeEngine (already true — Model-D holds it; the
  LedgerEngine never sees it). The `P`-scan builds a `ViewPair` *from `ArchivalPKeys`*
  and never hands `view_sk` across the actor boundary (`PersonaIdentity` is public-only).
- **Cursor + output set:** `P` gets its **own** sealed cursor and output set — it **must
  not** reuse `LedgerBlock::tip` / `LedgerIndexes` (the principal's), or the two
  perspectives cross-contaminate (DQ4).
- **Network:** the block *fetch* is the correlatable surface (a network observer seeing
  `P` and the principal pull the same blocks over the same connection links them). That
  is the **`P`-isolated Arti outbound path — deferred to 2d-2**. At the 2d-1 (read-side)
  layer there is no transport yet, so 2d-1 scans a block *source* (fixture / local
  daemon) with `P`'s keys/cursor/output-set; 2d-2 layers the isolated fetch underneath.

**Resolution:** reuse the scanner's **pure primitives** (`ViewPair`, `Scanner::scan`,
`scan_output_recover_with_ml_kem_dk`) with `P`'s keys; isolate **state (cursor + output
set), secrets (view-key residency, DQ5), and network (2d-2)**. "Piggyback the decode" is
safe *because* the decode is pure; the cross-contamination the firewall prevents is at
the key/state/network layers, which `P` owns separately. This is the boundary the rest
derives from.

### DQ2 — the two readers are *not* the same scan (split confirmed at source)

§3.6's "one sweep, two readers." From source they differ in **data, key material, and
miss-cost**:

| | (a) Funding discovery | (b) Bond reconcile |
| --- | --- | --- |
| Scans for | `P`'s **confidential** funding outputs | `P`'s **public** bond-posts on-chain |
| Needs | `view_sk` (ML-KEM/ECDH ownership test) | **no `view_sk`** — match `p_canonical_id` cleartext |
| Miss costs | an output isn't spent *yet* — **lag-tolerant** | a phantom `bonded_slot`/`p_slot` GC'd wrong, or a real bond missed → **persisted ticket diverges from chain truth (correctness)** |
| Class | wallet-balance | consensus-reconciliation (**finality depth + completeness over a range**) |

**Resolution:** it is **one block-iteration, two extractors**, *not* one homogeneous
sweep. The **cursor is pinned to the stricter (reconcile) discipline** — completeness
over the range up to the finality horizon (`ARCHIVAL_REORG_DEPTH_BLOCKS`-deep) — and the
lag-tolerant funding reader rides on top of that for free (a finality-complete scan
over-serves it). The reconcile extractor reads **public** bond-posts (no secret); the
funding extractor runs the view-key ownership test. Conflating them into one
secret-bearing sweep would have given reader (b) a privacy surface it doesn't need and
reader (a) a completeness burden it doesn't need.

### DQ3 — the earnings-ramp signal is a *deliverable*, not an emergent hope (`C_min`)

The cover's `C_min` (runway floor, `ARCHIVAL_COVER_DRAW.md` §8.3) is sized against **how
fast `P` earns** in steady state — and that rate is an output of reader (a). The scanner
produces an **output set**, not a rate; `AccrualRecord` is chain-wide reward, not `P`'s
*realized inflow*. **Resolution:** 2d-1 must name, as an explicit reader-(a) deliverable,
a **per-epoch `P`-funding-inflow accrual** (new `P` funding outputs × amount per
settlement epoch) — the ramp signal `C_min` consumes, modeled on the `AccrualRecord`
per-height pattern. Without it, 2d-1 "completes," `C_min` sizing starts, and discovers
the scan reports *which* outputs exist but not the *rate* — a rediscovered measurement
pass.

### DQ4 — the cursor is funds-relevant state: `P`-owned, sealed, StakingBlock-class

A `P`-scan cursor that loses its place re-scans or **half-scans** — and the cursor
(plus the reconcile's completeness claim) is funds-relevant. **Resolution:** `P` owns a
**separate** sealed cursor (not `BlockchainTip` — DQ1), following the **`StakingBlock`
discipline exactly**: postcard + AEAD seal + `atomic_write_file` (`tmp→fsync→rename→
fsync(parent)`) + a version constant, tier-4 (sealed, not advisory). A persisted cursor
is then a durable crash-atomic commit; on reopen the monotone-cursor rule prevents a
rolled-back scan from re-reporting.

### DQ5 — view-key locality: reuse the resident union, don't widen the surface

The sweep needs `view_sk` live. **It already is** — Model-D holds the bonded-union's full
`ArchivalPKeys` resident (bonded never wiped). **Resolution:** the sweep reuses the
**already-resident** union keys (no *new* residency), constructs a **transient
per-persona `ViewPair` dropped after that persona's scan** (don't hold all `ViewPair`
copies resident at once), and the scanned set **is** the bonded-union (Model-D's existing
surface — bounded by lookahead + bonded slots, not "every rotated persona ever"). So
2d-1 adds **no** secret-residency surface beyond what Model-D already holds; it only adds
the transient per-scan `ViewPair` copies, dropped per persona.

### DQ6 — where the scan loop lives (no tick exists)

The actor is **purely message-driven; there is no tick**. So a periodic sweep has no
home. **Open sub-decision (the one DQ this round flags rather than fully resolves):** the
loop is either (i) a dedicated **`P`-scan task** that owns a clone-free handle and
messages the actor for keys per sweep, or (ii) the actor gains a scan-driver message an
external scheduler calls. (i) keeps the actor message-pure but needs a key-access message
that returns *something scannable without exposing `view_sk`* (e.g. the actor performs
the ownership test internally and returns owned outputs — secret never leaves); (ii) adds
a periodic surface to a deliberately message-only actor. **Lean: (i)** — the actor stays
the `view_sk` vault and *performs* the scan-step on request (secret never crosses the
boundary, consistent with `PersonaIdentity` being public-only), the task owning the
cursor, block source, and cadence. Confirm against the kameo handler model in Round 1.

---

## 3. SP-# enumeration (sub-parts / deliverables)

| SP | Deliverable | Notes |
| --- | --- | --- |
| **SP-1** | `ViewPair`-from-`ArchivalPKeys` adapter + a `P`-scan over the scanner's pure primitives | reuse `Scanner`/`scan_output_recover`; no scanner fork |
| **SP-2** | The sealed `P`-scan **cursor** (StakingBlock-class; new version const) | DQ4; separate from `BlockchainTip` |
| **SP-3** | **Dual extractor** over one block-iteration: view-key funding outputs (a) + public bond-post match (b) | DQ2; cursor at reconcile-grade finality |
| **SP-4** | The **per-epoch `P`-earnings-inflow accrual** (reader-a output `C_min` consumes) | DQ3; `AccrualRecord`-modeled |
| **SP-5** | The scan-loop **home** — `P`-scan task owning cursor + cadence + block source; actor performs scan-step, `view_sk` never crosses | DQ6 |
| **SP-6** | The reconcile **interface** reader (b) hands to 2d-2 (which performs the GC) | the GC *action* is 2d-2 |

**Out of scope (carried to 2d-2):** the `P`-isolated Arti outbound fetch (DQ1 network
layer), the actual `bonded_slots`/`p_slot` GC, broadcast/re-anchor. 2d-1 is **read-side
only** — it produces the output set, the inflow accrual, and the reconcile input; it
broadcasts and GCs nothing.

---

## 4. Dependency posture (why this is the keystone, and parallelizable)

- **North-Star-independent.** 2d-1 is read-side; it never broadcasts, so it does **not**
  wait on the daemon-accept gate (`e2e_fcmp_spend_accepted_by_daemon`). It parallelizes
  the active North-Star work.
- **Three consumers hang off it:** 2d-2's reconcile (consumes SP-3/SP-6), steady-state
  fund-from-earnings (consumes SP-1/SP-4), and the cover's `C_min` (consumes SP-4). The
  cover design is otherwise complete (PR #192) — `C_min` is its one unset magnitude, and
  it is unset *because* SP-4 does not exist yet.

**Round 1** drafts the per-SP design (the kameo handler shape for DQ6, the cursor schema
and version const for DQ4, the inflow-accrual type for DQ4/SP-4) once this boundary is
ratified.
