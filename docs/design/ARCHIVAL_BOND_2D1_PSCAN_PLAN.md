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
sharing the *code* leaks nothing **against a chain observer**. But the firewall boundary
is **not the code, and not only the keys** — it is **keys, state (cursor + output set),
the operational/fetch layer, and execution**:

- **Keys:** `P.view_sk` lives only in StakeEngine (already true — Model-D holds it; the
  LedgerEngine never sees it). The `P`-scan builds a `ViewPair` *from `ArchivalPKeys`*
  and never hands `view_sk` across the actor boundary (`PersonaIdentity` is public-only).
- **Cursor + output set:** `P` gets its **own** sealed cursor and output set — it **must
  not** reuse `LedgerBlock::tip` / `LedgerIndexes` (the principal's), or the two
  perspectives cross-contaminate (DQ4).

**Primary derived constraint — the operational/fetch layer (the Monero light-wallet
lesson).** The block *fetch* is where stealth-address chains' privacy actually died: the
cryptography was sound, but *which blocks/outputs you request* links you, and a server —
or a **shared local cache** — that serves both identities sees the correlation the view
key was meant to hide. So the load-bearing rule, elevated from a 2d-2 parenthetical to
**the** constraint 2d-1 pins: **the `P`-scan's block source is an *injected, per-`P`,
fetch-everything* interface — no selective requests, no shared buffer, no shared cache.**
`P` fetches its **own full block range**; it never reads blocks the principal already
pulled, even from the same local daemon. If it does, a "separate cursor" is cosmetic —
the blocks arrived over one connection, deduped by one cache — and **2d-2 cannot isolate
that without re-architecting 2d-1**. Pinning the fetch-everything injectable now is what
lets 2d-2 swap the Arti transport in *underneath* without touching the scan (DQ-type).

**The execution/timing boundary — "pure" is source-level, not execution-level — but it
is the *weaker* of two side-channel families, and the family with a body count is already
guarded.** Distinguish them, because they get conflated:

- **Key-extraction side channels** (Minerva/TPM-Fail on ECDSA nonces, ROCA, power analysis
  on Ledger/Trezor) — **catastrophic** (recover the key, steal funds). This is the family
  that drew blood — on **signing hardware/HSMs/smartcards**, *not* exchanges-via-scanning
  (the big exchange losses were custody, insider, and fraud). So the high-value "fix it
  now" points at the **signing path**, not the scan. **Verified at source:** the hybrid
  bond/spend sign is `ed25519-dalek` (deterministic RFC-8032 nonce — no nonce-sampling
  leak) + `fips204` ML-DSA-65, behind a **four-tripwire 64-bit-only build gate** that
  names **KyberSlash** (Bernstein et al., 2024) as the exact threat (`crypto-pq/src/lib.rs:14–48`).
  The catastrophic family is already hardened; nothing to do here for 2d-1.
- **Ownership/linkability side channels** (scan timing leaks *which outputs are yours*) —
  a **deanonymization** risk, not theft, with no notable real-world loss, requiring a
  **co-resident** observer timing the process. This is the 2d-1 question, and it is the
  weaker cousin.

And on the scan cousin, **neither "in-scope = process isolation + CT compare" nor a flat
defer is right** — both as I first framed them are wrong:

- **A CT compare alone is nearly cosmetic.** The dominant leak is the **pre-filter
  early-exit**, not the final `!=`: the signal is *how far down the pipeline each output
  got* (rejected at the FA-6 filter vs ran full ML-KEM recovery vs reached the compare).
  Making the last `!=` constant-time while the filter early-exits leaves the big signal
  intact. **Truly** closing it means running the **entire** per-output path on **every**
  output (full ML-KEM decap + recovery + CT compare, *no early exit*) — discarding the
  FA-6 performance win **on every wallet, every sync**: a permanent all-user tax.
- **Process isolation does not rescue it** — cross-process / cross-VM cache attacks cross
  the boundary. And in **self-custody**, an adversary who can time your scan can almost
  always **read its memory** — where `P.view_sk`, the bonded-union, and the output sets
  live; CT scanning then rearranges deck chairs while they read the keys. The *one* model
  where timing-without-memory holds is **shared-cloud co-tenancy** (e.g. an exchange
  running `P`-staking on shared hardware) — real, but its right mitigation is **dedicated
  hardware**, not taxing every wallet's sync.

**Resolution — build the seam, do the cheap compare, defer the tax (the third option).**

- **Now, unconditionally:** (1) the **constant-time ownership compare** — free, correct
  regardless of the scope call, no argument for a variable-time `!=` on a secret bit; and
  (2) the **architectural seam** — the per-output extractor behind a trait whose
  constant-time, **no-early-exit** implementation is a *drop-in swap*, not a
  re-architecture. The expensive-to-retrofit thing is the *architecture* (where the scan
  runs, the swappable extractor, the fetch-everything `BlockSource`); the cheap-to-add
  thing is the CT impl *behind* that stable seam.
- **Deferred (seam in place, rule-21 reopen):** the constant-time-**everything**
  no-early-exit path + execution isolation. **Reopen criteria:** (a) a deployment target
  enters scope where timing-without-memory is real (**shared-cloud staking-as-a-service**),
  or (b) the cold-start/cover analysis shows the scan-timing channel meaningfully narrows
  `P`'s anonymity set beyond what the **network** and **funder-scope** seams already cover.
  Filed, named, swappable — not silently dropped.

So 2d-1 reuses the scanner's primitives (`GuaranteedViewPair`, `Scanner`,
`scan_output_recover`) with `P`'s keys; isolates **state and the fetch layer** (per-`P`
fetch-everything `BlockSource`); does the **CT compare + the swappable extractor seam**;
and defers constant-time-everything behind that seam. This is the boundary the rest
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
over the range up to the finality horizon — and the lag-tolerant funding reader rides on
top of that for free (a finality-complete scan over-serves it). The reconcile extractor
reads **public** bond-posts (no secret); the funding extractor runs the view-key
ownership test. Conflating them into one secret-bearing sweep would have given reader (b)
a privacy surface it doesn't need and reader (a) a completeness burden it doesn't need.

**Consequence 1 (benefit) — 2d-1 needs *no reorg machinery*.** Because the cursor commits
only out to the finality horizon, `P` **never commits a scan result inside the reorg
window**, so — unlike the ledger scan, which carries an explicit `RollbackToFork` — the
`P`-scan has **no reorg-rollback path to build**: the finality lag *is* the reorg defense.
State it deliberately, so nobody later "improves" the `P`-scan by reading closer to tip
and silently reintroduces a rollback surface.

**Consequence 2 (cost) — a network-parameterized funding-visibility lag feeds cold-start.**
That finality horizon is **`max_reorg_depth`, which is *network-parameterized*, not a
constant** (the cover work already moved off the hardcoded `720`: archival ≈ 720, testnet
6 — `NetworkSafetyConstants`). `P` discovers its funding by **scanning** (the firewall-clean
path — being *handed* the funding tx out-of-band would relink principal→`P`). So
**cold-start "stake from the cover" inherits a `max_reorg_depth`-deep discovery latency**:
`P` cannot see the cover output to spend it until it is finality-deep — most of a day on
archival, trivial on testnet, so the cold-start sequence **behaves differently per
network**, and the cover/standoff timing was pinned *without this lag in view*. **Two pins
for Round 1:** (a) confirm `P` truly *scan-discovers* its funding (vs is handed it), and
(b) if so, name the `max_reorg_depth` funding-visibility lag as an **explicit input to the
cold-start sequence** — it composes with the already-pinned entry-gap standoff.

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

**Hard constraint on lean (i): the scan-step is bounded and offloaded, never a blocking
handler.** A scan-step run inline in the actor's handler blocks the **single-threaded
mailbox** for its duration — a full sync would *freeze* the StakeEngine (no rotation, no
sign, no activate). The actor is already shaped for this: Model-D derivation runs in
`spawn_blocking` *off* the hot path. So the per-scan-step must do the same — **chunked
per-block or per-batch and offloaded** — so the actor stays the `view_sk` vault that
*dispatches* the ownership test without *blocking* on it. This is part of the resolution,
not a Round-1 surprise.

### DQ7 — scan correctness: the two ways a corrupted scan mis-sizes a *privacy parameter*

`SP-4`'s inflow accrual feeds the cover's `C_min` — a **privacy** parameter — so a scan a
local adversary can *corrupt* doesn't merely lose an output, it mis-sizes the firewall's
runway floor off poisoned input. Two cross-chain failure shapes, both already defended in
the tree if 2d-1 selects for them:

- **Burning-bug immunity is a *variant-selection* requirement, not new code.** The scanner
  ships a plain `ViewPair` **and** a `GuaranteedViewPair` / `GuaranteedScanner`
  (`view_pair.rs:113`, `scan.rs:954`) that drops colliding one-time keys under a guard
  contract (`ledger_ext.rs:154`). An adversary can send `P` colliding one-time keys; the
  plain variant would mis-count, and `SP-4` would then size `C_min` off a corrupted
  inflow. **SP-1 must scan with the `Guaranteed` variant** — name it, or the default plain
  one silently undersizes the firewall.
- **The accrual rate is computed from *confirmed* outputs, never pre-filter hits (the Zcash
  trial-decryption-DoS lesson).** Trial-decryption is a per-output cost an adversary
  inflates by stuffing the chain; the FA-6 pre-filter is therefore load-bearing for DoS,
  not just speed (so the reuse is doubly justified). But `SP-4`'s rate must be computed
  from outputs that **passed the full ownership test**, never from FA-6 *pre-filter hits*
  (the ~1/256 false positives that pass the byte filter and burn a full recovery) — else
  an attacker pumps the *apparent* inflow rate and skews `C_min`, the same "corrupt the
  privacy parameter via the scan" failure, a different vector.

---

## 3. SP-# enumeration (sub-parts / deliverables)

| SP | Deliverable | Notes |
| --- | --- | --- |
| **SP-0** | The **per-`P` `BlockSource` trait** (fetch-everything; *no* selective-request or shared-buffer method exists) — the DQ1 keystone | 2d-1 ships a local impl; 2d-2 swaps Arti underneath, untouched |
| **SP-1** | `GuaranteedViewPair`-from-`ArchivalPKeys` adapter + a `P`-scan over the scanner's pure primitives | reuse `GuaranteedScanner`/`scan_output_recover`; **immune variant** (DQ7); no scanner fork |
| **SP-1a** | The **CT ownership compare** + the per-output **extractor seam** (trait; CT-no-early-exit impl is a drop-in swap) | DQ1 third option — do the cheap part now, defer the perf tax behind the seam |
| **SP-2** | The sealed `P`-scan **cursor** (StakingBlock-class; new version const) | DQ4; separate from `BlockchainTip`; no rollback path (DQ2 c1) |
| **SP-3** | **Dual extractor** over one block-iteration: view-key funding outputs (a) + public bond-post match (b) | DQ2; cursor at reconcile-grade finality |
| **SP-4** | The **per-epoch `P`-earnings-inflow accrual** (reader-a output `C_min` consumes) — from **confirmed** outputs only | DQ3/DQ7; `AccrualRecord`-modeled |
| **SP-5** | The scan-loop **home** — `P`-scan task owning cursor + cadence + `BlockSource`; actor performs the **offloaded, non-blocking** scan-step, `view_sk` never crosses | DQ6 |
| **SP-6** | The reconcile **interface** reader (b) hands to 2d-2 (which performs the GC) | the GC *action* is 2d-2 |

**Scan-timing posture (DQ1, resolved — the third option, not a Round-1 binary):** Round 1
does the **CT ownership compare** + the **swappable no-early-exit extractor seam** (SP-1a),
and **defers** constant-time-everything + execution isolation behind that seam under a
rule-21 reopen (shared-cloud staking-as-a-service, or a cover/cold-start anonymity finding).
The catastrophic side-channel family (signing) is separately verified CT-and-guarded, so no
2d-1 action there.

**Out of scope (carried to 2d-2):** the Arti transport *impl* behind SP-0's `BlockSource`
(the interface is pinned now; the transport is 2d-2), the actual `bonded_slots`/`p_slot`
GC, broadcast/re-anchor. 2d-1 is **read-side only** — it produces the output set, the
inflow accrual, and the reconcile input; it broadcasts and GCs nothing.

---

## 4. Type-safety opportunities (make the firewall boundary unrepresentable to cross)

Rust's type system is a reason we're here; where a constraint above is *structural*, it
should be a **type that makes the violation unrepresentable**, not a convention a reviewer
must police. The candidates this boundary surfaces, for Round 1 to realize:

- **`BlockSource` trait with no selective-fetch method (SP-0).** The fetch-everything rule
  is enforced by the *shape of the trait*: it exposes "give me block at height `h`" / "the
  next block", and **no** "give me outputs matching X". A wallet-server-style selective
  query is then literally uncallable — the Monero-light-wallet leak is unrepresentable, and
  2d-2's Arti impl satisfies the same trait. (Make-bad-states-unrepresentable, as with the
  `PersonaHandle` `!Clone` seal.)
- **A typed `PScanCursor` distinct from `BlockchainTip`.** Two cursor types, not one `u64`
  reused — so a `P`-cursor can never be passed where the principal's ledger tip is expected
  (or vice versa), the DQ4 cross-contamination caught by the compiler, not a code review.
- **A typed `PFundingInflow` (per-epoch), not a bare `u64`.** The `C_min`-feeding accrual
  (SP-4) carries its unit and its *provenance invariant* in the type — constructible **only**
  from confirmed outputs (DQ7), so a pre-filter-hit count cannot be passed to `C_min` sizing
  even by mistake. The cover's `C_min` consumer then takes `PFundingInflow`, not `u64`.
- **`GuaranteedViewPair` as the *only* constructor on the `P`-scan path (SP-1).** The plain
  `ViewPair` is simply not in the `P`-scan's type surface, so the burning-bug-vulnerable
  variant is unselectable for `P` — DQ7's variant choice enforced by construction.
- **A per-output `Extractor` trait (SP-1a) so the constant-time path is a *swap*, not a
  rewrite.** The ownership test sits behind a trait; the default impl reuses the FA-6
  early-exit, a future CT-no-early-exit impl satisfies the same trait. The expensive
  scan-timing decision (DQ1) becomes a one-line impl swap behind a stable seam — the
  architecture is pinned now, the perf tax is paid only if-and-when a co-tenancy target
  reopens it.
- **A typed reconcile result for SP-6** (the public bond-post match set `P` hands 2d-2),
  distinct from the funding output set — so the two readers' outputs can't be conflated at
  the 2d-2 boundary.

The throughline: each load-bearing *don't* in §2 becomes a *can't* in the types. Round 1
designs these alongside the per-SP work, not as a cleanup pass after.

---

## 5. Dependency posture (why this is the keystone, and parallelizable)

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
