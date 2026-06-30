# Bond-PR 2d-1 — the `P`-scan layer (Round 0 scoping pre-flight)

**Arc / numbering authority:** [`ARCHIVAL_BOND_PR2_CHAIN.md`](ARCHIVAL_BOND_PR2_CHAIN.md)
§3.6 (2d-1 is 2d's first sub-part; this doc is the architecture round nested under it).
**Status:** ROUND 0 (boundary — ratified) + ROUND 1 (per-SP design, §6) + ROUND 2 (seam
hardening — cadence-injectable, SP-6 coverage, cover-discovery split, DQ8 union-shrink) +
ROUND 3 (threat-model cross-check vs `ARCHIVAL_FIREWALL_THREATS.md` — SP-7 funding-side gate
closes `TM-3`; cross-reference table marks what 2d-1 can/can't address) — for review; no code. Round-2's source-verification items are **resolved at source**: DQ8's
terminal-bond predicate exists (`Unbond` + Full-retirement) with `W` single-sourced from
config for production; the cover output's *form* is verified-covered (no recovery carve-out;
FA-6 false-negative-free modulo negligible KEM decap) and its sender corrected to the
**principal**. Rounds accrete in this one doc. **Process rule:** `26-sub-pr-design-discipline.mdc`
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
is then a durable crash-atomic commit; the *crash-recovery* design (how a stale-on-reopen
cursor is handled) is resolved in §6 SP-2/SP-4 — **Design B**: the cursor is the single
authoritative frontier and resume re-scans idempotently, rather than a monotone-forward
clamp (whose floor, unlike the slot's, has no chain-derived source).

### DQ5 — view-key locality: reuse the resident union, don't widen the surface

The sweep needs `view_sk` live. **It already is** — Model-D holds the bonded-union's full
`ArchivalPKeys` resident (bonded never wiped). **Resolution:** the sweep reuses the
**already-resident** union keys (no *new* residency), constructs a **transient
per-persona `ViewPair` dropped after that persona's scan** (don't hold all `ViewPair`
copies resident at once), and the scanned set **is** the bonded-union (Model-D's existing
surface — bounded by lookahead + bonded slots, not "every rotated persona ever"). So
2d-1 adds **no** secret-residency surface beyond what Model-D already holds; it only adds
the transient per-scan `ViewPair` copies, dropped per persona. (That this resident set stays
bounded by *active* rather than *lifetime* bonds is **DQ8** — "bonded never wiped" needs a
retirement condition or it is unbounded.)

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

### DQ8 — the bonded-union must be able to *shrink*: bound residency by active, not lifetime, bonds

DQ5 reuses the resident bonded-union and notes "bonded never wiped." That is correct for
**reachability** — a retired-but-still-bonded persona's funding must keep being scanned until
its bond obligation is genuinely over. But taken alone it means the resident `view_sk` set and
the per-sweep scan cost grow with `P`'s **lifetime** bond history, and the secret-residency
surface **never shrinks** — the Monero subaddress-lookahead foot-gun (unbounded scan sets that
degrade over time). Not a privacy break, but a long-run cost and a monotonically-growing
secret surface, and there is a natural bound DQ5 doesn't use.

**The bound: a persona that is genuinely *done* should leave the union** — its key out of
residency, its funding outputs out of the re-scan set. Two things to pin:

1. **Retirement is a *positive* confirmation, never inference-from-absence** — the **same
   discipline as SP-6**, aimed at the lifecycle: retire a persona only on an *affirmatively
   confirmed* terminal-and-finality-deep bond state, **never** because a scan "didn't see its
   bond" (which a transport gap or a stale source also produces). A persona wrongly retired on
   absence stops scanning *live* collateral — the funds-loss mirror of SP-6's wrongful GC.
2. **The terminal predicate exists — use it (resolved at source).** Archival bonds are
   **not** permanent: `BondPostKind::Unbond` (`bond_wire.rs:34`) is the terminal post kind —
   after exit + the release cooldown it zeroes the persona's `bonded_total_atomic`
   (`ARCHIVAL_BOND_GATE4.md` §4.3). Settlement-epoch / `claimed_epochs` machinery is **reward
   accounting, *not* bond termination** — orthogonal. And the retirement predicate is already
   named in design: **"Full retirement = bond released ∧ backlog exhausted/lapsed; then
   `p_slot` burn"** (`PHASE_2B_FSM_RETOOL.md:209`). So a persona is wipe-eligible when its bond
   is **Unbonded** *and* its reward **backlog window `W` has lapsed** (it can still claim for up
   to `W` epochs after Unbond, so it must keep scanning until then) *and* both are
   **finality-deep**. **Resolution:** the union shrinks to **active bonds + the `W` backlog
   tail**, not lifetime bonds — DQ5's "bounded by bonded slots" bound is now *real*, anchored on
   the existing Unbond + Full-retirement predicate, retired on positive confirmation per (1).
3. **SP-5's retirement predicate must read the consensus `W`, not a re-literal.** The
   predicate and consensus's claim-window must agree on `W` *exactly* — retire a persona at a
   shorter `W` than consensus allows claims for, and the scan stops watching a persona that can
   still receive reward outputs, under-counting SP-4's inflow and mis-sizing `C_min` (the
   privacy parameter) again. `W` is single-sourced for consensus:
   `config/consensus_constants.json:21` (`max_claim_age_w: 26`) → generated into
   `pub const MAX_CLAIM_AGE_W` by `shekyl-archival-retention/build.rs:99` → consumed by the
   claim-window (`claimed_epochs.rs:84`) and prune (`archival_ffi.rs:468`). **SP-5 (production)
   must read *that* generated const**, never a copied literal. (The independent
   `MAX_CLAIM_AGE_W` in `shekyl-staking-sim` is *not* a violation — the sim is a
   configuration-sweep harness, never compiled into a production binary; differing from
   production values is its purpose.)

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
| **SP-5** | The scan-loop **home** — `P`-scan task owning cursor, **injectable cadence**, and `BlockSource`; actor performs the **offloaded, non-blocking** scan-step, `view_sk` never crosses | DQ6; cadence injectable (no hardwired tick) |
| **SP-6** | The reconcile **interface** reader (b) hands to 2d-2 — matches **plus a `VerifiedRange` `covered`** (absence ≠ unscanned) | the GC *action* is 2d-2; positive-confirmation only |
| **SP-7** | The **funding-side completeness gate** — a typed `CoverDiscovery` so cold-start re-fund is gated on header-root-verified absence, never on a withheld block | closes `TM-3`; root-anchored cursor; surface, don't auto-re-fund |

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
  the 2d-2 boundary — and carrying a `VerifiedRange` `covered`, so an *absence* can only be
  concluded where coverage was affirmatively proven; GC-from-an-unscanned-gap is
  unrepresentable (SP-6, DQ8).

The throughline: each load-bearing *don't* in §2 becomes a *can't* in the types. Round 1
designs these alongside the per-SP work, not as a cleanup pass after.

---

## 5. Dependency posture (why this is the keystone, and parallelizable)

- **North-Star-independent *at runtime*, but the *build* waits for PR #193 to land.** 2d-1 is
  read-side; it never broadcasts, so it does **not** depend on the daemon-accept gate
  (`e2e_fcmp_spend_accepted_by_daemon`) *functionally* — which is why the **design** could and
  did proceed in parallel. The **implementation**, however, branches off `dev` only **after
  PR #193 lands** (the north-star: "first daemon-accepted FCMP++ spend"). PR #193's own scope
  unblocks 2d (a bond-post *is* an FCMP++ spend) and reworks the **engine / prover / scanner**
  surfaces SP-0..SP-7 sit on (witness `x = ho + b`, the per-`(tx_hash, output_index)` bundle
  cache, strict vin sorting, the refresh-scan path). Branching 2d-1 before it lands would force
  a rebase across exactly those consensus-alignment changes — so the SP-0 build starts from a
  PR #193-landed, north-star-green `dev`, not before. (Logical independence ≠ build-base
  independence.)
- **Consumers hang off it — and they do *not* share a completeness profile.** Three are
  **lag-tolerant**: 2d-2's reconcile (SP-3/SP-6), steady-state fund-from-earnings (SP-1/SP-4),
  and the cover's `C_min` sizing (SP-4). The cover design is otherwise complete (PR #192) —
  `C_min` is its one unset magnitude, unset *because* SP-4 does not exist yet.
- **A fourth consumer is *not* lag-tolerant: cover-output *discovery* (the cold-start gate).**
  Before `P` can ever stake, it must **scan-discover its own `bond_floor + cover` output**,
  finality-deep — a hard *must-discover-before-proceeding*, not a "delays a re-stake" like
  reader (a). The failure case the lag framing hides: if the funding scan **misses** the cover
  output, `P` is stranded at cold-start with funds it cannot see, and the only recovery is
  re-funding from the principal — **a second cold-start link, the exact correlation the cover
  exists to prevent.** Missing a steady-state output delays a re-stake; missing the *cover*
  output forces a re-link. So cover-discovery owns its own completeness assertion, separate from
  reader (a)'s lag-tolerance, composing with the `archival_reorg_depth_blocks` latency (DQ2 c2).
  **The output *form* is verified-covered (source check):** the recovery path
  (`scan_output_recover_with_ml_kem_dk`, `scan.rs:626–648`) has **no form-specific carve-out**
  (no output-type / amount-encoding / coinbase branch), and the FA-6 view-tag pre-filter is
  **false-negative-free for owned outputs** — the tag comes from the *single* function
  `derive_view_tag_prefilter(ml_kem_ss, output_index)` (`crypto-pq/src/derivation.rs:263`)
  called identically by the **sender** (`output.rs:278`) and the **scanner** (`output.rs:509`)
  over the same recipient-recomputable shared secret, so it cannot reject an owned output.
  A non-colliding cover output is therefore *guaranteed* discovered regardless of form —
  **modulo the one residual: a negligible (~2⁻¹⁶⁴, ML-KEM-768) decapsulation failure** that
  would recover a different shared secret and miss the tag. Cryptographically irrelevant as a
  probability, but named, not rounded to zero, because *this* output's miss forces a re-link.
  The other residuals are the **non-form** ones (transport gap / pruned source / **withheld
  block** — handled by **SP-7's funding-side completeness gate**, *not* SP-6, which is the
  reconcile reader) and **variant mis-selection** (already type-pinned by SP-1's
  `GuaranteedViewPair`-only). One correction on the fresh-key point: `Guaranteed` *drops* a
  colliding `output.key`, so the cover output needs a fresh one-time key — and the sender that
  generates it is the **principal**, not `P` (`ARCHIVAL_COVER_DRAW.md:53,99`: "principal sends
  `bond_floor + cover` to `P`"). Freshness rides the principal wallet's random tx-key (honest
  stealth construction), so the guarantee holds — but it rests on the *principal's* correctness,
  a **different firewall controller** than `P`; naming that precisely is the firewall's whole
  point (`P` ≠ principal).

---

## 6. Round 1 — per-SP design (enforcement-point-with-the-type)

The Round 0 boundary (above) is drawn at keys / state / fetch / execution. Round 1 derives
the per-SP design from it, and for every typed surface **pins the enforcement point *with*
the type shape** — because §4's "structural *don't* → *can't*" degrades back to "don't" at
the two places it's actually tested: the **kameo actor boundary** (message fields are
constructed by the sender, `Send + 'static`, moved/serialized) and the **seal**
(serialization round-trips a type through bytes and reconstitutes it from disk). A type's
guarantee is only as strong as the privacy of its constructor and the checks on its load
path. So each surface below names *where the invariant is enforced*, not just its shape.

---

### SP-0 — `BlockSource`: the no-selective-fetch property *is the trait's shape*

The fetch-layer isolation (Round 0 DQ1, the Monero light-wallet lesson) is enforced by
**capability absence**: the trait can ask for a block by height or the next block, and has
**no method that could express a selective/filtered request**. A wallet-server-style query
is then uncallable — uncompilable — not a documented convention.

```rust
/// Per-`P`, fetch-everything block source. 2d-1 ships a local impl; 2d-2's Arti
/// transport implements the SAME trait (the interface is pinned now, the transport
/// is 2d-2). There is deliberately NO `outputs_matching` / filtered-fetch method:
/// the selective-request leak is absent from the surface, so it cannot occur.
pub trait BlockSource {
    /// This source's *claimed* tip — NOT a trusted-current one. A single source can
    /// truncate it for free (SP-7 stale-tip residual); trusted-currency is a 2d-2
    /// multi-source / out-of-band-sanity property, not a single source's word.
    fn tip_height(&self) -> Result<u64, BlockSourceError>;
    fn block_at(&self, height: u64) -> Result<Option<ScannableBlock>, BlockSourceError>;
}
```

**Enforcement point:** the trait *surface*. Adding a selective method is the only way to
reintroduce the leak, and that is a visible, reviewable API change — not an accident a
caller can make. (Same bar as the `PersonaHandle` `!Clone` seal: the bad state has no
representation.)

---

### SP-1 / SP-1a — the extractor: `Guaranteed`-only construction + the CT seam

**SP-1 (variant):** the `P`-scan constructs its scanner **only** from a `GuaranteedViewPair`
(burning-bug-immune, Round 0 DQ7) — the plain `ViewPair` is not in the `P`-scan's type
surface, so the vulnerable variant is *unselectable*.

**SP-1a (the seam):** the per-output ownership test sits behind a trait so the constant-time
decision (DQ1, third option) is an **impl swap, not a re-architecture**:

```rust
/// The per-output ownership test. The seam that makes constant-time a swap.
pub trait OutputExtractor {
    fn test(&self, out: &ScannableOutput) -> Option<OwnedOutput>;
}

/// DEFAULT (ships now): reuses the FA-6 early-exit (`GuaranteedScanner`) — fast.
/// The final ownership compare is constant-time NOW (cheap, correct regardless):
/// `recovered_spend.ct_eq(&self.primary_spend)` (subtle), replacing the plain `!=`.
pub struct FaFastExtractor { /* GuaranteedViewPair-backed */ }

/// DEFERRED (rule-21 reopen): runs the full per-output path on EVERY output (no
/// early exit) — closes the pre-filter timing channel at the all-wallet perf cost.
/// Satisfies the SAME trait — a one-line swap, no caller change.
// pub struct CtNoEarlyExitExtractor { ... }   // not built until a co-tenancy target reopens
```

**Enforcement point:** two. (a) `GuaranteedViewPair` is the only type the `P`-scan's
constructor accepts — variant choice by construction. (b) The CT *compare* is unconditional
(no argument for a variable-time `!=` on a secret bit); the CT *everything* impl is gated
behind the trait, so the deferral is a swap, and the architecture (the thing expensive to
retrofit) is pinned today.

**Build status (refines the seam decision):** SP-1 (the `GuaranteedViewPair`-only adapter)
landed in PR #195 and the **CT compare** in PR #194 (`subtle::ct_eq` in the shared scanner).
The **`OutputExtractor` seam itself is deferred *with* the CT-everything impl it exists to
enable** (rule-21) — not built now. Reasoning: the seam is a refactor of the *shared*
scanner's per-output path whose only purpose is to make a **rule-21-deferred** swap cheap;
building it now is pre-provisioning flexibility for a maybe-never trigger, which
[`21-reversion-clause-discipline`](../../.cursor/rules/21-reversion-clause-discipline.mdc)
and [`70-modular-consensus`](../../.cursor/rules/70-modular-consensus.mdc) (no speculative
scaffolding) say to avoid. When a co-tenancy target reopens the CT-everything tax, the seam
and its impl land together — the re-architecture cost is real but paid against a real target,
not pre-paid. The CT compare (the correct-now half) did *not* wait on the seam.

---

### SP-2 — `PScanCursor`: single authoritative frontier, resume-and-recompute (crash-recovery **Design B**, decided jointly with SP-4)

A distinct newtype stops accidental reuse of the principal's `BlockchainTip` (the compiler
rejects passing one for the other — DQ4 cross-contamination caught by `cargo`, not review).
That part is type-carried. The crash-recovery *behaviour*, though, is the real decision, and
**it cannot be specified separately from SP-4's accrual** — they are two halves of one design.

**Why the earlier "monotone-forward clamp" was wrong.** A `synced_height.max(known_frontier)`
clamp *advances* the cursor and **scans from there, skipping `[synced_height, known_frontier)`** —
safe only if `known_frontier` means "already durably scanned to here." But the
`monotone_current_slot` precedent (`staking_block.rs:166`) **does not transfer**: the slot's
floor (`highest_bonded_slot_seen`) is **chain-derived** — the bonded set independently anchors
"this persona has a bond, never reuse it." The scan cursor has **no chain-derived
already-scanned anchor** — scan progress is private to `P` and recorded *only* by the cursor.
So `known_frontier` had no safe source short of a *second* durable progress record, which just
raises "why isn't the seal authoritative, and what's the commit ordering between the two?"

**Two coherent designs; we take B.** *Design A (clamp/skip):* commit scan results durably to
height H **before** advancing the cursor, set `known_frontier = H`; the clamp then correctly
skips the already-committed range — but you owe a second durable frontier, a pinned
results-before-cursor commit ordering, and a defined recovery if the results commit is itself
interrupted. *Design B (resume/idempotent):* the cursor is the **single** authoritative scan
frontier; on resume, re-scan from the sealed `synced_height` forward to
`tip − archival_reorg_depth_blocks` (`= 720`, `config/consensus_constants.json:23`), and make
the accrual idempotent (SP-4) so the re-scan is harmless. **We take B** — one frontier with no
cross-record ordering beats A's two-frontier atomicity protocol (which grows its own
crash-window bugs), and on a read-side scan the redundant post-crash re-scan is cheap.

```rust
/// `P`'s scan cursor — distinct from `BlockchainTip`. Sealed StakingBlock-class
/// (postcard + AEAD + atomic_write_file + version). THE single scan-progress record.
pub struct PScanCursor {
    version: u32,                 // rejected (not migrated) on mismatch — StakingBlock precedent
    synced_height: BlockHeight,   // the one authoritative durable scan frontier
    frontier_hash: [u8; 32],      // AS BUILT (v2): recomputed hash of block[synced_height-1],
                                  // [0;32] at genesis — the verified-frontier anchor the next
                                  // batch must chain to (see "Exhaustiveness, as built" below)
}

impl PScanCursor {
    /// LOAD just verifies + decodes — NO forward clamp, NO `known_frontier` (Design B:
    /// nothing safe to clamp to). AEAD integrity + version-reject; the value is trusted
    /// as a resume point. A stale-low seal merely re-scans more (harmless under SP-4
    /// idempotency); a too-high seal is impossible because of the write discipline below.
    pub fn from_sealed(bytes: &[u8]) -> Result<Self, CursorError> {
        decode_versioned(bytes)
    }
}
```

**Enforcement point — a *write* discipline, not a load clamp.** Persist the confirmed
owned-output set durably, **then** seal the cursor to that frontier: the cursor **never seals
past durable outputs** (never over-claims), so a crash can only leave it *at or behind* real
progress, and resume re-scans the gap. The newtype stops cross-use at compile time; *integrity*
is AEAD + version; *safety* is seal-after-durable-outputs + SP-4 idempotency. There is no
load-time invariant to get wrong because there is no clamp.

**Completeness is *root-anchored*, not source-delivered (SP-7 / `TM-3`).** The cursor advances
only over a range `P` has confirmed complete against the **header chain** (`prev`-chained) — so a
block a withholding source silently omits is *detectable* (a continuity break or a body that does
not match its committed hash), and both readers' "absent" conclusions mean *provably absent*, not
*undelivered*. This is what makes SP-6's `covered` and SP-7's `AbsentVerified` trustworthy against
a C3 source. *(Refined by the trust-anchor resolution + "Exhaustiveness, as built" below: the
2d-1 check is recompute-and-chain continuity + per-body tx-hash — **exhaustiveness**, no wallet
PoW; canonicity and full withheld-body/tip robustness are posture/2d-2.)*

---

### SP-4 — `PFundingInflow`: confirmed-only + output-only + **idempotent recompute** (Design B's other half)

The `C_min`-feeding inflow (DQ3) carries its unit *and* its provenance invariant. Two things
must hold: the actor-boundary trap (a hand-built inflow injected as a message field), and —
because we took Design B in SP-2 — **idempotency**, so a post-crash re-scan recomputes the
same value rather than double-counting.

**Idempotency (the Design-B obligation):** the per-epoch inflow is **recomputed once from the
epoch's *complete* confirmed-output set** — a pure fold over that set — **not accumulated
across scan passes**. Re-scanning a range therefore changes nothing: the constructor is called
per epoch when the epoch is finality-sealed, over all of that epoch's confirmed outputs, and is
a deterministic function of them. (The companion `PReconcileSet`, SP-6, is likewise recomputed,
and 2d-2's GC must be idempotent — re-handing the same matched posts is a no-op.)

**"Confirmed" is two different predicates — disambiguate them, because only one is
type-guarded.** `ConfirmedOutput` means **ownership-confirmed** (DQ7: passed the full
ownership test, *not* an FA-6 pre-filter hit) — and the type carries that, built only by the
extractor's confirmed path. But `C_min` also needs **finality-confirmed** (DQ2: reorg-deep,
behind `tip − archival_reorg_depth_blocks`), and **nothing in the type enforces that.**
Finality is *contextual* — a function of the current tip, not intrinsic to an output — so it
cannot be a purely intrinsic type guard; it rides entirely on the extractor running behind the
cursor's finality horizon. **So `PFundingInflow`'s finality soundness is exactly as strong as
SP-2's cursor discipline** — finality-confirmedness has **no type guard; it is a cursor
invariant.** Fixing SP-2 (seal-behind-the-horizon) *is* what makes SP-4 finality-sound. The
constructor guards provenance + ownership; the cursor guards finality, and only the cursor.

```rust
/// Per-epoch `P` funding inflow — the signal `C_min` sizing consumes. Private
/// fields; NO `pub` constructor, NO `From<raw>`. Constructible ONLY inside the
/// extractor module, ONLY from OWNERSHIP-confirmed outputs (DQ7: passed the full
/// ownership test, never FA-6 pre-filter hits). FINALITY-confirmedness (DQ2) is
/// NOT in this type — it is the SP-2 cursor invariant (scan only behind the horizon).
/// Money is `AtomicUnits`, epoch is the sweep's settlement-epoch type (Alignment §).
pub struct PFundingInflow {
    settlement_epoch: SettlementEpoch,   // sweep home-crate type, not raw u64
    atomic: AtomicUnits,                 // EXISTING newtype — checked, unit-marked
}

impl PFundingInflow {
    /// `pub(in crate::pscan::extractor)`. IDEMPOTENT: `epoch_outs` is the epoch's
    /// COMPLETE ownership-confirmed set; this recomputes (does not accumulate), so a
    /// post-crash re-scan yields the same value. Called once per finality-sealed epoch.
    pub(in crate::pscan::extractor) fn recompute_for_epoch(epoch: SettlementEpoch, epoch_outs: &[ConfirmedOutput]) -> Self { /* checked sum into AtomicUnits */ }
    pub fn epoch(&self) -> SettlementEpoch { self.settlement_epoch }
    pub fn atomic(&self) -> AtomicUnits { self.atomic }
}
```

**Enforcement point:** (a) **constructor privacy** — `pub(in extractor)`, so no foreign
module builds one (ownership/provenance); (b) **direction across the seam** — output only (a
handler `Reply`, pulled toward `C_min`), **never an inbound message field**, so no caller can
send a message *carrying* a hand-built inflow into sizing (the user's pick: message carries the
already-validated type, built only inside the extractor — never raw-validated-on-receipt); and
(c) **finality has no type guard** — it is the SP-2 cursor invariant, so (a)/(b) secure
provenance and ownership while *finality* is secured upstream by seal-behind-the-horizon.

---

### SP-3 / SP-5 — the dual extractor, run inside the actor, offloaded and bounded

**SP-3 (dual extractor, DQ2):** one block-iteration, two extractors over the same decoded
block — the view-key **funding** extractor (`OutputExtractor`, secret) and the **public
bond-post** match (`p_canonical_id` cleartext, no secret). The cursor advances at
**reconcile-grade finality** (the stricter reader sets the discipline; funding rides free).

**SP-5 (where it runs, DQ6):** the `P`-scan **task** owns the cursor, cadence, and
`BlockSource`; the **actor** is the `view_sk` vault and *performs* the per-batch scan-step.
`view_sk` never crosses the actor boundary — only **public** results come back.

**Cadence is an injectable, not a hardwired tick (don't foreclose the third fetch-layer
leak).** SP-0 closed output-*selectivity* and the forward-note closes fetch-*order*; the
third fetch-layer side channel is *when and how often* `P` scans. A task that wakes on a
fixed wall-clock tick, on wallet-open, or bursts right after a bond it cares about lands has
a **timing signature on the wire** (under Arti: the connection's existence and request
rhythm) that correlates with `P`'s lifecycle even though no single request is selective —
the pattern-deanonymization lesson Lightning and Monero both learned. Fixing it is 2d-2's
job (it's network-observable), but **not foreclosing it is 2d-1's:** SP-5 must take its
cadence as an **injected schedule** (a `ScanSchedule`/clock trait), so 2d-2 can later make it
constant-rate or jittered — it must **not** bake a `tokio::time::interval` or a scan-on-open
trigger into the task. Cheap now; a retrofit once the task hardcodes its own timer.

```rust
/// Public input — heights only. No secrets, and (SP-4) NO `PFundingInflow` inbound.
struct ScanStep { range: BlockRange }    // BOUNDED per message (DQ6)

impl Message<ScanStep> for StakeEngine {
    type Reply = Result<ScanStepResult, StakeEngineError>;  // PUBLIC outputs + confirmed inflow
    async fn handle(&mut self, msg: ScanStep, _ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        // Clone the bonded-union GuaranteedViewPairs (transient secret copies, DQ5),
        // then OFFLOAD the CPU+secret work to spawn_blocking — the secret lives only
        // in the closure and is dropped at its end; it never reaches the task.
        let vps = self.clone_bonded_union_guaranteed_vps();
        let blocks = fetch(msg.range)?;   // from the injected BlockSource
        let res = tokio::task::spawn_blocking(move || run_dual_extractor(vps, blocks)).await??;
        Ok(res)   // owned outputs (public) + bond-post matches (public) + PFundingInflow
    }
}
```

**The bounded-AND-offloaded point (DQ6, the subtle one):** kameo handlers are
`async fn handle(&mut self, …)` and hold `&mut self` across the `await`, so `spawn_blocking`
moves the CPU off the runtime thread but the **actor still cannot process another message
until `handle` returns**. So `range` must be **bounded**: the task loops, sending small
`ScanStep`s, and the actor interleaves rotation/sign/activate *between* batches. Bounded
batch and offload together; neither alone is enough.

**Block-granularity is adequate — no mid-block-resumable cursor needed.** A single block's
work is **consensus-bounded**: outputs-per-tx are capped at `BULLETPROOF_PLUS_MAX_OUTPUTS = 16`
(`src/cryptonote_config.h:241`), the decode path independently gates on
`shekyl_scanner::MAX_OUTPUTS` (`engine-core/.../curve_tree_decode.rs:109`), and txs-per-block
is bounded by the cumulative block-weight limit. So a small `BlockRange` carries bounded work
and `synced_height` (block-granular) is a sufficient resume point. **Tuning note (not
architecture):** size the `range` bound against the **worst-case (max-weight) block**, not the
average — a maximally-stuffed range must still return fast enough not to starve a pending
rotation/sign between batches.

**Enforcement point:** the secret stays inside the `spawn_blocking` closure (cloned from
`self.held`, dropped at closure end); `ScanStepResult` carries only public outputs +
`PFundingInflow` (built inside `run_dual_extractor`'s confirmed path). The actor returns
data, never keys — consistent with `PersonaIdentity` being public-only.

**Build status (split into two PRs by validation surface):** **PR-A landed in PR #201** —
SP-3's `run_dual_extractor` (`engine/pscan/scan_step.rs`) and the SP-5 **actor half**
(`Message<ScanStep> for StakeEngine`, offloaded to `spawn_blocking`; `view_sk` never crosses,
DQ5/DQ6). Two refinements over the sketch above, with their rationale:

- **The `ScanStep` message carries the already-fetched blocks, not heights-only.** The *task*
  owns the `BlockSource` and fetches (this section, above); carrying public blocks keeps network
  I/O out of the single-threaded actor mailbox (the DQ6 anti-blocking concern) without weakening
  SP-4's anti-injection rule (the message carries blocks, never a `PFundingInflow`).
- **A scan-step returns per-epoch *deltas*, not a finalized `PFundingInflow`.** A step is a
  *partial* epoch (`SETTLEMENT_EPOCH_BLOCKS = 10 000` blocks ≫ a bounded step), so it cannot
  satisfy SP-4's "recompute over the epoch's *complete* confirmed set." `run_dual_extractor`
  therefore emits `EpochInflowDelta`s; **PR-B** accumulates them across steps and finalizes
  `PFundingInflow` at epoch-close. (This *corrects* the enforcement-point line above, which had
  the step return a finished `PFundingInflow`.)

  PR-A also enforces DQ6's "bounded per message" as an invariant (`MAX_SCAN_STEP_BLOCKS`
  fail-closed backstop), not a contract.

**PR-B (remaining SP-5):** the driving P-scan **task** + injectable cadence (`ScanSchedule`);
the **new sealed P-isolated cursor/inflow persistence** (the write-discipline: persist outputs
→ seal cursor; rule-42 schema + version const — the genesis-freeze-sensitive surface that
motivated the split); `PFundingInflow` finalization at epoch-close; `Engine::start_pscan`
wiring; and the DQ8 retirement/union-shrink reading consensus `W`. `block_source` and `inflow`
keep their transient `#[allow(dead_code)]` until that task wires them.

---

### SP-6 — `PReconcileSet`: typed, distinct, *and* carries the range it can vouch for (absence ≠ unscanned)

The dangerous failure here is **availability masquerading as truth**. SP-6 feeds 2d-2's GC of
phantom `bonded_slots`. If `P`'s isolated transport is down, censored, or the daemon serves a
truthful-but-**stale** or selectively-**pruned** view, the reconcile sees *fewer* bond-posts
than exist — and a GC that reasons "I didn't find this bond, so it's phantom" then
**garbage-collects *real* collateral** on a transport outage. The finality horizon defends
against reorgs, **not** against an adversarially-incomplete source. Monero and Zcash both treat
"my view of the chain may be incomplete" as a first-class scanner assumption; an archival
staker behind an isolated, censorship-prone transport is *more* exposed, not less.

So `PReconcileSet` must carry **not just the matches but the range `P` can affirmatively vouch
it completely scanned, from a source verified against the consensus root** — and the GC
(2d-2) must be a **positive** operation: GC only a slot it *affirmatively confirmed absent over
a range it provably covered*, **never** inferred from absence. A missing bond-post must be
**distinguishable from an unscanned one** — the "absence of a claim is not a claim of absence"
rule, aimed at the reconcile. The type makes the distinction unrepresentable to lose:

```rust
/// A height range `P` AFFIRMATIVELY, EXHAUSTIVELY scanned on the chain it was served
/// (recompute-and-chain `prev` continuity + per-body tx-hash — AS BUILT; the
/// `curve_tree_root` match lives in the decode/*matches* half, not here) —
/// constructible only by the verified scan path, never by hand. Claims *exhaustiveness*,
/// NOT *canonicity*: that `[low, high]` is the most-work chain is a separate token the
/// 2d-2 GC requires alongside this (see the trust-anchor resolution — most-work needs
/// competitors a single source cannot supply, so there is no wallet-side PoW here).
pub struct VerifiedRange { low: BlockHeight, high: BlockHeight }

/// The reconcile input `P` hands 2d-2. DISTINCT from the funding `OwnedOutput` set, and
/// it carries its own coverage: matches are claims of PRESENCE; `covered` bounds where an
/// *absence* may be concluded. 2d-2 may GC a slot ONLY if its height ∈ `covered` and no
/// matched post claims it — outside `covered`, absence means "unscanned," not "phantom."
pub struct PReconcileSet {
    covered: VerifiedRange,
    matched_posts: Vec<MatchedBondPost>,
}
```

**Enforcement point:** (a) the type distinction — `PReconcileSet` ≠ funding set, so the two
readers' outputs can't be conflated; and (b) **coverage is carried, not assumed** — `covered`
is constructible only by the verified scan path, and the GC contract keys "confirmed-absent"
on `height ∈ covered`, so *GC-from-an-unscanned-gap is unrepresentable*. This is the most
likely place 2d-1's design, as scoped, would otherwise lead to a real downstream bug; the
positive-confirmation GC *action* is 2d-2, but the type that forces it is pinned here. (DQ8's
persona-retirement is the same rule on the lifecycle side — never retire on absence.)

### SP-7 — the funding-side completeness gate: never re-fund on absence (closes `TM-3`)

SP-6 gave reader (b) a `covered` range so the *reconcile* never GCs on absence. Reader (a) —
**cold-start cover-discovery** — needs the **same defense, and didn't have it**: DQ2 had the
funding reader "ride the cursor for free," but the cursor's completeness is **source-delivered**
("I scanned every block the source handed me"), which a **withholding C3 source defeats** — it
serves every block *except* the one carrying `P`'s cover output. The scan looks complete, `P`
concludes its funding never arrived, and `P` **re-funds from the principal** — a *second*
cold-start event on the attacker's infrastructure, correlated with the first. The attacker
**induces** the exact re-link the cover exists to prevent, by controlling availability rather
than breaking crypto (`ARCHIVAL_FIREWALL_THREATS.md` A2/`TM-3`).

**The defense is header-root-verified completeness, and a gate on the re-fund decision.**
Block headers chain (`prev[32]`, `shekyl-wire/src/block.rs:12`) and commit PoW
(`cumulative_difficulty`, `shekyl-consensus`), so `P` can verify it holds **every block body
the header chain says exists** up to a finality-deep `H` — a **withheld body is detectable**
(the header is present, the body is missing), which makes "missing" *distinguishable from
unscanned* on the funding side too. So:

- **The shared cursor's completeness is *root-anchored*, not source-delivered** (strengthens
  SP-2/DQ2): the cursor only advances over a range `P` has confirmed complete against the
  header chain. Both readers then inherit withholding-resistance — SP-6's `covered` and SP-7's
  absent-verdict both derive from the *same* root-anchored coverage.
- **The cold-start re-fund decision is gated, and the gate is a type:**

```rust
/// The cover-discovery verdict. A re-fund may be considered ONLY from `AbsentVerified`
/// (cover provably absent within a header-root-complete, finality-deep range) — never
/// from `Incomplete` (a gap the source may simply be withholding). "Re-fund on a gap"
/// is unrepresentable: the re-fund path does not accept `Incomplete`.
pub enum CoverDiscovery {
    Found(OwnedOutput),
    AbsentVerified(VerifiedRange),   // header-root-complete AND finality-deep, cover absent
    Incomplete,                      // view not yet provably complete — WAIT, never re-fund
}
```

- **Even `AbsentVerified` does not *auto*-re-fund.** A header-root-complete view with the
  expected cover absent means the **original funding tx never confirmed** — so the safe action
  is **surface to the operator / retry-broadcast the original**, not silently mint a second
  cold-start link. Auto-re-fund is precisely the induced-relink `TM-3` describes; the gate
  routes `AbsentVerified` to an operator-visible decision, not a reflex.

**The residual SP-7 does *not* close on its own — the stale-tip (verified single-source today).**
`AbsentVerified` is "complete up to the **tip**" — but `BlockSource::tip_height()` is *one
source's word*, and the engine is **single-`DaemonClient`** today (`lifecycle.rs:423`;
`anchor_target(scan_start_floor, daemon_height)` trusts the reported `daemon_height`). A C3
daemon can withhold the **tip** (serve a truthful-but-stale chain ending *below* the cover's
block) for free — `forging` a header chain is PoW-expensive, but *truncating* it is not. The
good news: this does **not** flip the type to a false re-fund — the cover's height is then
*above* P's believed tip, so the verdict is `Incomplete` (wait), not `AbsentVerified`. The
relink re-opens only through a **liveness shortcut**: if anything escalates a *prolonged*
`Incomplete` into a re-fund ("waited long enough, must have failed"). So two pins:

- **Hard rule (2d-1):** prolonged `Incomplete` **never** auto-escalates to re-fund — it
  **surfaces** ("your funding source may be stale or withholding"). Only `AbsentVerified` is a
  re-fund input, and there is no timeout path that manufactures one. This keeps the relink
  closed even under an indefinite stall.
- **Tip-currency is a 2d-2 property, named here.** `AbsentVerified` is only as honest as P's
  reason to believe its tip is *current*, which a single daemon cannot supply. That needs
  **multiple `P`-isolated sources** cross-checking the tip (or an out-of-band difficulty/
  timestamp progression sanity-check). This does **not** violate DQ1: per-`P` isolation is
  about not sharing a source with the **principal**, not about using one source — the
  cross-check is *among `P`'s own* isolated sources. Routed to 2d-2's transport (the
  `BlockSource` impl), with SP-0's `tip_height()` documented as "*this source's claimed tip*,"
  not a trusted-current one.

**Enforcement point:** the `CoverDiscovery` type — the re-fund path takes `AbsentVerified`
only, so "re-fund because I haven't seen it yet" cannot be written; the root-anchored cursor
makes `AbsentVerified` mean *provably absent below the tip*, not *undelivered*; and the
no-timeout-escalation rule plus the 2d-2 multi-source tip close the stale-tip path. This is the
funding-side twin of SP-6, **buildable in this round** (the type + the no-escalation rule),
with the tip-currency half explicitly a 2d-2 obligation.

---

### Trust-anchor resolution (design round, 2026-06-29): exhaustiveness vs canonicity vs tip-honesty — **no wallet-side PoW**

The "root-anchored completeness" of SP-2/SP-6/SP-7 was one word over **three** distinct
properties; naming them resolves the SP-2 (`:909` build-order) vs SP-7 (`:925` TM-3 row) vs
`block_source.rs` three-way pointing, and fixes each property's home:

1. **Exhaustiveness** — "I scanned *every* block in `[A,B]` on the chain I was served." Cheap,
   local, single-source. **As built** (`verify_exhaustive`): **recompute-and-chain `header.previous`
   continuity** — each block's `previous` is checked against the hash *recomputed from received
   material* (`Block::hash` rebuilds the tx-tree from the inline miner body + the received
   `transaction_hashes`), so a held tx set that is not the committed one is caught, not just a
   consistent link — **plus per-body tx-hash** (`transactions[i].hash() == transaction_hashes[i]`,
   the miner body covered inline). The `curve_tree_root` match was **re-homed to the decode/*matches*
   half**, where it belongs; exhaustiveness does not need it. The cursor advances **only** over the
   contiguous verified range, and a gap, continuity break, or missing/tampered body is a verification
   **`Err`**, never a silent skip or a fabricated `None`. **This is the whole of the 2d-1
   completeness unit.**
2. **Canonicity** — "`[A,B]` is the *most-work* chain, not a fork." Most-work is a comparison
   against competitors a single source **structurally cannot provide**: a mined valid-PoW
   *minority* fork passes a valid-PoW check identically to the real chain, and the wire header
   carries **no `cumulative_difficulty`**, so the wallet can neither sum work nor see the
   competing chain. Canonicity therefore comes from **trusting the node** (posture ①/② — the
   node already ran most-work selection) or **multiple `P`-isolated sources** (posture ③ — 2d-2
   transport). It is **not** standalone and never was.
3. **Tip-honesty** — "nothing is withheld *above* my frontier" — already homed in 2d-2 (SP-7's
   stale-tip residual, multi-source tip-currency).

**Disposition — no RandomX in the wallet (`21-reversion-clause-discipline`).** Re-deriving PoW
in the wallet is **dominated in every posture**: redundant where the node is trusted (it
already validated PoW + most-work), **insufficient** where it isn't (it cannot reject a mined
valid-PoW *minority* fork without a second source — the patient C3 the threat model assumes),
and a 256 MiB RandomX dependency either way. It catches only an *invalid*-PoW fork, which
multi-source also catches — so it adds no capability the posture/transport doesn't already
give, while failing the standalone canonicity it reaches for. **Reopen** only if a header ever
gains an in-band cumulative-work field **and** single-source most-work proof becomes possible —
neither exists today.

**`VerifiedRange` = exhaustiveness only.** Refines the SP-6 type: `covered` claims
*"exhaustively scanned `[A,B]` on the chain served,"* **not** "on the canonical chain." The
permanent GC (2d-2) consumes `VerifiedRange` **plus a canonicity token** (a trusted-posture
marker or a multi-source proof); its signature makes **"GC on exhaustive-but-uncanonical
evidence" unrepresentable** — the same shape as "absence ≠ unscanned." That type-level handoff
keeps the 2d-1/2d-2 split from leaking at the seam.

**Scope-limiter — canonicity strength only where the consequence is permanent.** Only the
irreversible `bonded_slots` GC needs canonicity at this strength. The **funding view** inherits
the existing daemon-trust model (a fork there yields a *recoverable* wrong balance, exactly as
the principal's refresh does today) — we gate the permanent removal on canonicity, and nothing
else.

**`creation_anchor_hash` / release checkpoint = trust floor, not a PoW anchor** (there is no
wallet PoW to anchor): below it, trusted; above it, exhaustiveness-verified by 2d-1 and
canonicity-confirmed by posture/transport at the GC.

**Build-order consequence.** The heavy "root-anchored completeness prereq" dissolves: the 2d-1
piece is the light exhaustiveness primitive (recompute-and-chain continuity + per-body tx-hash),
small enough to land **inside the SP-6 area**, with **no PoW prerequisite PR**. *As built,* the
primitive (`exhaustiveness.rs`) + its sweep wiring landed first (see "Exhaustiveness, as built"
below); `PReconcileSet` is the remaining SP-6 piece, built on the daemon-trusted, continuity-checked
`covered`. (Impl-PR carry — **done:** `block_source.rs`'s `block_at` comment now frames withheld-body
detection as a 2d-2 transport property, not "SP-7's root-anchored job"; exhaustiveness is 2d-1, and
withheld-body / fork / tip robustness is 2d-2 transport.)

### Records-driven retirement: the authoritative done-side slot ledger (design round, 2026-06-29)

The retire's last absence-inference dissolves once the wallet keeps an **authoritative
done-side record**. Today's hazard is the GC reasoning "persona done" from *not seeing*
activity on a chain a source could forge — absence-driven, the reason canonicity arose. But
retirement is **presence-and-own-records-driven**: the wallet *bonded* slot N (its own recorded
action), *observed* the `Unbond` (presence, not absence), and the claim window *expired* (a
clock, not a chain-absence). Driving retirement from that record **removes** the
absence-inference failure mode — it doesn't recover from a wrong GC, it stops the GC from
guessing. **Canonicity shrinks to corroboration:** `covered` confirms the presence-events the
ledger expects; it is no longer the trigger.

**The live/done line — the load-bearing reconciliation with the frozen `bonded_slots`
decision.** `staking_block.rs:47-63` deliberately makes `bonded_slots` a **hint, not truth**:
an authoritative *live*-bond record goes stale and "would derive that slot forever, every open,
for nothing" (`:53-54`), so "no aggregator invariant treats `bonded_slots` as truth — adding
one would contradict" (`:62`). The done-side ledger does **not** reopen that — it is the *other*
half of the lifecycle. The frozen objection was the *absence of retirement status*; an
authoritative **retired**-record supplies exactly that: the thing that says "**stop deriving
slot N**," the fix the forever-derive problem was waiting for. **Authoritative-for-done
completes hint-for-live; opposite ends of one lifecycle, never in conflict.** It is not new
architecture — it is the formalization of `pending_unbonds` (PR-B) + SP-6's durable removal into
**one coherent done-side ledger**, retirement records-driven rather than re-inferred from
absence each open.

**Placement makes the line a *physical file boundary*, not just a sentence.** The done-side
ledger (retired-records + the high-water mark) rides in **`PScanState` (`.wallet.pscan`)** with
`pending_unbonds` — its done-side sibling — while the **live** `bonded_slots`/`p_slot` stay in
`StakingBlock` (`.wallet`, hint). So `StakingBlock`/`.wallet` = live = hint and
`PScanState`/`.wallet.pscan` = done = authoritative: the split is enforced by the file boundary,
which is what keeps the next reader from collapsing "authoritative for done" into "authoritative
for live." Both region-2-sealed (slot indices are "public" only in the *not-a-zeroize-key* sense
of `staking_block.rs:87` — sealed either way; the done ledger is derivable-but-worth-persisting,
P-isolated for the same firewall discipline as `pending_unbonds`).

**Mechanism.** `spawn_stake_engine_if_staker` (derives `bonded_slots ∪ lookahead` from
`StakingBlock` at open) must also read the `PScanState` retired-record and **subtract** retired
slots — that is how "stop deriving N" takes effect. A cross-file read, but both files are
available at open; it is the cost of the P-isolated done-side, and the records-driven
replacement for absence-driven GC of the live hint.

**Crisp caution — authoritative about *itself*, not the *chain*.** The ledger makes retirement
safe from the wallet's own records; it does **not** make the wallet authoritative about chain
state. The presence-events it still reads — the `Unbond` observation and the claim-window clock
against the *settled tip* — keep their existing trust model (exhaustiveness/tip-honesty do not
vanish). The ledger removes the *absence-inference*, not the dependence on honest *presence*
data; do not oversell it to "retirement needs no chain."

**No-reuse is already enforced — reference, don't rebuild.** `StakingBlock::monotone_current_slot`
(`staking_block.rs:74-77`): `current = max(persisted p_slot, highest_bonded_slot_seen + 1)`, so
the active slot can never sit at or below a slot with observed activity; rotation is sequential
(`:17`). This is a **restore-safety** invariant ("the cursor never goes backwards") and a
**privacy** one (re-using a retired persona links its activities) — not a collision defense; the
high-water mark catches a reverted/mis-seeded cursor, not a chance clash.

**SP-6 notes invariant (one sentence, so it can't drift):** *the slot ledger is authoritative
for retirement and monotonicity, advisory for live bonds* — encoding the frozen hint-not-truth
(live) and the authoritative-records insight (done) at once.

### Exhaustiveness, as built (2026-06-29): the verified `(height, hash)` frontier

The exhaustiveness primitive + its sweep wiring landed ahead of `PReconcileSet` (commits
`644939ab0` the primitive, `9bd415c16` the wiring). This subsection is the as-built record; where
it refines the design above, it wins.

**The primitive — `verify_exhaustive` (`shekyl-engine-core/.../pscan/exhaustiveness.rs`).** Given a
contiguous batch starting at `first_height` and an `anchor` (the recomputed hash of the block
*before* the batch, or the genesis `previous`), it returns a `VerifiedRange [first, first+n)` or an
`ExhaustivenessError`. Two checks, recompute-from-received not compare-to-claimed:

- **Continuity (the hash list is complete-and-committed):** each block's `header.previous` must
  equal the hash *recomputed* from the predecessor's received material — `Block::hash` rebuilds
  `tx_tree_hash` from the inline miner body + the received `transaction_hashes`, reforms the
  `pow_blob`, and hashes it. Comparing against a *stored* or *source-claimed* hash would verify the
  links but not that the tx set `P` holds is the committed one; recompute proves both. The first
  block checks against `anchor` (→ `AnchorMismatch`), the rest against the running predecessor hash
  (→ `ContinuityBreak`).
- **Per-body (each body matches its committed hash):** `transactions[i].hash() ==
  transaction_hashes[i]`; a count mismatch is `BodyCountMismatch`, a value mismatch `BodyMismatch`.
  The miner tx is covered automatically (inline body, first Merkle leaf in `Block::hash`).

No `curve_tree_root` here — that match is the decode/*matches* half. This is **exhaustiveness**
(no block silently skipped on the chain served), **not canonicity** (most-work), per the
trust-anchor resolution: `VerifiedRange` is constructible only by `verify_exhaustive`, so a value
of that type *is* proof the verified path produced it, and the 2d-2 GC will require a separate
canonicity token alongside it.

**The cursor is now a verified `(height, hash)` frontier.** `PScanCursor` (and its working twin
`PScanAccrual`, and the persisted `PScanState`) carry `frontier_hash` — the recomputed hash of the
last verified block, `[0;32]` at genesis (the anchor block 0 chains to). `synced_height` and
`frontier_hash` advance **together** in `ingest`. This is seam choice **(b)**: the sweep anchors
`verify_exhaustive` on the **stored** `frontier_hash`, never a freshly re-derived one — so the next
batch's first block must chain to *a hash already in our own sealed state*. A height-only cursor
structurally cannot refuse a resume-splice (it cannot say *which* chain's height N), and under
no-wallet-PoW a fabricated fork is free, so the sealed hash is the one thing a forging source
cannot change. (Option (a) — re-derive the anchor from the source on resume — would make
`VerifiedRange` unsound; rejected.)

**`VerifiedRange` and `frontier_hash` are the same guarantee from two directions.** Both assert
"verified-to-here, on one coherent chain": the range is what `verify_exhaustive` *returns*, the
frontier hash is what the next sweep *resumes from*. They must not drift apart — in particular, an
"optimization" that re-fetched the anchor from the source on resume would break the frontier's
coherence **without touching `VerifiedRange`**, and is exactly the option-(a) regression this
design rejects. A change to one is a change to both.

**Mismatch is a loud halt, not a rewind or a re-fetch.** The sweep runs `verify_exhaustive` before
extracting; an `ExhaustivenessError` becomes `PScanTaskError::Exhaustiveness`, and `run_pscan_task`
**halts** (returns, releasing the single-flight slot) instead of retrying — unlike a transient
transport blip, which it logs and retries next tick. The cursor does **not** advance over the
unverified batch, is **not** rewound, and the anchor is **not** re-derived; nothing is sealed past
the mismatch. The justification is finality depth — but it is **conditional on an honest tip**, and
that condition is worth stating because the layer does not establish it alone. The horizon is
`tip − reorg_depth` where `tip` is the source's **claimed** height; given an honest tip the verified
frontier sits beneath the reorg horizon of the *real* tip and an ordinary reorg cannot reach it (a
**beyond-finality anomaly**). Under an **over-claiming source** the horizon is too high, the frontier
can advance *within* reorg range, and the same mismatch may instead be an **ordinary reorg** — still
correctly caught as a halt, since 2d-1 cannot distinguish the two and halting + surfacing is the safe
response to both. (Tip-honesty is a posture/2d-2 property by our own three-property split, so the
finality-depth here is tip-honesty-dependent, not unconditional.) Either way the response is the
same, which is *why* there is no fork-point / re-org-rewind machinery here, where the principal's
refresh has it. A test asserts the anomaly is **raised, not absorbed** (Err surfaced, no advance,
frontier hash untouched, nothing sealed).

**Schema — bump without migration (two gates, not one).** `PSCAN_CURSOR_VERSION` and
`PSCAN_STATE_VERSION` went `1 → 2` with regenerated snapshots. The decision separates into two
independent gates that the `pending_unbonds` precedent only *looked* fused:

- *Migration code* is gated on **forward-persistence** — and there is none. The `.wallet.pscan`
  writer (`start_pscan` / the scan task) is dead-code-unwired; no deployed wallet (RC tags
  included) has ever persisted a v1 `.wallet.pscan`, so nothing reads v1 forward → **no migration
  code**.
- *The version number* is gated on **rule-42's snapshot guard** — a post-merge `.snap` diff forces
  the paired constant to move in the same PR (mechanical, persistence-independent). `pending_unbonds`
  needed no bump only because it rode v1's *creating* PR (a fresh `+` const line — a new, not a
  changed, version); this is a post-merge amend, so the bump is **forced**. It also honestly marks
  the real `height → verified-frontier` shape change. No rule-42 escape was taken: suppressing the
  guard to preserve a "true amend" would weaken a mechanical, self-documenting invariant on
  sealed funds-bearing state to save one integer — a bad trade.

**Still to build (after this round):** the 2d-2 GC (SP-R0) that consumes `PReconcileSet`'s
`covered` **+ a canonicity token**. `frontier_hash` is a public block hash (allowlisted in
`.zeroize-allowlist`, like `tip_hash`).

### `PReconcileSet` + durable reconcile evidence, as built (2026-06-29): the binding, the storage, the structural `covered`

SP-6 part 2 landed the reconcile evidence `P` hands 2d-2 — the type-safety spine plus the
durable storage that makes it correct across restart. Where this refines the design above, it
wins.

**The binding (`reconcile.rs`).** `PReconcileSet { covered: VerifiedRange, matches:
Vec<BondPostMatch> }`, constructible only via `from_verified_scan(covered, matches)`, which takes
a `VerifiedRange` (producible only by the verified path) — so a match set can **never** be paired
with an unverified range. The query is three-valued: `reconcile(persona, evidence_height) ->
ReconcileVerdict` returns `Present` / `AbsentWithinCovered` / **`OutsideCovered`**, so "absence ≠
unscanned" is *unrepresentable* — the same unmatched persona yields `AbsentWithinCovered` inside
`covered` but `OutsideCovered` off-range, and the GC cannot obtain a confirmed-absence verdict for
a height the scan did not cover. This unblocks 2d-2 SP-R0 (which was gated on this type existing).

**Durable, because in-memory can't reach the consumer.** The matches persist in `PScanState`
(`bond_post_matches`, schema bump **`PSCAN_STATE_VERSION` 2 → 3**, snapshot regenerated, no
migration — the writer is still unwired). This is *forced*, not a preference: Design B never
re-scans below the cursor, and SP-R0 corroborates an `Unbond` ~`MAX_CLAIM_AGE_W` epochs (~270k
blocks) after it was observed — by which point the block is far behind the cursor and gone. An
in-memory, per-session match set would be structurally absent exactly when SP-R0 needs it. Durable
is also the *superset*: it supports corroboration at observation-time **or** retire-time, so it
does not bet on SP-R0's still-settling shape. The accrual accumulates matches inside the same
all-or-nothing `ingest` commit as the funding deltas, and converts them to the state-shaped twin
`BondPostRecord` at the seal (rule 18, like the cursor/accrual split).

**The match set is the most privacy-sensitive field in `PScanState`.** It is `P`'s
persona-activity history (id × height × post-kind) — the exact thing the firewall keeps
off-disk-in-the-clear; public on-chain, but *correlated and co-located off-chain is the leak*. So
both `BondPostMatch` and `BondPostRecord` carry a **redacting `Debug`** (no clear log / `{:?}` /
export path the public amount-deltas never trigger), and the per-batch seal-cost note now records
that `bond_post_matches` grows per matched post (thousands over a long active lifetime), not on
`accruals`' bounded per-epoch schedule.

**`covered` is a structural verified-advance, not a `height → range` constructor (load-bearing).**
A free `covered() -> [0, synced_height)` would rest "everything below the frontier was verified" on
a cross-method invariant a future fast-forward could silently break — minting `VerifiedRange`s for
unverified ranges, so the GC removes personas on **forged absence**. Instead the accrual owns
`covered` as a `VerifiedRange` *token* that grows **only** through `VerifiedRange::extend(&VerifiedBatch)`
— and `ingest` takes the `VerifiedBatch` (not a bare hash), so the frontier cannot advance without
verification. The only height-taking constructors are `genesis_empty()` (`[0,0)`) and the one
seal-trust boundary `reconstruct_from_sealed_frontier` (`from_state` restoring `[0, synced_height)`
— justified because the sealed frontier could only have been reached *through* `extend`), both
`pub(in pscan)`. A scan/verify range divergence fails closed (`AccrualError::FrontierGap`) rather
than recording a `covered` with an unverified hole.

### `CoverDiscovery`, as built (2026-06-30): the funding-side completeness gate (SP-7)

SP-7 (`cover_discovery.rs`) landed as the funding-side twin of SP-6, closing `TM-3`. Three
refinements vs the §SP-7 sketch, all surfaced at source:

**The verdict is a wrap, not a new scan.** Cover *identification* is already guaranteed — the FA-6
view-tag pre-filter is false-negative-free, so the funding scan cannot reject an owned output. So
SP-7 does **not** build cover identification; it composes the funding-scan result (did the cover
recover, at what height?) with SP-6's [`VerifiedRange`] into the three-valued verdict, the
funding-side mirror of `PReconcileSet::reconcile`. Gate-first: `CoverDiscovery::classify` returns
`AbsentVerified` **only** when the *whole* cover window lies within `covered`; a window reaching
past the verified frontier is `Incomplete` (never `AbsentVerified`) — the funding-side "absence
concludable only within `covered`," which stops a source inducing a re-fund by under-serving the
window's tail.

**`Found` carries a redacted descriptor, not `OwnedOutput`.** The §SP-7 sketch's
`Found(OwnedOutput)` predates PR-A's firewall: `OwnedOutput` does not exist, and the secret outputs
stay inside the actor. So `Found` carries a minimal public `CoverFound` (the diagnostic height) —
the cover is already accrued in the actor's funding state; the verdict only signals it *arrived*.
That descriptor is `P`'s cold-start cover-funding moment (persona-history, on-chain-public but
correlated), so `CoverFound` carries a **redacting `Debug`**, the same discipline as
`BondPostMatch` / `BondPostRecord`.

**The real 2d-2 dependency is the tip-currency token, not the scan.** `verify_exhaustive` catches a
*gap* (a stripped cover-tx → continuity break → `Incomplete`) but **not** a complete-but-stale or
fork chain — it *passes* on a fork where the cover is absent-on-served-chain yet present-on-real-chain.
So `AbsentVerified` alone cannot authorize a re-fund; it needs a `TipCurrencyToken` certifying the
served chain is current — exactly SP-6's GC needing a canonicity token alongside
`AbsentWithinCovered` (same shape, same handoff). Cover-discovery is the one **non-lag-tolerant**
consumer (it decides at cold-start, time-sensitively — where a withholding source attacks by
claiming a stale tip and hiding the cover above it), which is *why* tip-currency is SP-7's
load-bearing dependency. The token is **posture-supplied**: trusted postures ①/② supply it by trust
(`TipCurrencyToken::trusted_node()`) so the gate **works now**; only the untrusted-posture ③
multi-source producer is deferred to 2d-2 §4 (rule-21 reopen: 2d-2 §4 lands). The gate's signature
requires the token *now*, so "re-fund on exhaustive-but-stale evidence" is unrepresentable
regardless of when ③ arrives.

**The re-fund gate — surface, never auto.** A `RefundConsideration` is constructible **only** via
`CoverDiscovery::refund_consideration` from `AbsentVerified` **plus** a token — never from
`Incomplete` or token-less absence, so "re-fund on a gap" and "re-fund on stale evidence" are both
unrepresentable. Even a valid consideration is a *consideration*: the consumer routes it to an
operator decision (the original funding likely never confirmed → retry-broadcast), never an
auto-re-fund (the induced relink `TM-3` describes). A prolonged `Incomplete` surfaces a warning;
there is no timeout path that manufactures a re-fund. The producer that supplies the funding-scan
result + the cover window is the cold-start lifecycle (unwired, like the rest of the pscan layer).
`AbsentVerified` / `RefundConsideration` carry **two distinct ranges**, not one: the **absence
window** (the cover window — where the cover provably did not appear, what the operator surface
reports) and the **exhaustiveness evidence** (the verified range the window lies within — a
superset, proof the window was fully scanned). They are separate accessors (`absent_window()` vs
`evidence()`) so a consumer cannot report the evidence range as the absence window.

**Two dispositions written into the module doc (deliberate, not gaps).** (1) **`Found` needs no
token** while `AbsentVerified` does — the asymmetry is intentional: a wrong-`Found` (a fork-cover
present on a served fork, absent on canonical) is **bounded and detectable** (posture-resolved,
finality-gated — `P` can't spend until finality-deep so a transient fork reorgs out — and a
fork-only spend produces a bond-post invalid on canonical, a *visible stake failure*), whereas a
wrong-`AbsentVerified` is a *silent, permanent* re-link. The token gates the silent-irreversible
side and only that side. (2) **An empty `cover_window` is unrepresentable** — it would vacuously
satisfy whole-window containment and mint `AbsentVerified`, so the non-emptiness is enforced **at
the type**: `BlockRange::new` rejects `start >= end`, so every `cover_window` covers at least one
block by construction and `classify` carries no runtime empty-window guard. A found cover's height
is still `debug_assert`-checked within the window (a scan/window-alignment tripwire).

### Alignment with the raw → newtype sweep (don't create new debt)

A large raw-primitive → domain-newtype migration runs at the end of Stage 2
([`RAW_TYPE_NEWTYPE_MIGRATION.md`](RAW_TYPE_NEWTYPE_MIGRATION.md)). 2d-1 introduces several
domain-carrying values; they are designed **sweep-conformant from birth**, so the sweep
finds no fresh raw-`u64`/`[u8;N]` debt here:

- **Money is `AtomicUnits`** (the existing newtype — checked-only, unit-marked) — never a
  bare `u64`. `PFundingInflow.atomic` is `AtomicUnits`; its `recompute_for_epoch` sums into
  it with the checked path. This is the migration's exact precedent, applied at creation.
- **Heights/epochs source the migration's home-crate types** (`BlockHeight`,
  `SettlementEpoch`), not raw `u64` — `PScanCursor.synced_height`, `BlockSource::block_at`,
  `BlockRange`, `PFundingInflow.settlement_epoch`. If those types aren't landed when 2d-1
  builds, 2d-1 either imports them from the migration's PR-0 home crate or flags the field
  so the sweep adopts it — **never** ships them as raw `u64` to be re-migrated.
- **Identity bytes are typed** (`p_canonical_id` already `[u8; 32]`-newtype-bound;
  `MatchedBondPost` carries the typed id, not a bare array) — the identity-confusion class
  the sweep removes.
- **Transparent where on-wire** (the `KeyImage` template: `#[repr(transparent)] +
  #[serde(transparent)]`) so the sealed `PScanCursor` is byte-stable; per the sweep's
  caveat, a `postcard-schema` field rename may need a `.snap` regen (mechanical), **not** a
  version bump.

Net: the §4 types are not just safe at the actor/seal boundary — they are the *kind* of
type the sweep is converging the whole stack toward, so 2d-1 lands *ahead* of the sweep,
not as work for it.

### What stays deferred (seam in place)

- **Constant-time-everything** (the `CtNoEarlyExitExtractor` impl behind SP-1a) +
  **execution isolation** — rule-21 reopen on a shared-cloud staking-as-a-service target or
  a cover/cold-start anonymity finding (Round 0 DQ1).
- **The Arti transport** behind `BlockSource` (SP-0 interface pinned; impl is 2d-2).
- **The `bonded_slots`/`p_slot` GC action** (2d-2 consumes `PReconcileSet`).
- **The `archival_reorg_depth_blocks` funding-visibility lag** as a cold-start sequencing
  input (DQ2 c2) — surfaced for the cold-start design, not 2d-1's to resolve.
- **Fetch-ordering of the same `BlockSource` trait (2d-2 constraint).** `block_at(height)`
  *permits* non-sequential fetch; once the Arti transport is underneath, the **order/timing**
  of `block_at` calls is itself a network-layer fingerprint. The trait correctly cannot leak
  output-*selectivity* (SP-0), but 2d-2's impl must additionally fetch **sequentially**, never
  in any output-correlated order. Not a 2d-1 issue — a constraint carried to the same trait's
  2d-2 implementation.
- **Scan *cadence* fingerprint (2d-2 constraint; SP-5 keeps it open).** The third fetch-layer
  leak after selectivity and order: *when/how often* `P` scans is a wire-pattern that
  correlates with `P`'s lifecycle. 2d-2 makes the injected `ScanSchedule` constant-rate or
  jittered; SP-5's only obligation now is to keep cadence injectable (no hardwired tick).
- **Positive-confirmation GC semantics (2d-2 consumes SP-6).** 2d-2 must GC a slot only when
  it is *affirmatively confirmed absent within `PReconcileSet.covered`*, never from absence
  outside the vouched range — the type pins the distinction, 2d-2 honors it. Same rule binds
  DQ8's persona-retirement.
- **Trusted-current tip — multi-source / out-of-band sanity-check (2d-2; closes SP-7's
  stale-tip residual).** `BlockSource::tip_height()` is one source's *claimed* tip; a single
  C3 daemon can truncate it for free. 2d-2 must supply **multiple `P`-isolated sources** that
  cross-check the tip (or an out-of-band difficulty/timestamp progression check) so
  `AbsentVerified` rests on a tip `P` has independent reason to believe current. Multi-source
  is consistent with DQ1 (the sources are all `P`'s, isolated from the principal). 2d-1's job
  is only to *not foreclose* it: `tip_height()` is documented as claimed-not-trusted, and no
  2d-1 path treats a single source as the tip authority.

**Build order (each SP a small, reviewable unit):** SP-0 (`BlockSource` + local impl) →
SP-1/1a (`GuaranteedViewPair` adapter + `OutputExtractor` seam + CT compare) → SP-2
(`PScanCursor`, Design-B single frontier, now a verified `(height, hash)` frontier —
**exhaustiveness** completeness via recompute-and-chain continuity + per-body tx-hash, no PoW;
canonicity/tip-honesty are posture/2d-2, see the trust-anchor resolution) → SP-3/SP-5 (dual
extractor + bounded `ScanStep` handler) → SP-4 (`PFundingInflow`, idempotent recompute) → SP-6
(`PReconcileSet`) → SP-7 (`CoverDiscovery` funding-side gate). Read-side only; SP-2 and SP-4
land **together** as the one crash-recovery decision. Broadcasts and GCs nothing.

### Threat-model cross-reference (`ARCHIVAL_FIREWALL_THREATS.md`)

The adversary pass catalogs `TM-1..8`. Of those, exactly **two are 2d-1's to build**, and
both are now in this design; the rest are either out of 2d-1's read-side scope (pre-genesis
analyses parallel to the consensus path) or route to a downstream consumer. Stated so "did we
cover the threats" has an explicit answer, not an implied one.

| Finding | What it is | 2d-1 disposition |
| --- | --- | --- |
| **`TM-3`** (A2, induced re-link by block-withholding) | funding reader re-funds on a withheld cover block | **Built — SP-7** funding-side completeness gate + root-anchored cursor (SP-2); the threats doc's one concrete 2d-1 ask |
| **`TM-6`** (A5, scan-cadence fingerprint) | *when/how-often* `P` scans leaks a wire pattern | **Built — SP-5** cadence-injectable (no hardwired tick); fix is 2d-2's, 2d-1 keeps it possible |
| **`TM-7`** (A8, cover *outflow* fingerprint) | spending the cover re-introduces a linkable pattern | **Routes to the steady-state consumer** (reader-(a)/SP-1 feeds it); the *spend* decorrelation is that design's, not the read side's — seam named |
| **`TM-1`** (A0, cross-persona clustering) | are `P`'s personas unlinkable from *each other*? | **Out of 2d-1 (read-side creates no on-chain event)** — but DQ8's `W`-tail is a named clustering correlate; flagged into the A0 analysis |
| **`TM-2`/`TM-8`** (A1, lifetime intersection; temporal model) | accumulation across windows; per-event ≠ lifetime | **Out of 2d-1** — pre-genesis temporal anonymity model (cover/standoff), parallel |
| **`TM-4`** (A3, earnings-scale fingerprint) | claim amount/cadence leaks `P`'s scale | **Out of 2d-1** — write-side claim/economics standardization, pre-genesis |
| **`TM-5`** (A4, join counterparty / Sybil) | a co-bonder is a closer observer than C0 | **Out of 2d-1** — JoinMarket bond design, pre-genesis |

**Honest bottom line.** 2d-1's read-side scope cannot address the top-of-ranking lifetime/
clustering/economics findings (`TM-1`, `TM-2`, `TM-4`) — those are not read-side problems and
must not be *claimed* closed here. What 2d-1 *can* foreclose, it now does: `TM-3` is built
(was a real gap — the funding reader had no completeness gate), `TM-6` is kept open for 2d-2,
and `TM-7`'s seam is named for the steady-state consumer. The cross-cutting `TM-8` (single-
window vs lifetime) is the meta-reason none of 2d-1's *per-event* soundness implies lifetime
unlinkability — a caveat this plan inherits, not resolves.
