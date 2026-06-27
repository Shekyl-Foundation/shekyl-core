# Bond-PR 2d-1 — `P`-scan layer, Round 1 (per-SP design)

**Predecessor:** [`ARCHIVAL_BOND_2D1_PSCAN_PLAN.md`](ARCHIVAL_BOND_2D1_PSCAN_PLAN.md)
(Round 0 — boundary ratified). **Status:** ROUND 1 — per-SP design for review; no code.
**Process rule:** `26-sub-pr-design-discipline.mdc`.

The Round 0 boundary is drawn at keys / state / fetch / execution. Round 1 derives the
per-SP design from it, and for every typed surface **pins the enforcement point *with* the
type shape** — because §4's "structural *don't* → *can't*" degrades back to "don't" at the
two places it's actually tested: the **kameo actor boundary** (message fields are
constructed by the sender, `Send + 'static`, moved/serialized) and the **seal**
(serialization round-trips a type through bytes and reconstitutes it from disk). A type's
guarantee is only as strong as the privacy of its constructor and the checks on its load
path. So each surface below names *where the invariant is enforced*, not just its shape.

---

## SP-0 — `BlockSource`: the no-selective-fetch property *is the trait's shape*

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
    fn tip_height(&self) -> Result<u64, BlockSourceError>;
    fn block_at(&self, height: u64) -> Result<Option<ScannableBlock>, BlockSourceError>;
}
```

**Enforcement point:** the trait *surface*. Adding a selective method is the only way to
reintroduce the leak, and that is a visible, reviewable API change — not an accident a
caller can make. (Same bar as the `PersonaHandle` `!Clone` seal: the bad state has no
representation.)

---

## SP-1 / SP-1a — the extractor: `Guaranteed`-only construction + the CT seam

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

---

## SP-2 — `PScanCursor`: distinct type *and* monotone-on-load (not type-at-runtime)

A distinct newtype stops accidental reuse of the principal's `BlockchainTip` (the compiler
rejects passing one for the other — DQ4 cross-contamination caught by `cargo`, not review).
But the **invariant lives in the LOAD path**: a postcard-decoded cursor is only as monotone
as the decode checks it to be — the type distinction *evaporates* at the seal boundary and
reconstitutes from whatever is on disk.

```rust
/// `P`'s scan cursor — distinct from `BlockchainTip`. Sealed StakingBlock-class
/// (postcard + AEAD + atomic_write_file + version). The monotone guard is on LOAD.
pub struct PScanCursor {
    version: u32,                 // rejected (not migrated) on mismatch — StakingBlock precedent
    synced_height: BlockHeight,   // sweep newtype — confirmed (finality-deep) scan frontier
}

impl PScanCursor {
    /// LOAD is where the invariant is enforced (mirrors `StakingBlock::
    /// monotone_current_slot`, `staking_block.rs:166`): reject on version mismatch,
    /// then clamp the on-disk height monotone-forward against the durably-known
    /// frontier — a rolled-back disk value can never re-report a scan (DQ2 c1:
    /// no reorg path because the frontier is finality-deep).
    pub fn from_sealed(bytes: &[u8], known_frontier: BlockHeight) -> Result<Self, CursorError> {
        let c: Self = decode_versioned(bytes)?;          // version-reject on load
        Ok(Self { synced_height: c.synced_height.max(known_frontier), ..c })  // monotone
    }
}
```

**Enforcement point:** the **deserializer (`from_sealed`)** — version-reject and the
monotone clamp — *not* the runtime newtype. The newtype is the in-memory carrier that stops
cross-use; the seal-load is the guard that survives the byte round-trip.

---

## SP-4 — `PFundingInflow`: confirmed-only constructor + *output-only across the seam*

The `C_min`-feeding inflow (DQ3) carries its unit *and* its provenance invariant. The trap
(actor boundary): if it travels as a message *field*, anything that can name the type can
build a message carrying a hand-built one — re-injecting an unconfirmed inflow into `C_min`,
the exact DQ7 corruption the type was meant to prevent. So **two** enforcement points:

```rust
/// Per-epoch `P` funding inflow — the signal `C_min` sizing consumes. Private
/// fields; NO `pub` constructor, NO `From<raw>`. Constructible ONLY inside the
/// extractor module, ONLY from outputs that passed the full ownership test (DQ7:
/// confirmed, never FA-6 pre-filter hits). Money is `AtomicUnits` (the existing
/// newtype), epoch is the sweep's settlement-epoch type — sweep-conformant from
/// birth, not new raw-`u64` debt (see "Alignment" below).
pub struct PFundingInflow {
    settlement_epoch: SettlementEpoch,   // sweep home-crate type, not raw u64
    atomic: AtomicUnits,                 // EXISTING newtype — checked, unit-marked
}

impl PFundingInflow {
    /// `pub(in crate::pscan::extractor)` — only the confirmed-output path builds it.
    pub(in crate::pscan::extractor) fn from_confirmed(epoch: SettlementEpoch, outs: &[ConfirmedOutput]) -> Self { /* checked sum into AtomicUnits */ }
    pub fn epoch(&self) -> SettlementEpoch { self.settlement_epoch }
    pub fn atomic(&self) -> AtomicUnits { self.atomic }
}
```

**Enforcement point:** (a) **constructor privacy** — `pub(in extractor)`, so no foreign
module builds one; and (b) **direction across the seam** — `PFundingInflow` is an *output*
only (a handler `Reply`, then pulled toward `C_min`); it is **never an inbound message
field**, so there is no message a caller can send that *carries* a hand-built inflow into
sizing. The `C_min` consumer takes `PFundingInflow` (not `u64`) and *queries* it; nothing
injects it. (Resolution of the user's pick: **message carries the already-validated type,
built only inside the extractor module — never raw-validated-on-receipt, never inbound.**)

---

## SP-3 / SP-5 — the dual extractor, run inside the actor, offloaded and bounded

**SP-3 (dual extractor, DQ2):** one block-iteration, two extractors over the same decoded
block — the view-key **funding** extractor (`OutputExtractor`, secret) and the **public
bond-post** match (`p_canonical_id` cleartext, no secret). The cursor advances at
**reconcile-grade finality** (the stricter reader sets the discipline; funding rides free).

**SP-5 (where it runs, DQ6):** the `P`-scan **task** owns the cursor, cadence, and
`BlockSource`; the **actor** is the `view_sk` vault and *performs* the per-batch scan-step.
`view_sk` never crosses the actor boundary — only **public** results come back.

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
until `handle` returns**. So `range` must be **bounded** (per-block / small batch): the task
loops, sending many small `ScanStep`s, and the actor interleaves rotation/sign/activate
*between* batches. Bounded batch + offload together; neither alone is enough.

**Enforcement point:** the secret stays inside the `spawn_blocking` closure (cloned from
`self.held`, dropped at closure end); `ScanStepResult` carries only public outputs +
`PFundingInflow` (built inside `run_dual_extractor`'s confirmed path). The actor returns
data, never keys — consistent with `PersonaIdentity` being public-only.

---

## SP-6 — `PReconcileSet`: typed, distinct from the funding output set

```rust
/// The public bond-posts matching `P`'s `p_canonical_id`s, in the scanned range —
/// the reconcile input `P` hands 2d-2 (which performs the GC). A DISTINCT type from
/// the funding `OwnedOutput` set, so the two readers' outputs cannot be conflated
/// at the 2d-2 boundary.
pub struct PReconcileSet { matched_posts: Vec<MatchedBondPost> }
```

**Enforcement point:** the type distinction — `PReconcileSet` ≠ funding output set, so
2d-2's GC cannot be fed a funding output by mistake, and a bond-post cannot be counted as
funding inflow. (The GC *action* is 2d-2; 2d-1 produces only this typed input.)

---

## Alignment with the raw → newtype sweep (don't create new debt)

A large raw-primitive → domain-newtype migration runs at the end of Stage 2
([`RAW_TYPE_NEWTYPE_MIGRATION.md`](RAW_TYPE_NEWTYPE_MIGRATION.md)). 2d-1 introduces several
domain-carrying values; they are designed **sweep-conformant from birth**, so the sweep
finds no fresh raw-`u64`/`[u8;N]` debt here:

- **Money is `AtomicUnits`** (the existing newtype — checked-only, unit-marked) — never a
  bare `u64`. `PFundingInflow.atomic` is `AtomicUnits`; its `from_confirmed` sums into it
  with the checked path. This is the migration's exact precedent, applied at creation.
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

## What stays deferred (seam in place)

- **Constant-time-everything** (the `CtNoEarlyExitExtractor` impl behind SP-1a) +
  **execution isolation** — rule-21 reopen on a shared-cloud staking-as-a-service target or
  a cover/cold-start anonymity finding (Round 0 DQ1).
- **The Arti transport** behind `BlockSource` (SP-0 interface pinned; impl is 2d-2).
- **The `bonded_slots`/`p_slot` GC action** (2d-2 consumes `PReconcileSet`).
- **The `max_reorg_depth` funding-visibility lag** as a cold-start sequencing input (DQ2
  c2) — surfaced for the cold-start design, not 2d-1's to resolve.

**Build order (each SP a small, reviewable unit):** SP-0 (`BlockSource` + local impl) →
SP-1/1a (`GuaranteedViewPair` adapter + `OutputExtractor` seam + CT compare) → SP-2
(`PScanCursor` + sealed monotone load) → SP-3/SP-5 (dual extractor + `ScanStep` handler) →
SP-4 (`PFundingInflow`) → SP-6 (`PReconcileSet`). Read-side only; broadcasts and GCs nothing.
