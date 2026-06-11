# CT-3 — persistent delta sync, reorg rollback, source seam (design — Round 1 open)

**Status:** Pre-flight substrate audit complete (2026-06-11). Round 1
questions enumerated with proposed dispositions; no production code yet.

**Parent design:** [`CURVE_TREE_CLIENT.md`](./CURVE_TREE_CLIENT.md) §9 CT-3 row:
"Source-agnostic bulk-segment fetch + delta sync + per-segment root verify
against header; reorg rollback by segment."

**Process discipline:** this plan-doc cites
`26-sub-pr-design-discipline.mdc` (multi-round per-trait PR; consensus-coupled
drain-order replication). The substrate audit below follows A2
(audit-against-actual-code, pinned citations); boundary moves follow A4;
findings route per A5.

**Timeframes (`05-system-thinking.mdc`):** addresses **Now** (V3.0 pre-genesis:
the production wallet's persistent tree sync) and **mining-era end** (the
archival data plane this store feeds is the fee-era staking substrate, §7 of
the parent doc). V4 lattice transition is not in scope; leaf format changes at
V4 are a re-sync, not a migration (pre-genesis discount inherited by design).

---

## 1. Scope and definition of done

### In scope

1. **Persistent client lifecycle.** `CurveTreeClient` opens an on-disk
   `LeafStore` (`LeafStore::open`, landed CT-1) and **resumes** from persisted
   state — no genesis replay on wallet restart.
2. **Delta sync.** After resume, `ingest_block` continues from
   `sync_tip_height + 1`. The pending-candidate set (undrained leaves) is
   reconstructed exactly (§4 R1-Q2).
3. **Reorg rollback by segment.** A persistent client that learns of a fork
   below its synced tip rolls back the store to the fork point (frontier
   truncate, landed CT-1) and re-syncs forward — without raw-block replay
   from genesis (§4 R1-Q3).
4. **Per-segment root verify.** Frozen-segment `R_k` recheck on resume
   (corruption detection) via `recompute_segment_r_k` (landed CT-1).
5. **Source seam.** The trait boundary that makes segment refetch
   peer-pluggable (§4 R1-Q5) — the seam only; no network implementation.

### Out of scope

- The C++ `get_curve_tree_leaves` daemon endpoint (separate PR per parent §6;
  see R1-Q1 for its repositioned role).
- Network/peer transport, Tor/I2P routing (parent §8 #11 rides the fetch
  *implementation*, not the seam).
- Engine/refresh wiring — who calls `ingest_block` in production is **CT-5**
  (the refresh loop already delivers every block; CT-5 connects it).
- Store-backed / pruned-tree path assembly (`assemble` currently reads the
  in-memory entry vec; see F5 disposition).
- `ArchivalEngine` serve/market (V3.x, parent §7.6).

### DoD

- A persistent client round-trips: sync N blocks → drop → reopen → resume →
  ingest N+1 — root at every reference height equals the CT-2 oracle root
  (extend `recon_kat.rs` / `store_kat.rs` over `ct2_tier_a.json`).
- Reorg KAT: the CT-2 `reorg_deep` chain replayed through the **persistent
  rollback path** (truncate + re-sync, not `from_blocks` rebuild) matches the
  oracle at every post-fork height.
- Resume KAT: pending candidates across a restart produce byte-identical
  drain order vs an unbroken run (the 150k-block staked-maturity case is the
  adversarial shape, §3 F3).
- `cargo fmt` / `clippy -D warnings` / crate tests green; no new `pub`
  surface without a named production caller (B2/B3).

---

## 2. Pre-flight substrate audit (A2 — pinned citations)

Audit pin: `chore/ct3-sync-design` branch point off `dev`, 2026-06-11.

| # | Surface | State | Evidence |
|---|---------|-------|----------|
| S1 | Client construction | **Ephemeral store only** — `try_new` hardcodes `LeafStore::open_ephemeral`; no on-disk constructor | `rust/shekyl-curve-tree/src/client.rs:173-196` |
| S2 | Persistent open | `LeafStore::open(path)` landed, **zero client callers** | `rust/shekyl-curve-tree/src/store/redb_backend.rs:120` |
| S3 | Ingest contract | Strictly consecutive heights **from genesis** (`expected = 0` when fresh); no resume entry point | `client.rs:217-230` |
| S4 | Reorg path | `from_blocks` = clear store + full replay (derive-don't-accumulate); needs every raw block | `client.rs:198-207` |
| S5 | Pending candidates | In-memory only (`entries_by_maturity`); **not persisted**; store holds drained leaves only (`append_drained`) | `client.rs:159-161`, `redb_backend.rs:197` |
| S6 | Maturity window bound | Long stake tier locks **150,000 blocks** — pending set is not reconstructible from a short tail re-scan | `config/economics_params.json:17`, `blockchain_db.cpp:408-411` |
| S7 | Rollback primitive | `truncate_from_tree_position` landed (batched, prune-aware) | `redb_backend.rs:357` |
| S8 | Height→position mapping | No index table; **but** drain order is `(maturity, gindex)` and persisted `leaf_meta` carries maturity → fork-height → position is binary-searchable | `redb_backend.rs:21` (`leaf_meta`), `types.rs:69-89` |
| S9 | Segment verify | `recompute_segment_r_k` landed | `store/ops.rs:139` |
| S10 | Freeze / pin / prune | `maybe_freeze_segments`, `pin_segment`, `prune_frozen` landed | `redb_backend.rs:284,447,465` |
| S11 | `sync` module | **Absent** (parent §3.2 names it; nothing exists) | `rust/shekyl-curve-tree/src/` listing |
| S12 | Daemon bulk-leaf RPC | **Absent**; only `get_curve_tree_root` exists | `src/rpc/core_rpc_server.cpp:3891` |
| S13 | Block-derived production path | Landed + KAT-verified end-to-end (CT-2 Tier A runs through `CurveTreeClient`) | `CT2_ROUND1_CLOSEOUT.md` §2, `client.rs` module doc |

### Findings

- **F1.** The gap between CT-1/CT-2's landed substrate and a production wallet
  is precisely lifecycle: persistence exists (S2), reconstruction exists
  (S13), but no code path opens-on-disk, resumes, or rolls back without
  genesis replay (S1/S3/S4).
- **F2.** The §9 row's "bulk-segment fetch" presumes the parent §6 RPC
  default. The substrate has shifted since Round 0: the block-derived
  replication the §6 reversion clause named ("reopened if this phase finds
  the replication cheap and well-tested") is now landed, production-pathed,
  and KAT-verified (S13). R1-Q1 re-evaluates the default per the named
  criterion — this is the reversion clause firing as designed, not scope
  drift.
- **F3.** Resume cannot re-derive pending candidates from a bounded tail
  re-scan: the staked maturity class reaches 150,000 blocks (S6). Pending
  candidates must persist (R1-Q2). This falsifies the implicit Round-0
  assumption that drained-leaf persistence suffices.
- **F4.** Rollback-by-height needs a height→tree-position mapping. S8 shows
  it is derivable (maturity is monotone non-decreasing in position), so no
  new table is strictly required — verify the binary-search disposition at
  impl (B6: confirm `leaf_meta` byte layout actually exposes maturity).
- **F5.** `assemble` reads the in-memory entry vec (`assemble.rs:84-89`);
  whole-tree-in-memory is fine at Tier-A scale and wrong at mainnet scale.
  Store-backed assembly is **not** CT-3 (it belongs with the prune-policy
  work, parent §8 #9) — recorded in `FOLLOWUPS.md` with a V3.0 target so it
  is not silently lost. CT-3 must not foreclose it (the store already holds
  `owned_identities`, S10).

---

## 3. Round 1 questions and proposed dispositions

### R1-Q1 — Forward-sync data source (parent §8 #6; reversion criterion met)

**Proposed disposition:** confirm **block-derived** as the forward-sync
default. The wallet's refresh loop already delivers every block; leaves derive
locally (zero new RPC, zero query metadata — strictly dominant on the parent
§7.4 privacy gradient). CT-2 proved the consensus-sensitive drain replication
bit-exact against real headers — the exact risk that justified the RPC default
at Round 0.

**Repositioned role of the §6 bulk-leaf RPC:** non-forward catch-up only —
refetching a segment the wallet previously **pruned** (parent §7.4 case 2) and
the archival data plane (§7.3). A wallet that has not pruned never needs it.
Pre-genesis there are no pruned wallets, so the endpoint is **deferrable
without loss**: CT-3 lands the seam (R1-Q5); the C++ endpoint and its KAT land
with the prune-policy work.

**Reversion clause:** reopen the RPC-default question if (a) measured
mainnet-scale forward sync (block ingest + drain + store mirror) exceeds the
refresh loop's latency budget (B9: measure, don't estimate), or (b)
pruned-segment refetch becomes load-bearing before genesis (prune policy
ships in V3.0 and field use shows refetch demand). Re-evaluation shape: new
round in this doc + `SHEKYLD_PREREQUISITES.md` entry for the endpoint.

### R1-Q2 — Resume semantics: persist pending candidates

**Proposed disposition:** add a pending-candidates table to the CT-1 store
schema (entries carry `(gindex, maturity, leaf, identity)` — same shape as
`leaf_meta` rows, keyed by gindex). `ingest_block` writes drained **and**
pending deltas in one redb transaction; resume reads both and rebuilds
`entries_by_maturity` in memory. Schema change is pre-genesis (no migration
code; `rm -rf` is the upgrade path per `15-deletion-and-debt.mdc`).

**Rejected alternative:** tail re-scan on resume — unbounded by S6/F3 (150k
blocks), and it couples client resume to block availability, which the
refresh layer does not guarantee backwards.

### R1-Q3 — Reorg rollback for the persistent client

**Proposed disposition:** rollback = three store operations in one
transaction: (1) binary-search the first drained position with
`maturity > fork_height` (F4) and `truncate_from_tree_position` there;
(2) delete pending candidates with `gindex` above the fork's last assigned
index; (3) reset `sync_tip_height` to `fork_height`. Then re-sync forward via
normal `ingest_block` as the refresh layer re-delivers the new branch.
`from_blocks` full rebuild remains the KAT/test path; the production path
never requires raw blocks below the fork.

**Invariant to assert:** post-rollback (root at every height ≤ fork) ==
(fresh-build root) — the CT-2 `reorg_deep` oracle pins this.

**`TruncatedIntoPrunedRange` interaction (S7):** pre-prune wallets cannot hit
it; once prune ships, a reorg deeper than a pruned frontier forces the R1-Q1
refetch path. Assert the error surfaces loudly (it does — landed CT-1) and
leave recovery to the prune-policy work.

### R1-Q4 — Match-cost index (parent §8 #2)

**Proposed disposition:** defer out of CT-3. Path assembly is per-spend and
reads owned outputs only; the linear identity scan is bounded by owned-output
count, not tree size, once `owned_identities` (S10) is consulted first.
Reopen if CT-5 wiring measures assembly latency above the send path's budget
(B9). No index table in CT-3.

### R1-Q5 — Source seam shape

**Proposed disposition:** a minimal crate-local trait, named caller = the
post-prune refetch path (R1-Q1):

```rust
/// Serve one frozen segment's leaves, content-addressed by R_k.
/// Implementors: own daemon (V3.0, deferred with the §6 endpoint),
/// staker peers (V3.x archival). Integrity per parent §7.3: the caller
/// verifies received bytes against R_k on receipt; a lying source can
/// only deny service.
pub trait SegmentSource {
    fn fetch_segment(&self, id: SegmentId, expected_r_k: [u8; 32])
        -> Result<Vec<[u8; 128]>, FetchError>;
}
```

No implementation in CT-3 (B3: no surface without a caller — the trait lands
**with** its first consumer, the refetch path, or not at all; if R1-Q1's
deferral holds through Round 1 review, the trait is *also* deferred and this
section becomes the recorded shape for that later PR). Anonymized routing
(parent §8 #11) attaches to implementations, not the seam.

### R1-Q6 — Persistent-client memory model

**Proposed disposition:** V3.0 keeps the in-memory entry vec as the assembly
substrate (F5); resume rebuilds it from the store (drained + pending tables).
This bounds CT-3 to lifecycle work without restructuring `assemble`. The
mainnet-scale store-backed assembly question rides the prune-policy item in
`FOLLOWUPS.md` (F5 routing).

---

## 4. PR decomposition (provisional; `06-branching.mdc` sized)

| PR | Scope | Key files |
|----|-------|-----------|
| **CT-3a** | Store schema: pending-candidates table + height→position lookup; resume read path (`LeafStore` only, no client change); KATs | `store/redb_backend.rs`, `tests/store_kat.rs` |
| **CT-3b** | Client lifecycle: `open(path)` constructor, resume (rebuild in-memory state from store), delta `ingest_block`; restart round-trip KAT | `client.rs`, `tests/recon_kat.rs` |
| **CT-3c** | Reorg rollback: fork-point search + transactional rollback + re-sync; `reorg_deep` persistent-path KAT; frozen-`R_k` resume recheck | `client.rs`, `store/`, `tests/` |
| **CT-3d** | Doc closeout: parent §8/§9 status updates, `CT3_ROUND1_CLOSEOUT.md` (or pins), CHANGELOG, FOLLOWUPS routing (F5) | docs |

Each lands on `dev` within the 5-day/10-commit guidance; no consensus-rule
boundary is touched (the drain rule is CT-2's landed, KAT-pinned replication —
CT-3 changes *where state lives*, not *what is computed*), so
`07-consensus-atomic-cutovers.mdc` is not invoked.

---

## 5. Threat-model addenda placeholder (A3 — due Round 3–4)

Objectives to enumerate at the late round, recorded now so closure cannot
skip them: store-corruption → forged root (S9 recheck must cover resume),
malicious reorg signal → rollback DoS (fork-height validation), pending-table
poisoning across restart (drain-order divergence ↔ the CT-2 KAT is the net),
refetch-source lying (parent §7.3 — only if R1-Q5's trait lands with a
consumer).

---

## 6. Cross-references

- Parent: `CURVE_TREE_CLIENT.md` §3.2 (sync module), §3.4 (reorg), §6 (RPC
  reversion clause → R1-Q1), §7.3–§7.4 (source-agnostic + privacy gradient),
  §8 #2/#6/#9/#11, §9 CT-3 row.
- Landed substrate: `CT1_ROUND1_PINS.md`, `CT1_ROUND1_CLOSEOUT.md`,
  `CT2_DRAIN_ORDER.md`, `CT2_ROUND1_CLOSEOUT.md`.
- Downstream: CT-5 (engine/refresh wiring consumes CT-3b's resume + ingest
  API), CT-2 Tier B (fixture generation rides CT-3 + CT-5 + the 2A spend
  path — see the CT-2B ordering note in `CT2_ROUND1_CLOSEOUT.md` §5).
- Process: `26-sub-pr-design-discipline.mdc` (A2/A3/A4/A5, B3/B6/B9),
  `21-reversion-clause-discipline.mdc` (R1-Q1 shape).
