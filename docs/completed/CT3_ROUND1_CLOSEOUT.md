# CT-3 Round 1 close-out (2026-06-13)

**Status:** Round 1 closed. The persistent curve-tree client lifecycle is
landed end to end — open-on-disk, resume without genesis replay, delta sync,
and reorg rollback by segment — KAT-gated against the CT-2 Tier-A oracle and
consensus headers. The two source-side surfaces (bulk-leaf RPC endpoint,
`SegmentSource` seam) are deferred-with-recorded-shape per their reversion
clauses; they land with their first consumer (the post-prune refetch path),
not in CT-3.

**Authoritative plan:** [`CT3_SYNC.md`](CT3_SYNC.md) (Round 1 closed
2026-06-11, §3.7–§3.8). **Parent:** [`CURVE_TREE_CLIENT.md`](../design/CURVE_TREE_CLIENT.md)
§8 #6 / §9 CT-3 row.

---

## 1. Landed scope (CT-3a → CT-3c)

| Sub-PR | Disposition | Key files |
|--------|-------------|-----------|
| **CT-3a** (PR #128, 2026-06-12) | Store schema for persistence/reorg: pending-candidates table + `creation_height` on `leaf_meta`; redb-typed keys end to end (`BlockHeight`/`Gindex`/`TreePosition`/`SegmentId`); `schema_version` stamp checked before any write; single-txn `append_block_deltas` and `rollback_to_fork` store ops; shared truncation internals factored into a private txn-taking helper (§3.8 rider 2) | `store/redb_backend.rs`, `tests/store_kat.rs` |
| **CT-3b** (2026-06-12) | Client lifecycle: `open(path)` + resume (in-memory state rebuilt as the gindex-sorted drained ∪ pending union, element-wise identical to a continuous run); `ingest_block` writes both tables atomically *before* committing memory (store-behind-memory made unreachable; CT-2-era self-heal deleted); client outward API retyped to `BlockHeight`; `SCHEMA_VERSION` 2 → 3 | `client.rs`, `store/redb_backend.rs` |
| **CT-3c** (PR #132, 2026-06-12; review-hardened 2026-06-13) | Reorg rollback wiring: `CurveTreeClient::rollback_to_fork` over the store single-txn rollback; partition corrected to the CT-2 drain cutoff (`maturity > drained_through(fork_height)`) while tip/orphan filter stay fork-height-based; post-rollback frozen-tail `R_k` recheck with structured corruption errors; machine-enforced rollback poison contract; `append_drained` demoted to test-only | `client.rs`, `store/redb_backend.rs`, `tests/recon_kat.rs` |

## 2. Test gates (workspace)

From `rust/`:

```bash
cargo fmt --all -- --check
cargo clippy -p shekyl-curve-tree --all-targets -- -D warnings
cargo test -p shekyl-curve-tree
```

| Test | Role |
|------|------|
| `recon_kat::persistent_rollback_reorg_deep_matches_fresh_replay` | File-backed rollback/resync == fresh replay + consensus oracle roots |
| `client::tests::rollback_restores_pending_rows_for_redraining_and_long_maturity` | **Primary R1-Q3 gate** — direct pending-table row-set equality with a re-draining class-(b) witness and a 150k-lock never-draining witness |
| `client::tests::rollback_to_fork_rebuilds_memory_and_resyncs` | Rollback rebuilds memory and resumes forward ingest at `fork + 1` |
| `client::tests::poisoned_client_fails_fast_on_load_bearing_methods` | Post-commit rollback failure poisons the client; load-bearing calls fail fast |
| `store_kat::truncate_and_replay_matches_from_blocks` | Store rollback == prefix replay through the production write API |
| `redb_backend::tests::rollback_lands_on_first_of_equal_maturity_run` | F7 synthetic equal-maturity partition boundary |
| Restart round-trip + staked-lock resume (B3) | Pending candidates across restart produce byte-identical drain order; 150k-block stake byte-correct without ever draining |
| `no_secrets::public_types_are_non_secret_copy` | F6 structural no-secrets disjointness extended over the pending-row shape (`LeafEntry`) |

## 3. DoD mapping (`CT3_SYNC.md` §1)

| In-scope item | Disposition |
|---------------|-------------|
| 1. Persistent client lifecycle (open + resume, no genesis replay) | **Landed** CT-3b |
| 2. Delta sync (pending set reconstructed exactly) | **Landed** CT-3b |
| 3. Reorg rollback by segment (no raw-block replay) | **Landed** CT-3c |
| 4. Per-segment root verify (frozen `R_k` recheck) | **Landed** CT-3c on the rollback path; resume-path and full-segment sweeps deferred (§4) |
| 5. Source seam (`SegmentSource`) | **Deferred-with-recorded-shape** (§4); lands with its first consumer per B3 |
| 6. Restore-from-seed (F8 trivial case) | **Landed** CT-3b — an empty store on disk resumes to an empty client ready for genesis ingest |

## 4. Deferred with reversion clauses (FOLLOWUPS-routed)

Per `21-reversion-clause-discipline.mdc`, each carries a named reopening
trigger; none is "refused forever."

- **Bulk-leaf RPC endpoint (`get_curve_tree_leaves`) — R1-Q1.** Block-derived
  forward sync is the confirmed default (the §6 reversion criterion fired:
  CT-2 landed the drain replication, KAT-verified), repositioning the RPC to
  non-forward catch-up + archival. Endpoint + §6 reconstruct-root KAT land
  with the prune-policy PR, which makes refetch reachable.
- **`SegmentSource` seam — R1-Q5.** The trait's recorded shape is
  `CT3_SYNC.md` §3 R1-Q5; B3 forbids a public surface without a caller, and
  the seam's first consumer is the R1-Q1 refetch path, so the seam rides that
  same FOLLOWUPS row.
- **Store-backed / pruned-tree path assembly — R1-Q6 / F5.** V3.0 keeps the
  in-memory entry vec as the assembly substrate (resume rebuilds it from the
  store); reopens when the prune-policy PR lands, where in-memory-only
  assembly breaks for pruned wallets by construction.
- **Resume-path and full-segment frozen-`R_k` recheck.** CT-3c runs the
  bounded check only on the rollback path; the resume-path O(segment) cost
  and the all-segment sweep ride the prune-policy / store-startup hardening.
- **CT-5 rollback poison reaction.** Detection is now machine-enforced
  (`ClientError::Poisoned`); CT-5's residual obligation is to map it to
  drop-and-reopen rather than retry-with-same-object.

## 5. What Round 1 ungates

- **CT-5 (engine/refresh wiring).** The resume + delta-ingest +
  rollback-to-fork API is the contract CT-5 consumes; CT-5 connects the
  refresh loop (which already delivers every block) to `ingest_block` and
  owns the poison reaction.
- **CT-2 Tier B** continues to order after CT-5 (real non-coinbase minting
  needs real local path assembly — CT-3 + CT-5 — then stake-tx minting), per
  `CT2_ROUND1_CLOSEOUT.md` §5.

## 6. Explicitly not Round 1

- Bulk-leaf RPC endpoint implementation and its C++ KAT (rides prune-policy).
- `SegmentSource` implementations and anonymized (Tor/I2P) routing.
- Store-backed assembly for pruned wallets.
- Network/peer transport.
