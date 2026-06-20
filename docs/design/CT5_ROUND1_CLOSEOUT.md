# CT-5 Round 1 close-out (2026-06-20)

**Status:** Round 1 closed. CT-5 wires the production `CurveTreeClient`
(CT-1–CT-4) into the 2A send path, replacing the synthetic membership vectors
with real reconstructed trees. The six in-scope surfaces
([`CT5_ENGINE_WIRING.md`](CT5_ENGINE_WIRING.md) §1) all landed across CT-5a
(actor + forward ingest), CT-5b (§3.3 verify-at-ingest + poison/respawn), CT-5c
(`assemble_path` cutover — synthetic vectors retired), and CT-5d (proactive
re-anchor horizon, PR #159), and the real-tree FCMP++ prove→verify roundtrip was
closed by PR #162 (the partial-branch-chunk fix). The engine now owns a
single-writer `CurveTreeActor` whose tree is driven from the refresh cursor and
defended at every ingest against the consensus header root.

**Authoritative spec:** [`CT5_ENGINE_WIRING.md`](CT5_ENGINE_WIRING.md) (engine
wiring), [`CURVE_TREE_CLIENT.md`](CURVE_TREE_CLIENT.md) §3.5 (assemble contract)
/ §5 (reference + horizon), [`PHASE_2A_SEND_PATH.md`](PHASE_2A_SEND_PATH.md)
§3.7 (the signer the path feeds). **Parent:** §9 CT-5 row.

---

## 1. Landed scope

| Surface | Disposition | Key files |
|---------|-------------|-----------|
| **Client ownership + lifecycle** (CT-5a) | The engine owns a production `CurveTreeClient` behind a single-writer `CurveTreeActor`, opened against an on-disk `LeafStore` beside the wallet files, resumed on open. The `CurveTreeHandle` is a `Clone` handle over a shared `Arc<Mutex<ActorRef>>` cell so a respawn swaps the fresh actor in for **all** clones. The actor holds no `Engine`/secret state (R1-Q1). | `engine/curve_tree_actor.rs` |
| **Forward ingest** (CT-5a) | The refresh merge decodes per-block leaves it already parses (`ScanResult.block_leaves`) and feeds each block to the actor at consecutive height via `IngestBlock`. The driver is **cursor-driven** (D2): it reads its resume point from `IngestedTipHeight` every iteration and holds no local frontier, so counter-drift is unrepresentable. | `engine/merge.rs`, `scan.rs` |
| **Reorg rollback + poison recovery** (CT-5b) | On a fork, `curve_tree_ingest_scan_result` rolls the tree back to `fork_height − 1` (`RollbackToFork`) alongside the ledger rewind, then re-ingests from the rewound cursor. `ClientError::Poisoned` (and a fail-stopped actor) are classified `recoverable_by_respawn` by `map_curve_tree_handle_error`; `ingest_scan_result_with_respawn` then **drops and reopens** the client (`respawn`) and retries once — never retry-with-same-object. Deterministic faults (`RootMismatch`, contract violations) surface terminally to avoid reopen→poison livelock. | `engine/merge.rs` |
| **§3.3 verify-at-ingest** (CT-5b, O5/R1-Q6) | The reconstructed root *defends* at ingest (`VerifyRoot` compares `root_at(height)` to the header-carried `curve_tree_root`); it is derived, not held as truth. A genuine divergence is `RootMismatch` (lying-daemon DoS), read apart from a client rejection. | `engine/curve_tree_actor.rs`, `engine/merge.rs` |
| **Real path assembly** (CT-5c) | The 2A signer's synthetic `TreeContext`/membership vectors are replaced by `CurveTreeClient::assemble_path` per spend input via the `AssembleTx` actor handler (one snapshot per handler invocation — no ingest/rollback interleave, E1), mapped onto the existing `TxInputSigningContext`/`SpendInput` shapes. The C3 precondition `c1_layers.len() + c2_layers.len() + 1 == tree_depth` is checked before proving. | `engine/curve_tree_actor.rs`, `engine/sign_bridge.rs` |
| **Reference selection + proactive horizon** (CT-5d, PR #159) | Reference at `tip − REF_ANCHOR_AGE`; pending txs track their reference height and `reference::should_reanchor` drives a content-preserving reprove re-anchor (three-phase, consent-gated) before a proof ages past the acceptance window. Reactive `ProofStale` detection stays deferred to Phase 6 (needs a daemon stale-root signal). | `tx-builder` reanchor, `engine/local_pending_tx.rs` |
| **Real-tree FCMP++ verify** (PR #162) | A membership proof built over a *real multi-layer* `assemble_path` now verifies. Root cause: `assemble` emits partial (narrow) branch chunks for incomplete nodes while the FCMP circuit needs the full chunk width; fixed by zero-padding branch chunks in `shekyl_fcmp::proof::prove`/`prove_with_sal` (zero scalars vanish in the layer hash → consensus root unchanged). Over-wide chunks are rejected (`BranchChunkTooWide`), not truncated. | `shekyl-fcmp/src/proof.rs` |

## 2. Test gates (workspace)

From `rust/`:

```bash
cargo fmt --all -- --check
cargo clippy -p shekyl-engine-core -p shekyl-fcmp -p shekyl-curve-tree --all-targets -- -D warnings
cargo test -p shekyl-engine-core -p shekyl-fcmp -p shekyl-curve-tree
```

| Test | Role |
|------|------|
| `refresh::tests::engine_ingest_reorg_matches_ct2_tier_a_oracle_at_every_height` | **Primary engine-path gate** — ingest the `ct2_tier_a.json` `reorg_deep` fixture *through the engine* (not the client-only path); the post-rollback tree root at every height equals the CT-2 oracle |
| `refresh::tests::ingest_pre_pass_reorg_rolls_back_and_resumes_from_cursor` | Reorg rolls the tree back to the fork and the cursor-driven driver resumes correctly |
| `refresh::tests::ingest_pre_pass_respawns_after_actor_fail_stop` | The drop-and-reopen poison reaction: a fail-stopped/poisoned actor is respawned and the ingest retried once (:219 wiring) |
| `curve_tree_actor::tests::respawn_resumes_from_store_and_propagates_to_clones` | `respawn` reopens from the persisted store and the fresh actor is visible to all handle clones |
| `local_pending_tx::tests::join_market_bond_post_fcmp_verify_over_real_tree` | **Real-tree verify gate** (PR #162) — a bond proof over a real depth-2 `assemble_path` verifies (`Ok(true)`), no longer `BatchVerificationFailed` |
| `proof::tests::ct5_partial_branch_chunk_is_padded_and_verifies` | Regression: a partial (1-wide) Helios branch chunk + narrow consensus root verifies (the padding contract) |

## 3. DoD mapping (`CT5_ENGINE_WIRING.md` §1.162)

| Item | Disposition |
|------|-------------|
| Built+submitted tx proves against a **real reconstructed root** (C3 precondition holds; `synthetic_tree_root_from_leaf_chunk` retired) | **Landed** — CT-5c cutover + #162 verify roundtrip |
| Refresh + reorg KAT: post-rollback root == CT-2 oracle through the engine path | **Landed** — `engine_ingest_reorg_matches_ct2_tier_a_oracle_at_every_height` |
| C2 gate rejects `eligible_height > reference_height` with a clean `OutputNotYetSpendable` | **Landed** — selection-time spendability gate |
| Structural no-secrets test over the `CurveTreeHandle`/actor/`AssembledPath` surface | **Landed** — secrets enter only at `sign_bridge → SpendInput` |
| `fmt`/`clippy -D warnings`/`test` clean across engine-core + curve-tree (+ fcmp for #162) | **Landed** |
| §3.7.6 / §5.4 two-ages terminology correction in `PHASE_2A_SEND_PATH.md` | **Landed** (PHASE_2A_SEND_PATH.md §3.7.6, "two ages, not one") |

## 4. Design pins (at source)

- **Single-writer actor, engine-side respawn (R1-Q1/R1-Q4).** One `CurveTreeActor`
  owns the client; mutation is serialized through it. Respawn-on-poison runs
  **engine-side, after** the failed `ask` returns — never inside a handler under
  the engine guard — and swaps a fresh actor into the shared cell.
- **Derive-don't-hold consistency (R1-Q6 / §3.3).** The tree reconstructs the
  root and verifies it against the per-block header `curve_tree_root` at ingest;
  the daemon is defended-against, not trusted. A lying daemon is a DoS, not a
  theft vector.
- **Cursor-driven resume (D2).** The ingest/rollback driver reads its frontier
  from the tree's `ingested_tip_height` each iteration; a reorg that rewinds the
  cursor is observed on the next read. No driver-local counter to drift.
- **Branch chunks are zero-padded to width for the proof, narrow on-chain
  (#162).** `hash_grow([c]) == hash_grow([c, 0…])`, so padding satisfies the FCMP
  circuit while the consensus root stays the narrow value `build_layers` / the
  daemon produce. The same Rust `verify` is what the daemon runs via FFI.

## 5. Deferred with reversion clauses (FOLLOWUPS-routed)

Per `21-reversion-clause-discipline.mdc`, each carries a named reopening trigger.

- **Per-input reconstruction reuse (CT-5c perf).** `assemble_path` re-runs
  `build_layers` + a linear `gindex` scan once per input (O(k·n log n) for a
  k-input tx). **Reopens** when per-tx batching at scale is taken up: fold to
  once-per-transaction with an ingest-time `gindex → position` index
  (O(log n)/O(1) per input). Not built in Round 1 — premature before mainnet
  scale (rules 21/70); correctness is unaffected.
- **Reactive `ProofStale` detection — Phase 6.** Needs a daemon-side stale-root
  signal (`SHEKYLD_PREREQUISITE`); CT-5 lands only the proactive horizon guard
  (`should_reanchor`). **Reopens** with the daemon signal (2A §3.6).
- **Store-backed / pruned-tree assembly — F5.** `assemble` reads the in-memory
  entry vec; correct at Tier-A scale. **Reopens** with the prune-policy PR.
- **Multisig (v31) send.** CT-5 wires the single-signer 2A path; multisig reuses
  the same `assemble_path` but is a separate signer surface. **Reopens** with the
  v31 multisig send slice.

## 6. What Round 1 ungates — and why Track 2 is *not* CT-5

CT-5 is the last CT phase: it consumes CT-1–CT-4 and proves the wallet can build
a spend over a real reconstructed tree that verifies. What remains is **not CT
scope** — it is end-to-end daemon parity and the deferred maturity classes,
tracked as **"Track 2" (the ephemeral FAKECHAIN regtest)**:

- **C++↔Rust verify parity** — the daemon's `shekyl_fcmp_verify` is the same Rust
  `verify` via FFI; an on-chain mint→spend regtest confirms the full path
  end-to-end (depth-3+ trees included). Spans the **§9 "C++" row**
  (`get_curve_tree_leaves`) + a regtest harness, not CT-5.
- **CT-2 Tier-B** reconstruct-root KATs (staked / non-coinbase maturity classes,
  `recon_tier_b.rs`) — explicitly *ordered after CT-5*, blocked on the
  `ct2_tier_b.json` fixture the regtest produces.

## 7. Explicitly not Round 1

- The C++ `get_curve_tree_leaves` bulk-leaf RPC / any daemon change (§9 C++ row).
- The Track-2 FAKECHAIN regtest, mint flow, and Tier-B fixture.
- Depth-3+ real-tree verify validation (needs the regtest's larger fixtures).
- Per-input reconstruction-reuse perf fold (§5).
- Multisig send and `ArchivalEngine` serve/market.

## 8. FOLLOWUPS audit (residual CT-5-tagged obligations)

Round 1 close pulled the CT-5-tagged FOLLOWUPS items in for verification rather
than paper-closing them. Result:

- **Poison drop-and-reopen reaction** (was: "CT-5's residual obligation is the
  reaction") — **delivered**, not residual: `map_curve_tree_handle_error` →
  `recoverable_by_respawn` → `ingest_scan_result_with_respawn` drops+reopens and
  retries, on both the ingest and rollback sends. The item's own reopening
  trigger ("CT-5 introduces a rollback actor/wrapper that owns this policy
  centrally") fired. **Closed.**
- **`BlockHeight`/`Gindex` typing across the client→engine seam** — **delivered**:
  the actor messages (`IngestBlock.height`, `RollbackToFork.fork_height`,
  `IngestedTipHeight → Option<BlockHeight>`) carry `BlockHeight`, with sends
  wrapping at the boundary; raw `u64` is confined to the internal recon/producer
  oracle exactly as the item specified. **Closed (engine portion).**
- **Per-input reconstruction reuse** — genuinely open perf item, re-routed to §5
  with a sharpened trigger (kept open, not closed).
