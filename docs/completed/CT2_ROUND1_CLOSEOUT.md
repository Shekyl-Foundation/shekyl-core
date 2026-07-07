# CT-2 Round 1 close-out (2026-06-06)

**Status:** Round 1 closed. Tier A reconstruct-root obligations are met against
the checked-in oracle; Tier B is scaffolded and deferred until Phase 2A can mint
regular/staked outputs.

**Authoritative spec:** [`CT2_DRAIN_ORDER.md`](../design/CT2_DRAIN_ORDER.md) §8.2–§8.3,
[`CURVE_TREE_CLIENT.md`](../design/CURVE_TREE_CLIENT.md) §9 CT-2.

---

## 1. Fixture verification (gates the obligation table)

### Chain shape

| Parameter | Value | Role |
|-----------|-------|------|
| `main_tip` | 210 | Past first Helios deepen (~height 99 on coinbase-only) |
| `deep_pop` | 70 | Deep reorg fork at 140 — trim branch, undeepen exercised |
| `shallow_pop` | 5 | Pending-only branch — freeze-lag, not undeepen |

### Empty-window boundary (fixture truth)

| Height | Oracle root |
|--------|-------------|
| 58–60 | `selene_hash_init` (empty tree) |
| 61 | First non-empty root |

Pinned by `recon_kat::empty_window_then_first_drain_at_61` using
`last_empty = 60`, `first_drain = 61` — not interior heights that leave the
S2 off-by-one surface unasserted.

### Provenance baseline

| Field | Value |
|-------|-------|
| `fixture_bytes_commit` | `e0526f172` (original generation) |
| `audited_daemon_commit` | `5bfef7c06` (audit at Round 1 close-out) |
| `regen_required` | `false` |

**Audit:** consensus coinbase leaf inputs (`O`, `C`, `h_pqc` / `tx_extra 0x07`)
and header `curve_tree_root` rules are unchanged between `e0526f172` and
`5bfef7c06`. Intervening edits are wallet scan (FA-6), regular-tx payment-uri
labels, and Rust `build_layers` parity (`1dd62dfce`) — all verified by the
passing KAT at audit time. **Regenerate** `ct2_tier_a.json` only when consensus
leaf/root rules change (`gen_ct2_fixture.py` records provenance on regen).

---

## 2. Tier A obligation mapping (§8.2)

| §8.2 obligation | Test(s) | Notes |
|-----------------|---------|-------|
| S1/S2/S3 replication | `reconstructed_root_matches_consensus_at_every_height`, `reorg_prefix_and_freeze_lag_are_frozen` | All three chains (`main`, `reorg_deep`, `reorg_shallow`) |
| Empty-tree root | `empty_window_then_first_drain_at_61` | `selene_hash_init` through height 60; consensus anchors at 60 and 61 |
| Coinbase `+60` drain | Every-height KAT on `main` | One coinbase leaf per block |
| Undeepen vs consensus | Every-height KAT on **`reorg_deep` only** | Fork 140 ≫ deepen boundary ~99; shallow reorg does not exercise undeepen |
| Production client path | `client_reconstructs_consensus_root_at_every_height`, `client_path_matches_recon_path` | CT-3 client over same oracle |
| `R_k` content-addressing | *(corollary)* | Whole-root match + CT-0 deterministic composition ⇒ matching sub-roots under deterministic composition; ~150 drained leaves at tip exercise freeze |
| `tx_extra 0x07` parse (scanner) | `shekyl-scanner::extra::pqc_leaf_hashes_tests::*` | Scanner first-match; see §4 |
| `tx_extra 0x07` validate | `recon::extract_leaf_hashes` unit tests | Post-parse stage in `shekyl-curve-tree` |

---

## 3. Tier B deferred (reversion clause)

| Test (`recon_tier_b.rs`) | Blocked on |
|--------------------------|------------|
| `mixed_maturity_collision_orders_by_gindex` | 2A FCMP++ spend → `ct2_tier_b.json` |
| `multi_tx_block_respects_coinbase_first_and_tx_hashes_order` | same |
| `staked_output_uses_max_lock_and_spendable` | same |
| `reorg_with_spend_mixed_leaves` | same |
| `scanner_extra_0x07_matches_daemon_on_adversarial_extra` | C++ adversarial `0x07` oracle + Tier B fixture |

**Reopen when:** Phase 2A regtest can mint regular/staked outputs and append a
Tier B oracle. **Not a 2A gate:** bootstrap FCMP spend proves against
coinbase-only tree — exactly Tier A shape (`CT2_DRAIN_ORDER.md` §8.2 acyclicity).
**Tracked in [`FOLLOWUPS.md`](../FOLLOWUPS.md)** (V3.0, ordered after CT-5).

Tier B tests are `#[ignore]` with compile-time drift canaries — no fake passes.

---

## 4. Decode boundary

```
block JSON / wire
  → shekyl_scanner::extra::Extra::read
  → pqc_leaf_hashes()          // first 0x07 match (scanner)
  → CurveTreeClient::ingest_block(leaf_hash_blob)
  → recon::extract_leaf_hashes // %32 validate + per-output slice
  → construct_leaf / build_layers
```

**Duplicate `0x07`:** scanner returns the **first** parsed `PqcLeafHashes`
field. C++ `parse_tx_extra` retains all fields; consumers using
`find_tx_extra_field_by_type(..., index=0)` also take the first match — but
**daemon parity on duplicate/malformed tags is unverified** (no adversarial C++
test). Owned by Tier B `scanner_extra_0x07_matches_daemon_on_adversarial_extra`
once an oracle exists.

---

## 5. What Round 1 ungates for 2A

Bootstrap FCMP++ spend proves membership against a **coinbase-only** curve tree —
the Tier A fixture shape. Real-root path integration is **CT-5** (engine wiring),
not Round 1.

**Tier B ordering note (2026-06-11).** The §8.2 reversion criterion ("2A's
send path can mint a regular (and staked) output on a regtest fixture") is
**not** met by 2a-4's `TestDaemon` integration: that path uses synthetic
`TreeContext`/membership paths against a Rust mock, and a real regtest daemon
rejects synthetic proofs. Minting a real non-coinbase output requires real
local path assembly — i.e. **CT-3 (persistent sync,
[`CT3_SYNC.md`](./CT3_SYNC.md)) + CT-5 (engine wiring)** ahead of the Tier B
fixture, plus stake-tx minting for the staked case. Tier B therefore orders
**after** CT-5, exactly as the §8.2 acyclicity argument predicts; the
deferral remains bounded by the spend path, not gating it.

---

## 6. Explicitly not Round 1

- CT-1 `store` / `R_k` hot cache
- CT-3 bulk segment sync
- CT-5 `shekyl-engine-core` wiring
- Tier B fixture generation / un-ignoring tests
