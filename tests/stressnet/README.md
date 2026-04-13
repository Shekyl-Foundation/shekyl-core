# Stressnet — 4-Week Sustained-Load Testnet

> **Pre-audit gate for FCMP++ mainnet readiness.**
>
> The stressnet must run for 4 consecutive weeks with zero failure criteria
> triggered before the codebase is submitted for the 4-scalar leaf circuit
> security audit (see `docs/AUDIT_SCOPE.md`).

---

## Overview

The stressnet is a multi-node testnet running under sustained synthetic load
that exercises every FCMP++ code path under realistic (and adversarial)
conditions. It validates:

- Curve tree growth, consensus, and checkpoint integrity
- Verification caching under continuous throughput
- Wallet restore-from-seed correctness after extended chain growth
- Pruned vs. full node storage divergence
- Staking lifecycle (stake → accrue → claim → re-stake)
- Block validation latency under near-block-weight-limit transactions

---

## Prerequisites

- `shekyld` binary built from the same commit on all nodes
- Python 3.10+ with `requests`, `pyyaml`, `tabulate` (`pip install requests pyyaml tabulate`)
- Network connectivity between all nodes (testnet ports `12021`, RPC `12029`)
- Empty testnet datadirs on every node
- Funded test wallets (the load generator bootstraps these automatically)

---

## Node Topology

| Node       | Type           | Purpose                                |
|------------|----------------|----------------------------------------|
| node-1     | Full archival  | Reference node, RPC endpoint           |
| node-2     | Full archival  | Consensus cross-check                  |
| node-3     | Full archival  | Consensus cross-check                  |
| node-4     | Pruned         | Storage delta measurement              |
| node-5     | Pruned         | Pruning integrity verification         |

All nodes run in `--testnet` mode. Archival nodes use `--no-prune`.
Pruned nodes use `--prune-blockchain`.

---

## Launching the Stressnet

### 1. Start the nodes

```bash
# On each machine (adjust peer addresses):
shekyld --testnet --no-igd --confirm-external-bind \
  --add-peer=NODE1_IP:12021 --add-peer=NODE2_IP:12021 \
  --rpc-bind-ip=0.0.0.0 --rpc-bind-port=12029
```

For pruned nodes, add `--prune-blockchain`.

### 2. Verify genesis consensus

```bash
python3 scripts/check_testnet_genesis_consensus.py \
  --rpc http://NODE1:12029 \
  --rpc http://NODE2:12029 \
  --rpc http://NODE3:12029 \
  --rpc http://NODE4:12029 \
  --rpc http://NODE5:12029
```

All nodes must report identical block 0 hash and miner tx hash.

### 3. Start the load generator

```bash
python3 tests/stressnet/load_generator.py \
  --config tests/stressnet/config.yaml
```

The generator will:
1. Create and fund test wallets on node-1
2. Begin submitting transactions at the configured rate
3. Periodically submit staking and claim transactions
4. Log status every 60 seconds

### 4. Start the monitor

```bash
python3 tests/stressnet/monitor.py \
  --config tests/stressnet/config.yaml
```

The monitor runs continuously, polling metrics and printing a status table
every 5 minutes. It writes alerts to stderr and periodic reports to
`stressnet_reports/`.

---

## Monitoring Metrics

| Metric                              | Target              | Alert threshold         |
|-------------------------------------|----------------------|-------------------------|
| Tree growth (outputs/day)           | Informational        | N/A                     |
| Tree growth (storage/day)           | Informational        | N/A                     |
| Pruned vs. full storage delta       | Informational        | >50% divergence         |
| Verification cache hit rate         | >95%                 | <90%                    |
| Proof generation latency p95        | <5s (precomputed)    | >10s                    |
| Block validation time p95           | <500ms               | >500ms (FAILURE)        |
| Wallet precomputation freshness     | <10 blocks stale     | >20 blocks stale        |
| Tree root consensus divergences     | 0                    | >0 (FAILURE)            |
| Reference block rejection rate      | <1%                  | >5%                     |
| Restore-from-seed correctness       | 100%                 | <100% (FAILURE)         |
| Checkpoint pruning integrity        | Consistent           | Any inconsistency       |

---

## Success Criteria

The stressnet passes when ALL of the following hold for 4 consecutive weeks:

1. **Zero tree root divergences** between any pair of nodes
2. **Block validation p95 < 500ms** across all archival nodes
3. **Verification cache hit rate > 95%** on nodes processing mempool txs
4. **Wallet restore-from-seed** produces identical key images and balances
   on a fresh node after full sync
5. **Checkpoint pruning** does not corrupt the tree — a pruned node can still
   serve correct `get_curve_tree_path` responses for recent outputs
6. **No unrecoverable node crashes** — any crash must be followed by
   automatic recovery without manual database surgery
7. **Staking lifecycle** completes at least 100 full cycles (stake → mature
   → claim → re-stake)

---

## Failure Criteria (Stop-Fix Triggers)

If any of the following occur, **stop the stressnet**, fix the issue,
and restart the 4-week clock:

| Failure                                  | Severity | Action                            |
|------------------------------------------|----------|-----------------------------------|
| Tree root divergence between nodes       | CRITICAL | Stop all nodes. Diff DB states.   |
| Block validation p95 > 500ms             | HIGH     | Profile and optimize hot path.    |
| Verification cache corruption            | HIGH     | Audit cache invalidation logic.   |
| Wallet restore key mismatch              | CRITICAL | Debug PQC key derivation chain.   |
| Node unable to sync from scratch         | HIGH     | Check checkpoint / bootstrap path.|
| Pruned node serves incorrect tree paths  | HIGH     | Audit pruning boundary logic.     |
| Unrecoverable LMDB corruption            | CRITICAL | Review all DB write transactions. |

---

## Report Format

The monitor generates daily reports in `stressnet_reports/YYYY-MM-DD.json`:

```json
{
  "date": "2026-04-04",
  "uptime_hours": 24,
  "blocks_produced": 720,
  "transactions_submitted": 18000,
  "tree_root_divergences": 0,
  "block_validation_p95_ms": 312,
  "cache_hit_rate": 0.973,
  "storage_full_gb": 2.4,
  "storage_pruned_gb": 1.1,
  "staking_cycles_completed": 5,
  "status": "PASS"
}
```

---

## After the Stressnet

Once the 4-week gate passes:

1. Archive all daily reports and node logs
2. Generate a summary report with aggregate statistics
3. Include the summary in the audit materials package (`docs/AUDIT_SCOPE.md`)
4. Proceed to security audit engagement

---

## Related Documents

- `docs/AUDIT_SCOPE.md` — Security audit scope (Phase 9)
- `docs/FCMP_PLUS_PLUS.md` — FCMP++ specification
- `docs/RELEASE_CHECKLIST.md` — Mainnet release gates
- `shekyl-dev/docs/TESTNET_REHEARSAL_CHECKLIST.md` — Testnet rehearsal runbook
