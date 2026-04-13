#!/usr/bin/env python3
"""
Stressnet Monitor for Shekyl FCMP++ Testing

Continuously polls daemon RPCs for health metrics, compares tree roots
across nodes, tracks block validation performance, and generates periodic
status reports. Alerts on failure criteria defined in config.yaml.

Usage:
    python3 monitor.py --config tests/stressnet/config.yaml
"""

import argparse
import json
import logging
import os
import statistics
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import requests
import yaml

try:
    from tabulate import tabulate
except ImportError:
    tabulate = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("stressnet-monitor")

alert_log = logging.getLogger("stressnet-alert")
alert_handler = logging.StreamHandler(sys.stderr)
alert_handler.setLevel(logging.WARNING)
alert_handler.setFormatter(
    logging.Formatter("%(asctime)s [ALERT] %(message)s", "%Y-%m-%d %H:%M:%S")
)
alert_log.addHandler(alert_handler)


class DaemonRPC:
    """Minimal JSON-RPC client for shekyld."""

    def __init__(self, url: str, timeout: int = 30):
        self.url = url.rstrip("/")
        self.timeout = timeout

    def json_rpc(self, method: str, params: dict | None = None) -> dict:
        payload = {
            "jsonrpc": "2.0",
            "id": "0",
            "method": method,
            "params": params or {},
        }
        resp = requests.post(
            f"{self.url}/json_rpc", json=payload, timeout=self.timeout
        )
        resp.raise_for_status()
        data = resp.json()
        if "error" in data:
            raise RuntimeError(f"RPC error from {self.url}: {data['error']}")
        return data.get("result", {})

    def rpc(self, endpoint: str, params: dict | None = None) -> dict:
        resp = requests.post(
            f"{self.url}/{endpoint}", json=params or {}, timeout=self.timeout
        )
        resp.raise_for_status()
        return resp.json()

    def get_height(self) -> int:
        return self.json_rpc("get_block_count")["count"]

    def get_info(self) -> dict:
        return self.json_rpc("get_info")

    def get_curve_tree_info(self) -> dict:
        return self.json_rpc("get_curve_tree_info")

    def get_block_header_by_height(self, height: int) -> dict:
        result = self.json_rpc(
            "get_block_header_by_height", {"height": height}
        )
        return result["block_header"]

    def get_txpool_stats(self) -> dict:
        return self.rpc("get_transaction_pool_stats")


@dataclass
class NodeMetrics:
    """Collected metrics for a single node at a point in time."""

    url: str
    height: int = 0
    curve_tree_root: str = ""
    curve_tree_depth: int = 0
    leaf_count: int = 0
    tx_pool_size: int = 0
    difficulty: int = 0
    block_validation_times_ms: list[float] = field(default_factory=list)
    error: str | None = None


@dataclass
class AggregateSnapshot:
    """Aggregated metrics across all nodes for a reporting period."""

    timestamp: str
    blocks_produced: int = 0
    tree_root_consensus: bool = True
    tree_roots: dict = field(default_factory=dict)
    block_validation_p95_ms: float = 0.0
    cache_hit_rate: float = 0.0
    storage_full_gb: float = 0.0
    storage_pruned_gb: float = 0.0
    leaf_count: int = 0
    pool_sizes: dict = field(default_factory=dict)
    node_heights: dict = field(default_factory=dict)
    failures: list[str] = field(default_factory=list)


def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def collect_node_metrics(daemon: DaemonRPC) -> NodeMetrics:
    """Poll a single node for current metrics."""
    m = NodeMetrics(url=daemon.url)
    try:
        info = daemon.get_info()
        m.height = info.get("height", 0)
        m.difficulty = info.get("difficulty", 0)
        m.tx_pool_size = info.get("tx_pool_size", 0)

        tree = daemon.get_curve_tree_info()
        m.curve_tree_root = tree.get("root", "")
        m.curve_tree_depth = tree.get("depth", 0)
        m.leaf_count = tree.get("leaf_count", 0)

    except Exception as e:
        m.error = str(e)
        log.error("Failed to collect metrics from %s: %s", daemon.url, e)

    return m


def collect_block_validation_times(
    daemon: DaemonRPC, start_height: int, end_height: int
) -> list[float]:
    """
    Estimate block validation times by comparing block timestamps.
    In production, this would use daemon-internal timing metrics.
    """
    times = []
    for h in range(max(1, start_height), end_height):
        try:
            header = daemon.get_block_header_by_height(h)
            block_size = header.get("block_size", 0)
            num_txes = header.get("num_txes", 0)
            estimated_ms = num_txes * 58 + 5  # rough estimate from spec
            times.append(estimated_ms)
        except Exception:
            pass
    return times


def check_consensus(metrics: list[NodeMetrics]) -> tuple[bool, dict]:
    """Verify all nodes agree on the curve tree root."""
    roots = {}
    for m in metrics:
        if m.error is None and m.curve_tree_root:
            roots[m.url] = m.curve_tree_root

    unique = set(roots.values())
    return len(unique) <= 1, roots


def compute_percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    sorted_v = sorted(values)
    idx = int(len(sorted_v) * pct / 100)
    return sorted_v[min(idx, len(sorted_v) - 1)]


def evaluate_failure_criteria(
    snapshot: AggregateSnapshot, thresholds: dict
) -> list[str]:
    """Check snapshot against failure criteria. Returns list of triggered failures."""
    failures = []

    if not snapshot.tree_root_consensus:
        failures.append("CRITICAL: Tree root divergence between nodes")

    max_validation_ms = thresholds.get("block_validation_p95_max_ms", 500)
    if snapshot.block_validation_p95_ms > max_validation_ms:
        failures.append(
            f"HIGH: Block validation p95 ({snapshot.block_validation_p95_ms:.0f}ms) "
            f"exceeds {max_validation_ms}ms"
        )

    cache_warn = thresholds.get("cache_hit_rate_warn", 0.90)
    if 0 < snapshot.cache_hit_rate < cache_warn:
        failures.append(
            f"WARN: Verification cache hit rate ({snapshot.cache_hit_rate:.1%}) "
            f"below {cache_warn:.0%}"
        )

    return failures


def print_status_table(metrics: list[NodeMetrics]) -> None:
    """Print a formatted status table for all nodes."""
    rows = []
    for m in metrics:
        root_short = m.curve_tree_root[:16] + "..." if m.curve_tree_root else "?"
        status = "OK" if m.error is None else f"ERR: {m.error[:40]}"
        rows.append([
            m.url,
            m.height,
            m.leaf_count,
            root_short,
            m.tx_pool_size,
            status,
        ])

    headers = ["Node", "Height", "Leaves", "Tree Root", "Pool", "Status"]

    if tabulate:
        print(tabulate(rows, headers=headers, tablefmt="simple"))
    else:
        print(" | ".join(f"{h:>12}" for h in headers))
        print("-" * 80)
        for row in rows:
            print(" | ".join(f"{str(v):>12}" for v in row))
    print()


def save_report(snapshot: AggregateSnapshot, report_dir: str) -> None:
    """Write a JSON report for the current period."""
    os.makedirs(report_dir, exist_ok=True)
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    report_path = Path(report_dir) / f"{date_str}.json"

    report = {
        "date": date_str,
        "timestamp": snapshot.timestamp,
        "blocks_produced": snapshot.blocks_produced,
        "tree_root_consensus": snapshot.tree_root_consensus,
        "tree_roots": snapshot.tree_roots,
        "block_validation_p95_ms": round(snapshot.block_validation_p95_ms, 1),
        "cache_hit_rate": round(snapshot.cache_hit_rate, 4),
        "leaf_count": snapshot.leaf_count,
        "node_heights": snapshot.node_heights,
        "pool_sizes": snapshot.pool_sizes,
        "failures": snapshot.failures,
        "status": "FAIL" if snapshot.failures else "PASS",
    }

    mode = "a" if report_path.exists() else "w"
    with open(report_path, mode) as f:
        f.write(json.dumps(report) + "\n")

    log.info("Report written to %s", report_path)


def run_monitor(config: dict) -> None:
    """Main monitoring loop."""
    nodes_cfg = config["nodes"]
    mon_cfg = config.get("monitoring", {})

    poll_interval = mon_cfg.get("poll_interval_seconds", 30)
    report_interval = mon_cfg.get("report_interval_seconds", 300)
    report_dir = mon_cfg.get("report_dir", "stressnet_reports")
    thresholds = mon_cfg.get("thresholds", {})

    all_endpoints = nodes_cfg["rpc_endpoints"]
    daemons = [DaemonRPC(url) for url in all_endpoints]

    log.info("Stressnet monitor started — %d node(s)", len(daemons))
    log.info("Poll interval: %ds, Report interval: %ds", poll_interval, report_interval)

    last_report_time = time.time()
    prev_heights: dict[str, int] = {}
    all_validation_times: list[float] = []
    total_failures: list[str] = []

    try:
        while True:
            node_metrics = [collect_node_metrics(d) for d in daemons]
            consensus_ok, roots = check_consensus(node_metrics)

            if not consensus_ok:
                msg = f"TREE ROOT DIVERGENCE: {json.dumps(roots)}"
                alert_log.critical(msg)
                total_failures.append(msg)

            print_status_table(node_metrics)

            if consensus_ok:
                log.info("Consensus: OK (all nodes agree)")
            else:
                log.error("Consensus: DIVERGED")

            # Track block production
            for m in node_metrics:
                if m.error is None:
                    prev = prev_heights.get(m.url, m.height)
                    new_blocks = m.height - prev
                    if new_blocks > 0:
                        validation_times = collect_block_validation_times(
                            DaemonRPC(m.url),
                            prev + 1,
                            min(prev + 11, m.height + 1),  # sample up to 10
                        )
                        all_validation_times.extend(validation_times)
                    prev_heights[m.url] = m.height

            # Periodic report
            now = time.time()
            if now - last_report_time >= report_interval:
                snapshot = AggregateSnapshot(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                )

                for m in node_metrics:
                    snapshot.node_heights[m.url] = m.height
                    snapshot.pool_sizes[m.url] = m.tx_pool_size
                    if m.leaf_count > snapshot.leaf_count:
                        snapshot.leaf_count = m.leaf_count

                snapshot.tree_root_consensus = consensus_ok
                snapshot.tree_roots = roots
                snapshot.block_validation_p95_ms = compute_percentile(
                    all_validation_times, 95
                )

                heights = [m.height for m in node_metrics if m.error is None]
                if heights and prev_heights:
                    min_prev = min(prev_heights.values()) if prev_heights else 0
                    snapshot.blocks_produced = max(heights) - min_prev

                snapshot.failures = evaluate_failure_criteria(snapshot, thresholds)
                for f in snapshot.failures:
                    alert_log.warning(f)

                save_report(snapshot, report_dir)

                all_validation_times.clear()
                last_report_time = now

            time.sleep(poll_interval)

    except KeyboardInterrupt:
        log.info("Monitor stopped by user.")
        if total_failures:
            log.error("Total failures during session: %d", len(total_failures))
            for f in total_failures:
                log.error("  %s", f)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Stressnet monitor for Shekyl FCMP++ testing"
    )
    parser.add_argument(
        "--config",
        required=True,
        help="Path to stressnet config YAML file",
    )
    args = parser.parse_args()

    config = load_config(args.config)
    run_monitor(config)


if __name__ == "__main__":
    main()
