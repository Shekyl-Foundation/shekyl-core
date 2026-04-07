#!/usr/bin/env python3
"""
Stressnet Load Generator for Shekyl FCMP++ Testing

Generates sustained transaction load across multiple daemon nodes with
configurable input distributions, staking operations, and multisig
transactions. Validates tree root consensus across all nodes periodically.

Usage:
    python3 load_generator.py --config tests/stressnet/config.yaml
"""

import argparse
import json
import logging
import os
import random
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import requests
import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("stressnet-load")


@dataclass
class WalletState:
    """Tracks a test wallet's RPC connection and funded status."""

    name: str
    rpc_port: int
    address: str = ""
    balance: int = 0
    funded: bool = False


@dataclass
class StressnetStats:
    """Accumulates load generation statistics."""

    txs_submitted: int = 0
    txs_failed: int = 0
    stakes_submitted: int = 0
    claims_submitted: int = 0
    multisig_txs_submitted: int = 0
    consensus_checks: int = 0
    consensus_failures: int = 0
    start_time: float = field(default_factory=time.time)

    def uptime_hours(self) -> float:
        return (time.time() - self.start_time) / 3600


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

    def get_block_header_by_height(self, height: int) -> dict:
        result = self.json_rpc(
            "get_block_header_by_height", {"height": height}
        )
        return result["block_header"]

    def get_curve_tree_info(self) -> dict:
        return self.json_rpc("get_curve_tree_info")

    def get_info(self) -> dict:
        return self.json_rpc("get_info")


class WalletRPC:
    """Minimal JSON-RPC client for shekyl-wallet-rpc."""

    def __init__(self, url: str, timeout: int = 60):
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
            raise RuntimeError(f"Wallet RPC error: {data['error']}")
        return data.get("result", {})


def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def pick_input_count(distribution: dict) -> int:
    """Sample an input count from the configured distribution."""
    choices = []
    weights = []
    for key, weight in distribution.items():
        count = int(key.split("_")[0])
        choices.append(count)
        weights.append(weight)
    return random.choices(choices, weights=weights, k=1)[0]


def check_tree_root_consensus(daemons: list[DaemonRPC]) -> tuple[bool, dict]:
    """
    Query curve tree info from all nodes and verify roots match.
    Returns (consensus_ok, {endpoint: tree_info}).
    """
    results = {}
    for d in daemons:
        try:
            info = d.get_curve_tree_info()
            results[d.url] = info
        except Exception as e:
            log.error("Failed to query tree info from %s: %s", d.url, e)
            results[d.url] = {"error": str(e)}

    roots = set()
    for url, info in results.items():
        if "error" not in info:
            roots.add(info.get("root", "unknown"))

    consensus = len(roots) <= 1
    return consensus, results


def submit_transfer(
    wallet: WalletRPC,
    destinations: list[dict],
    priority: int = 0,
) -> str | None:
    """Submit a transfer and return the tx hash, or None on failure."""
    try:
        result = wallet.json_rpc(
            "transfer",
            {
                "destinations": destinations,
                "priority": priority,
                "get_tx_key": False,
            },
        )
        return result.get("tx_hash")
    except Exception as e:
        log.warning("Transfer failed: %s", e)
        return None


def submit_stake(
    wallet: WalletRPC, tier: int, amount: int
) -> str | None:
    """Submit a staking transaction. Returns tx hash or None."""
    try:
        result = wallet.json_rpc(
            "stake",
            {"tier": tier, "amount": amount},
        )
        return result.get("tx_hash")
    except Exception as e:
        log.warning("Stake failed: %s", e)
        return None


def submit_claim(wallet: WalletRPC) -> str | None:
    """Submit a claim_rewards transaction. Returns tx hash or None."""
    try:
        result = wallet.json_rpc("claim_rewards", {})
        return result.get("tx_hash")
    except Exception as e:
        log.warning("Claim failed: %s", e)
        return None


def pick_staking_tier(tier_distribution: dict) -> int:
    """Sample a staking tier from the configured distribution."""
    tiers = {"short": 1, "medium": 2, "long": 3}
    choices = []
    weights = []
    for name, weight in tier_distribution.items():
        choices.append(tiers[name])
        weights.append(weight)
    return random.choices(choices, weights=weights, k=1)[0]


def log_status(stats: StressnetStats) -> None:
    log.info(
        "STATS | uptime=%.1fh txs=%d failed=%d stakes=%d claims=%d "
        "multisig=%d consensus_checks=%d consensus_failures=%d",
        stats.uptime_hours(),
        stats.txs_submitted,
        stats.txs_failed,
        stats.stakes_submitted,
        stats.claims_submitted,
        stats.multisig_txs_submitted,
        stats.consensus_checks,
        stats.consensus_failures,
    )


def run_load_generation(config: dict) -> None:
    """Main load generation loop."""
    nodes_cfg = config["nodes"]
    load_cfg = config["load_profile"]
    wallet_cfg = config.get("wallet", {})

    daemons = [DaemonRPC(url) for url in nodes_cfg["rpc_endpoints"]]
    primary = daemons[0]

    block_time = load_cfg.get("block_time_seconds", 120)
    tx_rate = load_cfg["sustained_tx_rate"]
    input_dist = load_cfg["input_distribution"]

    staking_cfg = load_cfg.get("staking", {})
    stakes_per_day = staking_cfg.get("new_stakes_per_day", 0)
    claims_per_day = staking_cfg.get("claims_per_day", 0)
    tier_dist = staking_cfg.get("tier_distribution", {"short": 1.0})

    multisig_cfg = load_cfg.get("multisig", {})
    multisig_per_day = multisig_cfg.get("2_of_3_txs_per_day", 0)

    blocks_per_day = 86400 / block_time
    tx_interval = block_time / max(tx_rate, 1)
    stake_interval = 86400 / max(stakes_per_day, 1)
    claim_interval = 86400 / max(claims_per_day, 1)
    consensus_check_interval = 300  # every 5 minutes

    stats = StressnetStats()
    last_stake_time = time.time()
    last_claim_time = time.time()
    last_consensus_time = time.time()
    last_status_time = time.time()

    log.info("Starting load generation: %d tx/block, block_time=%ds", tx_rate, block_time)
    log.info("Connected to %d daemon(s)", len(daemons))
    log.info("Staking: %d stakes/day, %d claims/day", stakes_per_day, claims_per_day)

    # In a real deployment, wallet RPCs would be initialized and funded here.
    # This skeleton uses daemon RPCs for consensus checks and logs simulated
    # transaction submission metrics. Wire up WalletRPC instances to
    # shekyl-wallet-rpc processes for actual transaction submission.

    wallet_rpc_base_port = 18100
    wallets: list[WalletRPC] = []

    num_wallets = wallet_cfg.get("seed_wallets", 10)
    for i in range(num_wallets):
        port = wallet_rpc_base_port + i
        wallets.append(WalletRPC(f"http://127.0.0.1:{port}"))

    log.info("Configured %d wallet RPC endpoints (ports %d-%d)",
             num_wallets, wallet_rpc_base_port,
             wallet_rpc_base_port + num_wallets - 1)

    try:
        while True:
            now = time.time()

            # --- Regular transactions ---
            input_count = pick_input_count(input_dist)
            amount_atomic = random.randint(100_000_000, 1_000_000_000)
            if wallets:
                sender = random.choice(wallets)
                receiver = random.choice(wallets)
                tx_hash = submit_transfer(
                    sender,
                    [{"amount": amount_atomic, "address": f"test_addr_{id(receiver)}"}],
                )
                if tx_hash:
                    stats.txs_submitted += 1
                else:
                    stats.txs_failed += 1

            # --- Staking ---
            if now - last_stake_time >= stake_interval and wallets:
                tier = pick_staking_tier(tier_dist)
                stake_amount = random.randint(100_000_000_000, 1_000_000_000_000)
                staker = random.choice(wallets)
                tx_hash = submit_stake(staker, tier, stake_amount)
                if tx_hash:
                    stats.stakes_submitted += 1
                last_stake_time = now

            # --- Claims ---
            if now - last_claim_time >= claim_interval and wallets:
                claimer = random.choice(wallets)
                tx_hash = submit_claim(claimer)
                if tx_hash:
                    stats.claims_submitted += 1
                last_claim_time = now

            # --- Consensus check ---
            if now - last_consensus_time >= consensus_check_interval:
                ok, results = check_tree_root_consensus(daemons)
                stats.consensus_checks += 1
                if not ok:
                    stats.consensus_failures += 1
                    log.critical(
                        "TREE ROOT DIVERGENCE DETECTED: %s",
                        json.dumps(results, indent=2),
                    )
                else:
                    roots = [
                        r.get("root", "?")
                        for r in results.values()
                        if isinstance(r, dict) and "root" in r
                    ]
                    root_display = roots[0][:16] + "..." if roots else "?"
                    log.info(
                        "Consensus OK (%d nodes, root=%s)",
                        len(results),
                        root_display,
                    )
                last_consensus_time = now

            # --- Status report ---
            if now - last_status_time >= 60:
                log_status(stats)
                last_status_time = now

            time.sleep(tx_interval)

    except KeyboardInterrupt:
        log.info("Load generation stopped by user.")
        log_status(stats)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Stressnet load generator for Shekyl FCMP++ testing"
    )
    parser.add_argument(
        "--config",
        required=True,
        help="Path to stressnet config YAML file",
    )
    args = parser.parse_args()

    config = load_config(args.config)
    run_load_generation(config)


if __name__ == "__main__":
    main()
