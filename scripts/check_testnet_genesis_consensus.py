#!/usr/bin/env python3

import argparse
import json
import sys
import urllib.error
import urllib.request


def rpc_call(base_url: str, method: str, params: dict):
    payload = {
        "jsonrpc": "2.0",
        "id": "0",
        "method": method,
        "params": params,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        base_url.rstrip("/") + "/json_rpc",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=8) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    if "error" in body:
        raise RuntimeError(f"RPC error from {base_url}: {body['error']}")
    return body.get("result", {})


def get_genesis_tuple(base_url: str):
    header = rpc_call(base_url, "get_block_header_by_height", {"height": 0})
    block_header = header.get("block_header", {})
    txs = rpc_call(base_url, "get_transactions", {"txs_hashes": [block_header.get("miner_tx_hash")]})
    if not txs.get("txs_as_hex"):
        raise RuntimeError(f"{base_url}: could not fetch genesis miner tx hex")
    return {
        "url": base_url,
        "height0_hash": block_header.get("hash"),
        "height0_miner_tx_hash": block_header.get("miner_tx_hash"),
        "height0_reward": block_header.get("reward"),
        "height0_tx_hex": txs["txs_as_hex"][0],
    }


def get_info_fields(base_url: str):
    info = rpc_call(base_url, "get_info", {})
    keys = [
        "release_multiplier",
        "burn_pct",
        "stake_ratio",
        "staker_pool_balance",
        "staker_emission_share_effective",
        "total_burned",
    ]
    return {k: info.get(k) for k in keys}


def main():
    parser = argparse.ArgumentParser(
        description="Verify testnet genesis consensus and economy RPC field presence across nodes."
    )
    parser.add_argument(
        "--rpc",
        action="append",
        required=True,
        help="Base RPC URL, e.g. http://127.0.0.1:12029 (repeat for multiple nodes)",
    )
    parser.add_argument(
        "--check-economy",
        action="store_true",
        help="Also verify economy fields exist in get_info on each node.",
    )
    args = parser.parse_args()

    if len(args.rpc) < 2:
        print("Need at least two --rpc endpoints for consensus comparison.", file=sys.stderr)
        return 2

    tuples = []
    try:
        for url in args.rpc:
            tuples.append(get_genesis_tuple(url))
    except (urllib.error.URLError, RuntimeError, KeyError, ValueError) as e:
        print(f"ERROR: failed to query RPC: {e}", file=sys.stderr)
        return 2

    ref = tuples[0]
    failed = False
    for t in tuples[1:]:
        if t["height0_hash"] != ref["height0_hash"]:
            print(
                f"MISMATCH: height 0 block hash differs\n"
                f"  ref {ref['url']}: {ref['height0_hash']}\n"
                f"  got {t['url']}: {t['height0_hash']}",
                file=sys.stderr,
            )
            failed = True
        if t["height0_miner_tx_hash"] != ref["height0_miner_tx_hash"]:
            print(
                f"MISMATCH: height 0 miner tx hash differs\n"
                f"  ref {ref['url']}: {ref['height0_miner_tx_hash']}\n"
                f"  got {t['url']}: {t['height0_miner_tx_hash']}",
                file=sys.stderr,
            )
            failed = True
        if t["height0_tx_hex"] != ref["height0_tx_hex"]:
            print(
                f"MISMATCH: height 0 miner tx hex differs between {ref['url']} and {t['url']}",
                file=sys.stderr,
            )
            failed = True

    if args.check_economy:
        required = {
            "release_multiplier",
            "burn_pct",
            "stake_ratio",
            "staker_pool_balance",
            "staker_emission_share_effective",
            "total_burned",
        }
        for url in args.rpc:
            try:
                fields = get_info_fields(url)
            except (urllib.error.URLError, RuntimeError, ValueError) as e:
                print(f"ERROR: get_info failed for {url}: {e}", file=sys.stderr)
                failed = True
                continue
            missing = [k for k in required if fields.get(k) is None]
            if missing:
                print(f"MISMATCH: {url} missing economy fields in get_info: {missing}", file=sys.stderr)
                failed = True

    print("Checked endpoints:")
    for t in tuples:
        print(
            f"- {t['url']}  h0={t['height0_hash']}  miner_tx={t['height0_miner_tx_hash']}"
        )

    if failed:
        print("FAIL: testnet consensus/economy checks failed.", file=sys.stderr)
        return 1
    print("PASS: all compared nodes agree on genesis tuple.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
