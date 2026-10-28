#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Capture one JSON file per RPC request, raw as the daemon answered.
# The flip leg runs this same tool against the flip binary. A row that
# is not sent is named in the omitted list with a reason.

import argparse
import json
import os
import urllib.error
import urllib.request

# Whole replies that are not a chain fact. Volatile fields inside a
# captured reply are named separately, in volatile_fields().
OMITTED = (
    ("get_connections", "nondeterministic: the live peer sockets"),
    ("sync_info", "nondeterministic: peer and sync timing"),
    ("/get_peer_list", "nondeterministic: the peer list"),
    ("/get_net_stats", "nondeterministic: counters"),
    ("generateblocks", "write lever: mining would extend the fixture"),
    ("/pop_blocks", "write lever: a pop would shorten the fixture"),
    ("submit_block", "write lever: a submit would extend the fixture"),
    ("/submit_transaction", "write lever: a submit would change the pool"),
    ("/start_mining", "write lever"),
    ("/stop_mining", "write lever"),
    ("flush_txpool", "write lever"),
    ("flush_cache", "write lever"),
    ("set_bans", "write lever"),
    ("/stop_daemon", "write lever: it stops the daemon"),
    ("/save_bc", "write lever"),
    ("option_set", "write lever"),
    ("relay_tx", "write lever"),
    ("inject_archival_serve_credit", "write lever, and armed"),
    ("/set_log_hash_rate", "write lever"),
)


def volatile_fields():
    """Fields that differ run to run on the same chain.

    The register filters these by name. The replies that carry them are
    still captured.
    """
    return (
        "get_info.adjusted_time",
        "get_info.start_time",
        "get_info.rpc_connections_count",
        "/get_info.adjusted_time",
        "/get_info.start_time",
    )


def chain_requests(tip_height, tip_hash, genesis_hash, tx_hash=None):
    """The chain reads, with the heights and hashes filled in.

    `tip_height` is the daemon's reported height (one past the last
    block). The tip block is at `tip_height - 1`.
    """
    if tip_height < 1:
        raise ValueError(f"tip height {tip_height} is not a chain")
    tip_block = tip_height - 1
    past = tip_height + 10
    unknown = "ff" * 32
    reqs = [
        ("get_block_count", {}),
        ("get_last_block_header", {}),
        ("get_block_header_by_height", {"height": 0}),
        ("get_block_header_by_height", {"height": tip_block}),
        ("get_block_header_by_height", {"height": past}),
        ("get_block", {"height": 0}),
        ("get_block", {"height": tip_block}),
        ("get_block", {"height": past}),
        ("get_block_header_by_hash", {"hash": genesis_hash}),
        ("get_block_header_by_hash", {"hash": tip_hash}),
        ("get_block_header_by_hash", {"hash": unknown}),
        ("on_get_block_hash", {"height": tip_block}),
        ("get_block_headers_range", {"start_height": 0, "end_height": min(2, tip_block)}),
        ("get_fee_estimate", {}),
        ("get_info", {}),
        ("get_version", {}),
        ("get_coinbase_tx_sum", {"height": 0, "count": 1}),
        ("get_alternate_chains", {}),
        ("get_curve_tree_info", {}),
        ("get_txpool_backlog", {}),
    ]
    if tx_hash:
        reqs.append(("get_transactions", {"txs_hashes": [tx_hash], "decode_as_json": False}))
    else:
        reqs.append(("get_transactions", None))  # omitted at plan time: no tx in hand
    out = []
    for method, params in reqs:
        if params is None:
            continue
        out.append({"kind": "json", "method": method, "params": params})
    return out


def _post(url, body, timeout):
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as err:
        raw = err.read()
    return json.loads(raw.decode())


def capture(base_url, requests, out_dir, timeout=60):
    """Write one file per request. Returns the number written."""
    os.makedirs(out_dir, exist_ok=True)
    base = base_url.rstrip("/")
    n = 0
    for i, item in enumerate(requests):
        kind = item["kind"]
        method = item["method"]
        params = item.get("params", {})
        if kind == "json":
            url = base + "/json_rpc"
            body = {"jsonrpc": "2.0", "id": "0", "method": method, "params": params}
        elif kind == "rest":
            url = base + method
            body = params
        else:
            raise ValueError(f"request {i} kind {kind!r} is not json or rest")
        response = _post(url, body, timeout)
        record = {"method": method, "params": params, "response": response}
        name = f"{i:03d}-{method.strip('/').replace('/', '_')}.json"
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(record, fh, indent=2)
            fh.write("\n")
        n += 1
    with open(os.path.join(out_dir, "omitted.json"), "w", encoding="utf-8") as fh:
        json.dump([{"method": m, "reason": r} for m, r in OMITTED], fh, indent=2)
        fh.write("\n")
    with open(os.path.join(out_dir, "volatile_fields.json"), "w", encoding="utf-8") as fh:
        json.dump(list(volatile_fields()), fh, indent=2)
        fh.write("\n")
    return n


def main():
    ap = argparse.ArgumentParser(description="Capture raw RPC replies")
    ap.add_argument("--url", required=True, help="daemon RPC base, no path")
    ap.add_argument("--requests", required=True, help="JSON list of requests")
    ap.add_argument("--out", required=True)
    ap.add_argument("--timeout", type=float, default=60)
    args = ap.parse_args()
    with open(args.requests, encoding="utf-8") as fh:
        requests = json.load(fh)
    if not requests:
        raise SystemExit("the request list is empty")
    n = capture(args.url, requests, args.out, args.timeout)
    print(f"wrote {n} replies to {args.out}")


if __name__ == "__main__":
    main()
