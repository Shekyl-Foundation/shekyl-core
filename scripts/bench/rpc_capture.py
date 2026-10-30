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
import base64
import json
import os
import socket
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
    ("calc_pow", "computes a proof-of-work hash for a supplied blob; not a fact of the stored chain"),
    ("get_block_template", "needs a wallet address; a template is not a fact of the stored chain"),
    ("banned", "needs a peer address; the fixture has no ban to ask about"),
    ("request_archival_shard", "asks the node to fetch a shard"),
    ("/get_blocks_by_height.bin", "request body is portable_storage, not JSON"),
    ("/getblocks_by_height.bin", "alias of /get_blocks_by_height.bin; binary, not JSON"),
    ("/get_o_indexes.bin", "request body is portable_storage, not JSON"),
    ("/json_rpc", "the endpoint the JSON methods are posted to, not a method"),
    ("getblockcount", "alias of get_block_count"),
    ("on_getblockhash", "alias of on_get_block_hash"),
    ("getblockheaderbyheight", "alias of get_block_header_by_height"),
    ("getblock", "alias of get_block"),
    ("getlastblockheader", "alias of get_last_block_header"),
    ("getblockheaderbyhash", "alias of get_block_header_by_hash"),
    ("getblockheadersrange", "alias of get_block_headers_range"),
    ("submitblock", "alias of submit_block"),
    ("getblocktemplate", "alias of get_block_template"),
    ("/getheight", "alias of /get_height"),
    ("/gettransactions", "alias of /get_transactions"),
    ("/getinfo", "alias of /get_info"),
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
        "get_info.free_space",
        "/get_info.adjusted_time",
        "/get_info.start_time",
        "/get_info.rpc_connections_count",
        "/get_info.free_space",
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
        ("get_block_header_by_hash", {"hashes": [genesis_hash]}),
        ("get_block_header_by_hash", {"hashes": [tip_hash]}),
        ("get_block_header_by_hash", {"hashes": [unknown]}),
        ("on_get_block_hash", [tip_block]),
        ("get_block_headers_range", {"start_height": 0, "end_height": min(2, tip_block)}),
        ("get_fee_estimate", {}),
        ("get_info", {}),
        ("get_version", {}),
        ("get_coinbase_tx_sum", {"height": 0, "count": 1}),
        ("get_alternate_chains", {}),
        ("get_curve_tree_info", {}),
        ("get_curve_tree_checkpoint", {"block_height": 0}),
        ("get_curve_tree_checkpoint", {"block_height": tip_block}),
        ("get_txpool_backlog", {}),
        ("get_archival_shard_coverage", {}),
        ("get_archival_emission_claim_source", {"p_id": "00" * 32}),
        ("option_show", {}),
        ("get_miner_data", {}),
        ("get_bans", {}),
    ]
    rest = [
        ("/get_height", {}),
        ("/get_alt_blocks_hashes", {}),
        ("/get_transaction_pool", {}),
        ("/get_transaction_pool_hashes", {}),
        ("/get_transaction_pool_stats", {}),
        ("/get_info", {}),
        ("/mining_status", {}),
        ("/get_stem_tallies", {}),
        ("/is_key_image_spent", {"key_images": ["00" * 32]}),
    ]
    if tx_hash:
        rest.append(("/get_transactions", {
            "txs_hashes": [tx_hash], "decode_as_json": False}))
    out = [{"kind": "json", "method": method, "params": params} for method, params in reqs]
    out.extend({"kind": "rest", "method": method, "params": params} for method, params in rest)
    return out


def reserve_loopback_ports(n):
    """Bind `n` loopback sockets to port 0 and return `(ports, sockets)`.

    The sockets stay open so the kernel cannot hand the same ephemeral
    port out again before the caller has all of them. The caller closes
    them before a daemon binds. A foreign process can still take a port
    in that gap; the spawn's console log is where that shows up.

    The bench reserves four ports the same way, for two daemons. This
    holds the one admin port the kept-chain capture binds. View listen
    is not reserved: it defaults to none, and the column does not use it.
    """
    if isinstance(n, bool) or not isinstance(n, int) or n < 1:
        raise ValueError(f"port count {n!r} is not a positive count")
    socks = [socket.socket() for _ in range(n)]
    try:
        for sk in socks:
            sk.bind(("127.0.0.1", 0))
        ports = [sk.getsockname()[1] for sk in socks]
    except OSError:
        for sk in socks:
            sk.close()
        raise
    if len(set(ports)) != n:
        for sk in socks:
            sk.close()
        raise RuntimeError(f"port reservation collided: {ports}")
    return ports, socks


def json_rpc(base_url, method, params=None, timeout=60):
    """One JSON-RPC call against `base_url`.

    `params` is the daemon's params value: an object, or a positional
    list (`on_get_block_hash`). None is an empty object, which is what
    a method with no arguments takes. An empty list stays a list.
    """
    if params is None:
        params = {}
    url = base_url.rstrip("/") + "/json_rpc"
    body = {"jsonrpc": "2.0", "id": "0", "method": method, "params": params}
    return _post(url, body, timeout)


def _post(url, body, timeout):
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as err:
        raw = err.read()
    try:
        return json.loads(raw.decode())
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"unparsed": True, "raw_base64": base64.b64encode(raw).decode("ascii")}


def capture(base_url, requests, out_dir, timeout=60):
    """Write one file per request. Returns the number written."""
    os.makedirs(out_dir, exist_ok=True)
    base = base_url.rstrip("/")
    n = 0
    for i, item in enumerate(requests):
        kind = item["kind"]
        method = item["method"]
        params = item.get("params", {})
        try:
            if kind == "json":
                response = json_rpc(base, method, params, timeout)
            elif kind == "rest":
                response = _post(base + method, params, timeout)
            else:
                raise ValueError(f"request {i} kind {kind!r} is not json or rest")
        except (urllib.error.URLError, TimeoutError, OSError) as err:
            response = {"capture_error": str(err)}
        record = {"method": method, "params": params, "response": response}
        name = f"{i:03d}-{method.strip('/').replace('/', '_')}.json"
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(record, fh, indent=2)
            fh.write("\n")
        n += 1
    omitted = [{"method": m, "reason": r} for m, r in OMITTED]
    if not any(item["method"] == "/get_transactions" for item in requests):
        omitted.append({
            "method": "/get_transactions",
            "reason": "this fixture's capture was given no transaction id",
        })
    with open(os.path.join(out_dir, "omitted.json"), "w", encoding="utf-8") as fh:
        json.dump(omitted, fh, indent=2)
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
