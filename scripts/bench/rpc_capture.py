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

# Whole replies that are not a chain fact: every row of the daemon's
# method table (`docs/generated/rpc_wire_schema.tsv`) is either asked by
# chain_requests() or named here with its reason. Volatile fields inside a
# captured reply are named separately, in volatile_fields().
OMITTED = (
    ("peer_connections", "nondeterministic: the live peer sockets"),
    ("sync_status", "nondeterministic: peer and sync timing"),
    ("peer_list", "nondeterministic: the peer list"),
    ("p2p_stats", "nondeterministic: counters"),
    ("dev_block_generate", "write lever: mining would extend the fixture"),
    ("dev_chain_pop", "write lever: a pop would shorten the fixture"),
    ("block_submit", "write lever: a submit would extend the fixture"),
    ("tx_submit", "write lever: a submit would change the pool"),
    ("mine_start", "write lever"),
    ("mine_stop", "write lever"),
    ("txpool_flush", "write lever"),
    ("tx_relay", "write lever"),
    ("ban_add", "write lever"),
    ("ban_remove", "write lever"),
    ("daemon_stop", "write lever: it stops the daemon"),
    ("option_set", "write lever"),
    ("pow", "computes a proof-of-work hash for supplied bytes; not a fact of the stored chain"),
    ("ban_show", "needs a host; the fixture has no ban to ask about"),
    ("shard_fetch", "asks the node to fetch a shard"),
)


def volatile_fields():
    """Fields that differ run to run on the same chain.

    The register filters these by name. The replies that carry them are
    still captured.
    """
    return (
        "daemon_status.time_adjusted",
        "daemon_status.started",
        "daemon_status.rpc_connections",
        "daemon_status.disk_free",
    )


def chain_requests(tip_height, tip_hash, genesis_hash, tx_hash=None):
    """The chain reads, with the heights and hashes filled in.

    `tip_height` is the tip's height, an ordinal: the tip block is at
    `tip_height`, and a chain holding only genesis has tip height 0.
    Every request is one JSON-RPC call to `/json_rpc`; `params` is the
    method's named object, or None for a method that takes none.
    """
    if isinstance(tip_height, bool) or not isinstance(tip_height, int) \
            or tip_height < 0:
        raise ValueError(f"tip height {tip_height!r} is not a tip's ordinal")
    tip = tip_height
    past = tip_height + 10
    unknown = "ff" * 32
    reqs = [
        ("version", None),
        ("chain_height", None),
        ("block_header_show", {"tip": None}),
        ("block_header_show", {"height": 0}),
        ("block_header_show", {"height": tip}),
        ("block_header_show", {"height": past}),
        ("block_header_show", {"hash": genesis_hash}),
        ("block_header_show", {"hash": tip_hash}),
        ("block_header_show", {"hash": unknown}),
        ("block_header_list", {"from": 0, "to": min(2, tip)}),
        ("block_header_list", {"hash": [genesis_hash, tip_hash, unknown]}),
        ("block_show", {"height": 0}),
        ("block_show", {"height": tip}),
        ("block_show", {"height": past}),
        ("block_list", {"height": [0, tip, past]}),
        ("chain_spent", {"key_image": ["00" * 32]}),
        ("fee", None),
        ("chain_coinbase_sum", {"from": 0, "to": 0}),
        ("chain_alt", None),
        ("curve_show", {"tip": None}),
        ("curve_show", {"height": 0}),
        ("curve_show", {"height": tip}),
        ("archival_claim_show", {"persona": "00" * 32}),
        ("shard_coverage", None),
        ("daemon_status", None),
        ("option_show", {}),
        ("txpool_list", None),
        ("txpool_stats", None),
        ("block_template", None),
        ("mine_status", None),
        ("ban_list", None),
        ("relay_stats", None),
    ]
    if tx_hash:
        reqs.append(("tx_show", {"id": tx_hash}))
        reqs.append(("tx_list", {"id": [tx_hash]}))
    return [{"method": method, "params": params} for method, params in reqs]


# The rows a capture asks only when it is given a transaction id.
TX_METHODS = ("tx_show", "tx_list")


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
    """One JSON-RPC 2.0 call against `base_url`'s `/json_rpc`, the only
    route the daemon serves.

    `params` is the method's named object; None leaves it out, which is
    what a method with no parameters takes. The raw reply is returned:
    a `result`, or an `error` whose code is the class and whose data is
    the diagnostic.
    """
    url = base_url.rstrip("/") + "/json_rpc"
    body = {"jsonrpc": "2.0", "id": 0, "method": method}
    if params is not None:
        body["params"] = params
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


def occupied_replies_refusal(out_dir):
    """Why `out_dir` cannot take a capture, or None when it can.

    None means the path is missing or an empty directory: this run's.
    A capture is one run. `omitted.json` names the methods this run did
    not ask, so a reply already in the directory is another run sitting
    beside this run's omitted list. The previous capture is left in place.
    """
    if not os.path.exists(out_dir):
        return None
    if not os.path.isdir(out_dir):
        return f"{out_dir} is not a directory; a capture is one run's replies"
    held = sorted(os.listdir(out_dir))
    if not held:
        return None
    names = ", ".join(held)
    return (f"{out_dir} already holds a capture ({names}); "
            "a second capture would mix replies from two runs")


def capture(base_url, requests, out_dir, timeout=60):
    """Write one file per request. Returns the number written.

    Refuses a directory that already holds a capture, before any write.
    An empty directory, including one the caller just created, is this run's.
    """
    occupied = occupied_replies_refusal(out_dir)
    if occupied:
        raise ValueError(occupied)
    os.makedirs(out_dir, exist_ok=True)
    base = base_url.rstrip("/")
    n = 0
    for item in requests:
        if set(item) != {"method", "params"}:
            raise ValueError(f"request {item!r} is not one method and its params")
    for i, item in enumerate(requests):
        method = item["method"]
        params = item["params"]
        try:
            response = json_rpc(base, method, params, timeout)
        except (urllib.error.URLError, TimeoutError, OSError) as err:
            response = {"capture_error": str(err)}
        record = {"method": method, "params": params, "response": response}
        name = f"{i:03d}-{method}.json"
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(record, fh, indent=2)
            fh.write("\n")
        n += 1
    omitted = [{"method": m, "reason": r} for m, r in OMITTED]
    for method in TX_METHODS:
        if not any(item["method"] == method for item in requests):
            omitted.append({
                "method": method,
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
