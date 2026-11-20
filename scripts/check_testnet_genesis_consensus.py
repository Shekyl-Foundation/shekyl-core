#!/usr/bin/env python3

import argparse
import json
import sys
import urllib.error
import urllib.request


def rpc_call(base_url: str, method: str, params: dict | None = None):
    # The daemon serves JSON-RPC 2.0 at /json_rpc and nothing else: a numeric
    # id, `params` a named object or left out. A refusal is the error's class
    # (its code) and the diagnostic's dotted code (its data).
    payload = {
        "jsonrpc": "2.0",
        "id": 0,
        "method": method,
    }
    if params is not None:
        payload["params"] = params
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
        error = body["error"]
        code = (error.get("data") or {}).get("code")
        raise RuntimeError(
            f"RPC error from {base_url}: {error.get('code')} {code}: {error.get('message')}"
        )
    return body["result"]


def get_genesis_tuple(base_url: str):
    header = rpc_call(base_url, "block_header_show", {"height": 0})
    coinbase = header["coinbase"]
    # `tx_show` answers the entry, or `{"archived": ...}` in its place. The
    # genesis coinbase is never discarded, so an archived answer is an error.
    entry = rpc_call(base_url, "tx_show", {"id": coinbase})
    if "body" not in entry:
        raise RuntimeError(f"{base_url}: genesis coinbase came back without a body: {entry}")
    return {
        "url": base_url,
        "height0_hash": header["hash"],
        "height0_coinbase": coinbase,
        "height0_reward": header["reward"],
        # base64, compared as text: equal text is equal bytes.
        "height0_tx_body": entry["body"],
    }


ECONOMY_FIELDS = (
    "emission_multiplier",
    "burn",
    "stake_share",
    "burn_total",
)


def get_economy_fields(base_url: str):
    status = rpc_call(base_url, "daemon_status")
    return {k: status.get(k) for k in ECONOMY_FIELDS}


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
        help="Also verify economy fields exist in daemon_status on each node.",
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
        if t["height0_coinbase"] != ref["height0_coinbase"]:
            print(
                f"MISMATCH: height 0 coinbase id differs\n"
                f"  ref {ref['url']}: {ref['height0_coinbase']}\n"
                f"  got {t['url']}: {t['height0_coinbase']}",
                file=sys.stderr,
            )
            failed = True
        if t["height0_tx_body"] != ref["height0_tx_body"]:
            print(
                f"MISMATCH: height 0 coinbase body differs between {ref['url']} and {t['url']}",
                file=sys.stderr,
            )
            failed = True

    if args.check_economy:
        required = set(ECONOMY_FIELDS)
        for url in args.rpc:
            try:
                fields = get_economy_fields(url)
            except (urllib.error.URLError, RuntimeError, ValueError) as e:
                print(f"ERROR: daemon_status failed for {url}: {e}", file=sys.stderr)
                failed = True
                continue
            missing = [k for k in required if fields.get(k) is None]
            if missing:
                print(f"MISMATCH: {url} missing economy fields in daemon_status: {missing}", file=sys.stderr)
                failed = True

    print("Checked endpoints:")
    for t in tuples:
        print(
            f"- {t['url']}  h0={t['height0_hash']}  coinbase={t['height0_coinbase']}"
        )

    if failed:
        print("FAIL: testnet consensus/economy checks failed.", file=sys.stderr)
        return 1
    print("PASS: all compared nodes agree on genesis tuple.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
