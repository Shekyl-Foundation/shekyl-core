#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# A regtest daemon is ready to mine once it has posted its first template.
#
# A daemon with no peers reads Synced at open, and posts a template once its
# chain follower has looped. A `dev_block_generate` sent before that is
# refused `mine.not_synced` with `sync: no_view`, honestly: the node has no
# template to fill. So a harness that mines waits for the first posted
# template, not for the daemon to answer some other method, as the Rust
# harness does (`regtest_e2e.rs`, `await_posted`).
#
# Every Python and shell launcher that mines waits here: the two fixture
# generators, the DRS bench and the WSS-Q1(b) bench script. The shell script
# runs this file: `posted_template.py <json_rpc url> [seconds]`; the exit
# status is the verdict (0 posted, 1 not within the bound).

"""Wait for a regtest daemon's first posted block template."""

import json
import sys
import time
import urllib.error
import urllib.request

# The bound a launcher gives a daemon that is already answering RPC. The
# follower's first loop takes well under a second; a loaded host is slower.
DEFAULT_TIMEOUT_S = 60


def _template(url):
    """One `block_template` call: the reply's `result`, or None while the
    daemon refuses it or does not answer; the refusal or the fault, as text,
    is the second value."""
    body = json.dumps({"jsonrpc": "2.0", "id": 0, "method": "block_template"}).encode()
    request = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=10) as reply:
            answer = json.loads(reply.read())
    except (urllib.error.URLError, OSError, json.JSONDecodeError, TimeoutError) as fault:
        return None, repr(fault)
    if answer.get("result") is not None:
        return answer["result"], None
    return None, json.dumps(answer.get("error"))


def await_posted(url, timeout_s=DEFAULT_TIMEOUT_S):
    """Return once the daemon at `url` (its `/json_rpc`) answers
    `block_template`. Raises RuntimeError, with its last answer, when no
    template is posted within `timeout_s` seconds."""
    deadline = time.monotonic() + timeout_s
    last = "no answer"
    while time.monotonic() < deadline:
        result, why = _template(url)
        if result is not None:
            return
        last = why
        time.sleep(0.1)
    raise RuntimeError(
        f"the daemon at {url} posted no template within {timeout_s}s; last answer: {last}")


def main(argv):
    if len(argv) not in (1, 2):
        print("usage: posted_template.py <json_rpc url> [seconds]", file=sys.stderr)
        return 2
    timeout_s = float(argv[1]) if len(argv) == 2 else DEFAULT_TIMEOUT_S
    try:
        await_posted(argv[0], timeout_s)
    except RuntimeError as refused:
        print(refused, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
