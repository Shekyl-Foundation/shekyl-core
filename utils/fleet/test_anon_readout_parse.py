#!/usr/bin/env python3
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# Tests for anon_readout_parse.py -- the parser that produces this run its
# headline number. It exists because two defects reached the fleet before it
# did, and neither needed a VM to catch:
#
#   1. An RPC error read as zero connections, so every node on a healthy estate
#      reported isolated. The instrument could manufacture the run result.
#   2. The fix for (1) asked `get_info` to corroborate a zero. `get_info`
#      counts the PUBLIC zone only (core_rpc_server.cpp:345) and is hard-zeroed
#      under `restricted` on the same line, so for an anonymity-only node -- the
#      entire fleet -- it answered 0/0 whether the node held zero peers or
#      twelve. Its refuse-the-zero branch needed public peers to reach and was
#      unreachable for the whole population it guarded.
#
# So the standing requirement here: every OK verdict must be reachable ONLY
# from an affirmatively recognized response, and every guard must have a test
# that FAILS when the guard is removed. A test that passes against a parser
# which always answers "ERR" is not coverage, and neither is one that passes
# against a parser which always answers zero.
#
# Run: python3 utils/fleet/test_anon_readout_parse.py

import json
import pathlib
import subprocess
import sys

PARSER = pathlib.Path(__file__).with_name("anon_readout_parse.py")

ONION_A = "jxm2ggz3ifshvhqgwxkvrwq4uo4gkn64dqsrokjc36i5nhhluwmiq5qd.onion:13021"
ONION_B = "kbesdwuof6il5btctanrh2vafalnfogln6qwyly3nvpjh74yklxdiayd.onion:13021"

failures = []


def run(conn, peers):
    """Feed the parser the two joined replies exactly as the shell does."""
    conn_s = conn if isinstance(conn, str) else json.dumps(conn)
    peers_s = peers if isinstance(peers, str) else json.dumps(peers)
    p = subprocess.run([sys.executable, str(PARSER)],
                       input=conn_s + "\n@@SPLIT@@\n" + peers_s,
                       capture_output=True, text=True)
    return p.stdout.strip()


def check(name, got, want):
    ok = got == want if isinstance(want, str) else want(got)
    print(("  ok   " if ok else "  FAIL ") + name + ("" if ok else "  got %r" % got))
    if not ok:
        failures.append(name)


def peers(white=(), gray=()):
    return {"status": "OK", "untrusted": False,
            "white_list": [{"host": h, "id": 1, "ip": 0, "port": 0} for h in white],
            "gray_list": [{"host": h, "id": 1, "ip": 0, "port": 0} for h in gray]}


def conns(entries):
    return {"jsonrpc": "2.0", "id": "0",
            "result": {"status": "OK", "untrusted": False, "connections": entries}}


def c(addr, incoming, atype=4):
    return {"address": addr, "incoming": incoming, "address_type": atype}


print("anon_readout_parse")

# --- the ordinary path, and the split across zones/directions ---------------
check("counts outbound, inbound and public separately",
      run(conns([c(ONION_A, False), c(ONION_B, False), c("x", True),
                 c("1.2.3.4:18080", False, 1)]),
          peers(white=[ONION_A, ONION_B])),
      "OK 2 1 1 2 0")

# --- the .onion matcher regression -----------------------------------------
# `host` carries the port, so an endswith(".onion") predicate counted nothing
# and every node read white=0 gray=0 against a fleet demonstrably holding
# candidates. A parser that silently reports an EMPTY CANDIDATE SET reports the
# suppression failure this arm exists to detect.
check("stored candidates survive the port suffix on host",
      run(conns([c(ONION_A, False)]), peers(white=[ONION_A, ONION_B], gray=[ONION_B])),
      "OK 1 0 0 2 1")

# --- an isolated node is a REAL zero, and still reports its candidates ------
# A genuinely isolated node omits `connections` entirely and returns exactly
# {"status":"OK","untrusted":false}. That is a zero -- and the stored count is
# precisely what says whether it can recover.
check("absent connections on a well-formed reply is an empty list",
      run({"jsonrpc": "2.0", "id": "0", "result": {"status": "OK", "untrusted": False}},
          peers(white=[ONION_A, ONION_B])),
      "OK 0 0 0 2 0")

check("isolated AND candidate-less is reported, not refused",
      run({"jsonrpc": "2.0", "id": "0", "result": {"status": "OK", "untrusted": False}},
          peers()),
      "OK 0 0 0 0 0")

# --- guards: each must fail if removed --------------------------------------
check("rpc error is never a zero",
      run({"jsonrpc": "2.0", "id": "0",
           "error": {"code": -32601, "message": "Method not found"}}, peers()),
      lambda g: g.startswith("ERR rpc-error:-32601"))

check("absent connections without status is refused",
      run({"jsonrpc": "2.0", "id": "0", "result": {"untrusted": False}}, peers()),
      lambda g: g.startswith("ERR no-connections-field:status="))

check("absent connections on a reply that is not get_connections is refused",
      run({"jsonrpc": "2.0", "id": "0", "result": {"status": "OK", "height": 1}}, peers()),
      "ERR no-connections-field:not-a-get_connections-reply")

check("unparseable connections reply is refused",
      run("<html>502 Bad Gateway</html>", peers()),
      lambda g: g.startswith("ERR unparseable:"))

check("empty connections reply is refused",
      run("", peers()),
      lambda g: g.startswith("ERR unparseable:"))

# An unusable PEER reply must not become an empty candidate set, for the same
# reason a failed connection reading must not become an isolated node.
check("unparseable peer list is refused, not read as zero candidates",
      run(conns([c(ONION_A, False)]), "<html>502</html>"),
      "ERR peer-list-unusable")

check("peer list with a bad status is refused",
      run(conns([c(ONION_A, False)]), {"status": "BUSY"}),
      "ERR peer-list-unusable")

check("connections of the wrong type is refused",
      run({"jsonrpc": "2.0", "id": "0",
           "result": {"status": "OK", "untrusted": False, "connections": "many"}}, peers()),
      lambda g: g.startswith("ERR connections-not-a-list"))

check("a connection entry missing address_type is refused",
      run({"jsonrpc": "2.0", "id": "0",
           "result": {"status": "OK", "untrusted": False,
                      "connections": [{"address": ONION_A, "incoming": False}]}}, peers()),
      "ERR connection-entry-missing-address_type")

# --- negative control on the SUITE ------------------------------------------
# If the parser were replaced by one that always printed a fixed verdict, the
# checks above must not all pass. Asserting that here keeps the suite from
# becoming the kind of seal it was written to prevent.
fixed_ok = [run(conns([c(ONION_A, False)]), peers(white=[ONION_A]))]
check("suite distinguishes verdicts (control)",
      "OK 1 0 0 1 0", lambda want: fixed_ok[0] == want)

print()
if failures:
    print("FAILED: " + ", ".join(failures))
    sys.exit(1)
print("all checks passed")
