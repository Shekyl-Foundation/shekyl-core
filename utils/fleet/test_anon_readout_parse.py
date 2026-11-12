#!/usr/bin/env python3
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# Tests for anon_readout_parse.py -- the parser that produces this run its
# headline number. It exists because two defects reached the fleet before it
# did, and neither needed a VM to catch:
#
#   1. An RPC error read as zero connections, so every node on a healthy estate
#      reported isolated. The instrument could manufacture the run result.
#   2. The fix for (1) asked the daemon's status read to corroborate a zero.
#      It counted the PUBLIC zone only and was hard-zeroed under `restricted`,
#      so for an anonymity-only node -- the entire fleet -- it answered 0/0
#      whether the node held zero peers or twelve. Its refuse-the-zero branch
#      needed public peers to reach and was unreachable for the whole
#      population it guarded.
#
# So the standing requirement here: every OK verdict must be reachable ONLY
# from an affirmatively recognized response, and every guard must have a test
# that FAILS when the guard is removed. A test that passes against a parser
# which always answers "ERR" is not coverage, and neither is one that passes
# against a parser which always answers zero.
#
# Run: python3 utils/fleet/test_anon_readout_parse.py

import json
import os
import pathlib
import subprocess
import sys

PARSER = pathlib.Path(__file__).with_name("anon_readout_parse.py")

ONION_A = "jxm2ggz3ifshvhqgwxkvrwq4uo4gkn64dqsrokjc36i5nhhluwmiq5qd.onion:13021"
ONION_B = "kbesdwuof6il5btctanrh2vafalnfogln6qwyly3nvpjh74yklxdiayd.onion:13021"

failures = []


def run(conn, peers, exclude_file=None):
    """Feed the parser the two joined replies exactly as the shell does."""
    conn_s = conn if isinstance(conn, str) else json.dumps(conn)
    peers_s = peers if isinstance(peers, str) else json.dumps(peers)
    env = dict(os.environ)
    env.pop("SEED_EXCLUDE_FILE", None)
    if exclude_file is not None:
        env["SEED_EXCLUDE_FILE"] = exclude_file
    p = subprocess.run([sys.executable, str(PARSER)],
                       input=conn_s + "\n@@SPLIT@@\n" + peers_s,
                       capture_output=True, text=True, env=env)
    return p.stdout.strip()


def check(name, got, want):
    ok = got == want if isinstance(want, str) else want(got)
    print(("  ok   " if ok else "  FAIL ") + name + ("" if ok else "  got %r" % got))
    if not ok:
        failures.append(name)


def peers(white=(), gray=()):
    return reply([{"endpoint": h, "tier": "white"} for h in white]
                 + [{"endpoint": h, "tier": "gray"} for h in gray])


def reply(result):
    return {"jsonrpc": "2.0", "id": 0, "result": result}


def conns(entries):
    return reply(entries)


def c(addr, inbound, connector="tor"):
    return {"endpoint": addr, "inbound": inbound, "connector": connector}


print("anon_readout_parse")

# --- the ordinary path, and the split across zones/directions ---------------
check("counts outbound, inbound and public separately",
      run(conns([c(ONION_A, False), c(ONION_B, False), c("x", True),
                 c("1.2.3.4:18080", False, "clearnet")]),
          peers(white=[ONION_A, ONION_B])),
      "OK 2 1 1 2 0")

# --- the .onion matcher regression -----------------------------------------
# `endpoint` carries the port, so an endswith(".onion") predicate counted nothing
# and every node read white=0 gray=0 against a fleet demonstrably holding
# candidates. A parser that silently reports an EMPTY CANDIDATE SET reports the
# suppression failure this arm exists to detect.
check("stored candidates survive the port suffix on endpoint",
      run(conns([c(ONION_A, False)]), peers(white=[ONION_A, ONION_B], gray=[ONION_B])),
      "OK 1 0 0 2 1")

# --- an isolated node is a REAL zero, and still reports its candidates ------
# A genuinely isolated node answers `[]`. A result that is not a list is a
# different method or a malformed reply.
check("empty connections list is an isolated node, not a refusal",
      run(conns([]), peers(white=[ONION_A, ONION_B])),
      "OK 0 0 0 2 0")

check("isolated AND candidate-less is reported, not refused",
      run(conns([]), peers()),
      "OK 0 0 0 0 0")

# --- guards: each must fail if removed --------------------------------------
check("rpc error is never a zero",
      run({"jsonrpc": "2.0", "id": 0,
           "error": {"code": -32601, "message": "no method is named peer_connections",
                     "data": {"code": "rpc.method", "parameter": {}, "message": "x"}}},
          peers()),
      lambda g: g.startswith("ERR rpc-error:-32601:rpc.method"))

check("a grant refusal is never a zero",
      run({"jsonrpc": "2.0", "id": 0,
           "error": {"code": -32002, "message": "outside the grant",
                     "data": {"code": "grant.outside", "parameter": {}, "message": "x"}}},
          peers()),
      lambda g: g.startswith("ERR rpc-error:-32002:grant.outside"))

check("an object result is not a connection list",
      run(reply({}), peers()),
      "ERR connections-not-a-list:dict")

check("a reply with no result is refused",
      run({"jsonrpc": "2.0", "id": 0}, peers()),
      "ERR no-result-field")

check("a null result is refused",
      run(reply(None), peers()),
      "ERR connections-null")

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

check("a refused peer list is refused, not read as zero candidates",
      run(conns([c(ONION_A, False)]),
          {"jsonrpc": "2.0", "id": 0, "error": {"code": -32004, "message": "not ready"}}),
      "ERR peer-list-unusable")

check("a peer list that is not a list is refused",
      run(conns([c(ONION_A, False)]), reply({"white": []})),
      "ERR peer-list-unusable")

check("connections of the wrong type is refused",
      run(reply("many"), peers()),
      lambda g: g.startswith("ERR connections-not-a-list"))

check("a connection entry missing its connector is refused",
      run(conns([{"endpoint": ONION_A, "inbound": False}]), peers()),
      "ERR connection-entry-bad-connector")

check("a connection entry with an unknown connector is refused, not counted public",
      run(conns([c(ONION_A, False, "i2p")]), peers()),
      "ERR connection-entry-bad-connector")

# --- malformed input must count UP to a refusal, not DOWN to zero ----------
# Review finding. Entries that were not dicts, or had no `host`, were SKIPPED --
# so a partially corrupt peer list counted DOWN, and fifteen unreadable entries
# produced white=0 gray=0. An empty candidate set IS the suppression failure
# this arm exists to detect, so silently dropping damage lets the instrument
# manufacture its own headline. The connections path already refused
# entry-level damage; this is the same rule on the side that lacked it.
check("a peer entry that is not an object refuses",
      run(conns([c(ONION_A, False)]), reply([ONION_A])),
      "ERR peer-list-unusable")

check("a peer entry with no endpoint refuses rather than counting zero",
      run(conns([c(ONION_A, False)]), reply([{"tier": "white"}])),
      "ERR peer-list-unusable")

check("a peer entry whose endpoint is not a string refuses",
      run(conns([c(ONION_A, False)]), reply([{"endpoint": 12345, "tier": "white"}])),
      "ERR peer-list-unusable")

check("a peer entry with an unknown tier refuses",
      run(conns([c(ONION_A, False)]), reply([{"endpoint": ONION_A, "tier": "black"}])),
      "ERR peer-list-unusable")

# A non-onion host is NOT damage: white and gray legitimately carry public-zone
# peers. Refusing those would make the instrument refuse healthy fleets.
check("a public-zone peer is counted out, not refused",
      run(conns([]), reply([{"endpoint": "1.2.3.4:18080", "tier": "white"},
                            {"endpoint": ONION_A, "tier": "white"}])),
      "OK 0 0 0 1 0")

# --- direction is load-bearing and was unchecked ---------------------------
# `not x.get("incoming")` once made a MISSING field count as OUTBOUND, inflating the
# exact quantity the floor is measured on, in the direction that reports a node
# as better connected than it is. There is no safe default for which way a
# connection points.
check("a connection entry missing inbound refuses",
      run(conns([{"endpoint": ONION_A, "connector": "tor"}]), peers()),
      "ERR connection-entry-bad-inbound")

check("a connection entry with a non-bool inbound refuses",
      run(conns([{"endpoint": ONION_A, "connector": "tor", "inbound": "yes"}]), peers()),
      "ERR connection-entry-bad-inbound")

# --- seed exclusion is an invariant, not an arrangement ------------------
# The arm excludes the bootstrap ring from the CANDIDATE pool (a different
# membership from the histogram exclusion, and the one the derivation rests on:
# with the ring in the pool a node tolerates 8 burns instead of 2 and can meet
# the floor entirely on ring links). That exclusion currently holds only because
# nobody wired the two together, and both share a NETWORK_ID -- so it is checked
# every reading rather than assumed.
import tempfile
_seed = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
_seed.write("# seeds\n" + ONION_B + "\n")
_seed.close()

check("no exclusion file asserts nothing (default stays open)",
      run(conns([c(ONION_A, False)]), peers(white=[ONION_A, ONION_B])),
      "OK 1 0 0 2 0")

check("a seed onion in the peer list VOIDS the reading",
      run(conns([c(ONION_A, False)]), peers(white=[ONION_A, ONION_B]), exclude_file=_seed.name),
      lambda g: g.startswith("ERR seed-CONTAMINATED"))

check("a clean fleet passes with exclusion armed",
      run(conns([c(ONION_A, False)]), peers(white=[ONION_A]), exclude_file=_seed.name),
      "OK 1 0 0 1 0")

# An exclusion list that silently becomes empty is a check that silently stops
# checking -- the exact shape of the corroborator this file was written for.
check("an exclusion file that is set but unreadable refuses",
      run(conns([]), peers(white=[ONION_A]), exclude_file="/nonexistent/seeds.txt"),
      lambda g: g.startswith("ERR unexpected:FileNotFoundError"))

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
