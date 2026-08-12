# Copyright (c) 2025-2026, The Shekyl Foundation
#
# Parser for read_anon_histogram.sh. Its own file rather than a heredoc inside
# the shell script, for two reasons: in the `python3 -c '...'` form every
# apostrophe in a comment closes the shell quote, so prose about a node's peers
# becomes a syntax error in a different language than the one it is written in;
# and a parser that produces this run its headline number should be directly
# testable without standing up a fleet. See test_anon_readout_parse.py.
#
# Reads the joined RPC output on stdin, prints exactly one verdict line:
#
#   OK <anon_out> <anon_in> <public> <white> <gray>
#   ERR <reason>
import sys, json

# A COUNT IS EMITTED ONLY FROM A PATH THAT AFFIRMATIVELY PARSED A LIST OF
# CONNECTION OBJECTS. Every other shape — an error, a missing field, a field of
# the wrong type, an element that is not an object, an exception nobody
# predicted — produces ERR. The class being closed is not "restricted mode": it
# is ANY unrecognized response collapsing to zero, because zero is this run its
# headline claim and the instrument must not be able to manufacture it.
def absent_connections_is_empty(r):
    """Decide an absent `connections` from the response's OWN shape.

    The previous version asked `get_info` to corroborate a zero. That check
    could not fire. `get_info`'s counters come from
    `get_public_outgoing_connections_count()`
    (src/rpc/core_rpc_server.cpp:345) — the PUBLIC zone only, and additionally
    hard-zeroed under `restricted` on the same line. Every node in this run is
    anonymity-only, so `get_info` reports 0/0 whether the node holds zero anon
    peers or twelve. Its "the node HAS peers, refuse the zero" branch needed
    public peers to reach and was unreachable for the entire population it
    guarded: a second instrument blind on exactly the axis under test, which
    is the same defect it was written to close, one layer out.

    A corroborating oracle is the wrong tool here. The ambiguity is "empty
    list" vs "a response shape we do not understand", and that is decidable
    from the reply itself: a get_connections reply affirmatively identifies
    itself with `status` and `untrusted` (a genuinely isolated node returns
    exactly `{"status":"OK","untrusted":false}`). Require those, and an absent
    `connections` is an empty list. Anything else stays ERR.

    Constrain what can match rather than asking something else to vouch.
    """
    if r.get("status") != "OK":
        return "ERR no-connections-field:status=%r" % (r.get("status"),)
    if "untrusted" not in r:
        return "ERR no-connections-field:not-a-get_connections-reply"
    return "OK 0 0 0"

def stored_anon(peers_raw):
    """White/gray anonymity candidates, or None if the reply is unusable.

    None is NOT zero, for the same reason a failed connection reading is not
    an isolated node: an empty candidate set is the suppression failure this
    arm exists to detect, so the instrument must not be able to produce one
    from a bad read.

    Counts include the node's OWN onion when the daemon has stored it (observed
    in aus's gray list), so this is an upper bound by at most one. That offset
    is uniform and does not blur the distinction the number is for -- a full
    candidate set against an exhausted one.
    """
    try:
        p = json.loads(peers_raw)
    except Exception:
        return None
    if not isinstance(p, dict) or p.get("status") != "OK":
        return None
    out = []
    for key in ("white_list", "gray_list"):
        v = p.get(key, [])
        if v is None:
            v = []
        if not isinstance(v, list):
            return None
        # `host` carries the PORT too -- "xxxx.onion:13021" -- so an
        # endswith(".onion") match counts nothing. It did: every node read
        # white=0 gray=0 while aus demonstrably held 4 and 1. The None-vs-zero
        # guard above does not catch this, because the read was fine and the
        # MATCHER was wrong; a guard against unparseable input says nothing
        # about a predicate that parses cleanly and matches the wrong thing.
        out.append(sum(1 for e in v
                       if isinstance(e, dict) and ".onion" in str(e.get("host", ""))))
    return out

def verdict():
    raw = sys.stdin.read()
    conn_raw, _, peers_raw = raw.partition("@@SPLIT@@")
    try:
        d = json.loads(conn_raw)
    except Exception as e:
        return "ERR unparseable:%s" % type(e).__name__
    if not isinstance(d, dict):
        return "ERR non-object-response:%s" % type(d).__name__
    if d.get("error"):
        e = d["error"]
        if isinstance(e, dict):
            return "ERR rpc-error:%s:%s" % (e.get("code"), e.get("message"))
        return "ERR rpc-error:%s" % (e,)
    if "result" not in d:
        return "ERR no-result-field"
    r = d["result"]
    if not isinstance(r, dict):
        return "ERR result-not-an-object:%s" % type(r).__name__
    stored = stored_anon(peers_raw)
    if stored is None:
        return "ERR peer-list-unusable"
    white, gray = stored

    if "connections" not in r:
        base = absent_connections_is_empty(r)
        return base if base.startswith("ERR") else "OK 0 0 0 %d %d" % (white, gray)
    c = r["connections"]
    if c is None:
        return "ERR connections-null"
    if not isinstance(c, list):
        return "ERR connections-not-a-list:%s" % type(c).__name__
    for x in c:
        if not isinstance(x, dict):
            return "ERR connection-entry-not-an-object:%s" % type(x).__name__
        if "address_type" not in x:
            return "ERR connection-entry-missing-address_type"
    tor_out = sum(1 for x in c if x.get("address_type") == 4 and not x.get("incoming"))
    tor_in  = sum(1 for x in c if x.get("address_type") == 4 and x.get("incoming"))
    pub     = sum(1 for x in c if x.get("address_type") != 4)
    return "OK %d %d %d %d %d" % (tor_out, tor_in, pub, white, gray)

try:
    print(verdict())
except Exception as e:
    # Even an unforeseen failure names itself rather than vanishing into the
    # NO ANSWER bucket, which is what hid the escaped-quote defect in the
    # previous version of this parser.
    print("ERR unexpected:%s:%s" % (type(e).__name__, e))
