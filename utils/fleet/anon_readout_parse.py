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
import os
import sys, json

# A COUNT IS EMITTED ONLY FROM A PATH THAT AFFIRMATIVELY PARSED A LIST OF
# CONNECTION OBJECTS. Every other shape — an error, a result that is not a
# list, an element that is not an object, an exception nobody predicted —
# produces ERR. The class being closed is not "restricted mode": it is ANY
# unrecognized response collapsing to zero, because zero is this run its
# headline claim and the instrument must not be able to manufacture it.
#
# Both replies are JSON-RPC 2.0 from the daemon's `/json_rpc`:
# `peer_connections` answers a list of connections, and `peer_list` a list
# of `{endpoint, tier}`. A refusal is an `error` whose code is the class and
# whose data is the diagnostic, never a `status` member.

def _rpc_error(d):
    """The ERR text for a reply's `error`, or None when it has none."""
    e = d.get("error")
    if e is None:
        return None
    if isinstance(e, dict):
        code = (e.get("data") or {}).get("code") if isinstance(e.get("data"), dict) else None
        return "ERR rpc-error:%s:%s:%s" % (e.get("code"), code, e.get("message"))
    return "ERR rpc-error:%s" % (e,)

def _excluded_onions():
    """Onions that must NOT appear in any fleet node's peer list.

    From SEED_EXCLUDE_FILE. Unset means no exclusion is being asserted, which
    is the right default for a fleet that has no separate bootstrap population
    -- but a file that is SET and unreadable is a refusal, not an empty set: an
    exclusion list that silently becomes empty is a check that silently stops
    checking.
    """
    path = os.environ.get("SEED_EXCLUDE_FILE")
    if not path:
        return []
    with open(path) as fh:          # deliberately unguarded; see docstring
        return [ln.split(":")[0].strip() for ln in fh
                if ln.strip() and not ln.lstrip().startswith("#")]

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
    if not isinstance(p, dict) or "error" in p:
        return None
    entries = p.get("result")
    if not isinstance(entries, list):
        return None

    # SEED EXCLUSION IS AN INVARIANT, NOT AN ARRANGEMENT.
    #
    # The arm excludes the bootstrap ring from the candidate pool -- with it
    # included, a node choosing 12 outbound from 20 candidates tolerates 8 burns
    # instead of 2, and can satisfy the floor entirely on ring links while
    # discovering nothing. Today that exclusion holds only because nobody wired
    # the two together, and both populations share a stagenet NETWORK_ID: one
    # stray onion in one config and the arm is measuring a different network
    # than it reports.
    #
    # "Nobody made a mistake" is not a property a result can rest on, so it is
    # checked every reading. Contamination VOIDS the arm, and it must be loud
    # at the moment it appears rather than inferred afterwards from a
    # suspiciously easy floor.
    # ENTRIES ARE VALIDATED, NOT SKIPPED. An earlier version ignored any entry
    # that was not a dict or had no `host`, which meant a partially corrupt
    # reply counted DOWN: fifteen unreadable entries produced white=0 gray=0,
    # an empty candidate set, which is the suppression failure this arm exists
    # to detect. Silently skipping malformed input is how an instrument
    # manufactures its own headline, and the connections path two functions
    # below already refuses entry-level damage rather than dropping it -- this
    # is that same rule, applied on the side where it was missing.
    #
    # A non-onion endpoint is NOT malformed: white and gray legitimately carry
    # public-zone peers. Only unreadable STRUCTURE refuses, and a tier that is
    # neither list is unreadable structure.
    hosts = {"white": [], "gray": []}
    for e in entries:
        if not isinstance(e, dict):
            return None
        h = e.get("endpoint")
        if not isinstance(h, str) or not h:
            return None
        tier = e.get("tier")
        if tier not in hosts:
            return None
        hosts[tier].append(h)

    excl = _excluded_onions()
    if excl:
        for key in ("white", "gray"):
            for h in hosts[key]:
                for bad in excl:
                    if bad and bad in h:
                        return "CONTAMINATED:%s" % bad[:16]

    # `endpoint` carries the PORT too -- "xxxx.onion:13021" -- so an
    # endswith(".onion") match counts nothing. It did: every node read
    # white=0 gray=0 while aus demonstrably held 5 and 1. The None-vs-zero
    # guard does not catch that, because the read was fine and the MATCHER was
    # wrong; a guard against unparseable input says nothing about a predicate
    # that parses cleanly and matches the wrong thing.
    return [sum(1 for h in hosts[k] if ".onion" in h)
            for k in ("white", "gray")]

def verdict():
    raw = sys.stdin.read()
    conn_raw, _, peers_raw = raw.partition("@@SPLIT@@")
    try:
        d = json.loads(conn_raw)
    except Exception as e:
        return "ERR unparseable:%s" % type(e).__name__
    if not isinstance(d, dict):
        return "ERR non-object-response:%s" % type(d).__name__
    refused = _rpc_error(d)
    if refused:
        return refused
    if "result" not in d:
        return "ERR no-result-field"
    # `peer_connections` answers the list itself. A genuinely isolated node
    # answers `[]`; anything that is not a list is a different method or a
    # malformed reply, never a zero.
    c = d["result"]
    if c is None:
        return "ERR connections-null"
    if not isinstance(c, list):
        return "ERR connections-not-a-list:%s" % type(c).__name__
    stored = stored_anon(peers_raw)
    if stored is None:
        return "ERR peer-list-unusable"
    # Contamination is reported as ERR so it propagates through the reader as a
    # FAILED node and the sampler discards the whole reading. A contaminated arm
    # must not produce a summary line at all.
    if isinstance(stored, str):
        return "ERR seed-%s" % stored
    white, gray = stored

    for x in c:
        if not isinstance(x, dict):
            return "ERR connection-entry-not-an-object:%s" % type(x).__name__
        # The connector is `clearnet` or `tor`; any other value is a reply
        # this parser does not understand, not a public connection.
        if x.get("connector") not in ("clearnet", "tor"):
            return "ERR connection-entry-bad-connector"
        # `incoming` was once read with `not x.get("incoming")`, so an entry
        # MISSING the field counted as OUTBOUND -- inflating the one quantity
        # the floor is measured on, in the direction that reports a node as
        # better connected than it is. The direction field is exactly as
        # load-bearing as the connector. A default is not available here:
        # there is no safe guess about which way a connection points.
        if not isinstance(x.get("inbound"), bool):
            return "ERR connection-entry-bad-inbound"
    tor_out = sum(1 for x in c if x["connector"] == "tor" and not x["inbound"])
    tor_in  = sum(1 for x in c if x["connector"] == "tor" and x["inbound"])
    pub     = sum(1 for x in c if x["connector"] == "clearnet")
    return "OK %d %d %d %d %d" % (tor_out, tor_in, pub, white, gray)

try:
    print(verdict())
except Exception as e:
    # Even an unforeseen failure names itself rather than vanishing into the
    # NO ANSWER bucket, which is what hid the escaped-quote defect in the
    # previous version of this parser.
    print("ERR unexpected:%s:%s" % (type(e).__name__, e))
