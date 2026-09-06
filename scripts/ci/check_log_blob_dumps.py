#!/usr/bin/env python3
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# check_log_blob_dumps.py -- no unbounded blob is rendered into a log line.
#
# THE DEFECT THIS EXISTS FOR. `cryptonote_protocol_handler.inl` used to hex
# dump peer-supplied block and transaction blobs at ERROR level on every
# parse failure. A block blob arriving in NOTIFY_RESPONSE_GET_OBJECTS has no
# bound tighter than levin's post-handshake LEVIN_DEFAULT_MAX_PACKET_SIZE
# (100 MB, contrib/epee/include/net/levin_base.h), and hex doubles it, so one
# packet could write ~200 MB to an operator's disk. Those paths do not score
# the drop, so the peer could reconnect and repeat: a remote-triggerable disk
# and IO amplifier, in the same family as the packet ceiling PWD-T6 derived
# away. The fix was `describe_peer_blob()` -- digest plus length.
#
# WHY THE SCOPE IS THE WHOLE TREE. An earlier draft of this gate was scoped to
# `src/cryptonote_protocol/`, which is just where the defects were found. A
# gate whose boundary is the directory its bugs lived in cannot see the next
# dump added anywhere else, and it reports green while doing so. The subject
# here is a *construct* -- a variable-length hex render inside a log macro --
# so the scan is every tracked C++ source and the exceptions are enumerated,
# not the inclusions.
#
# WHAT IS AND IS NOT IN SCOPE. `pod_to_hex` is bounded by construction (it is
# a template over a POD, so its length is a compile-time property) and is the
# sanctioned replacement; it is deliberately not a subject. The three subject
# idioms all take a span or a string, so their length is a runtime property
# the reader cannot see at the call site. Uses OUTSIDE a log macro are also
# out of scope: RPC responses (`core_rpc_server.cpp`) return hex because the
# schema says hex, `cn_deserialize` is an operator tool reading a blob the
# operator already has, and tests assert on hex by design. None of those write
# to an operator's disk on a peer's say-so.
#
# BOTH DIRECTIONS ARE ENFORCED. A hit with no allowlist row fails (someone
# added a dump). An allowlist row matching no hit also fails (someone removed
# or edited a dump and left the row), because an allowlist that accretes dead
# rows stops describing the tree and starts excusing it.
#
# Allowlist rows are keyed on path plus the whitespace-normalized ARGUMENT
# text, never on a line number: line numbers rot on the next edit above them,
# and a rotted key silently re-arms nothing. Editing the argument invalidates
# the row on purpose -- the bound is a property of the argument.
#
# Run `--selftest` to prove the detector can fail; CI runs it before the scan.

import io
import os
import re
import subprocess
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
ALLOWLIST = os.path.join(REPO, ".log-blob-allowlist")

# The subject idioms: every epee entry point that renders a RUNTIME-length
# byte range as hex. `pod_to_hex` is absent deliberately -- see the header.
IDIOMS = ("buff_to_hex_nodelimer", "to_hex::string", "to_hex::formatted")
IDIOM_RE = re.compile("|".join(re.escape(i) for i in IDIOMS))

# Where those idioms are DEFINED. Asserted to exist before the scan: if a
# rename lands and this list is not updated, every call site stops matching
# and the gate reports green over a tree it no longer understands (rule 47 --
# a gate must assert its own subject exists).
DEFINITIONS = {
    "contrib/epee/include/string_tools.h": ["buff_to_hex_nodelimer"],
    "contrib/epee/src/hex.cpp": ["to_hex::string", "to_hex::formatted"],
}

# Matched against the identifier immediately preceding an enclosing `(`.
LOGMAC_RE = re.compile(
    r"^(M[A-Z_]*ERROR[A-Z_]*|MWARNING|MINFO|MDEBUG|MTRACE|MGINFO|MLOG[A-Z_]*"
    r"|LOG_[A-Z_]*|MC[A-Z_]+)$"
)


def blank_literals(text):
    """Replace the CONTENTS of string and char literals with spaces, keeping
    length and newlines. Log format strings routinely contain parentheses --
    `"(height "` -- and a paren scanner that counts them walks out of the call
    it is standing in and reports the wrong enclosing macro, or none."""
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
            continue
        if c in "\"'":
            quote, j = c, i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == quote or text[j] == "\n":
                    break
                j += 1
            for k in range(i + 1, min(j, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = min(j + 1, n)
            continue
        i += 1
    return "".join(out)


IDENT_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*$")


def enclosing_log_macro(scrubbed, pos):
    """Walk left from `pos` through enclosing parens. Returns the name of the
    first enclosing call that is a log macro, else None.

    Balance is computed to the idiom's OFFSET, never to the end of its line.
    An earlier version compared paren counts over whole lines, which made the
    LAST argument of a multi-line macro invisible: the line carrying it also
    carries the macro's closing paren, so the count balanced and the hit was
    silently dropped. That is a gate reporting green over the exact site it
    was written for, so the selftest now pins this case."""
    depth = 0
    i = pos - 1
    while i >= 0:
        c = scrubbed[i]
        if c == ")":
            depth += 1
        elif c == "(":
            if depth == 0:
                m = IDENT_RE.search(scrubbed[:i])
                if m and LOGMAC_RE.match(m.group(1)):
                    return m.group(1)
                # Not a log macro -- step outside this call and keep going,
                # since the idiom may be nested inside a helper inside a macro.
            else:
                depth -= 1
        i -= 1
    return None


def norm(s):
    """Whitespace-normalized argument text -- the half of an allowlist key
    that survives reindentation but not a change to what is being dumped."""
    return " ".join(s.split())


def extract_arg(text, start):
    """Return the balanced argument text of the idiom call opening at/after
    `start`, or None if the call is a declaration rather than an invocation."""
    open_paren = text.find("(", start)
    if open_paren < 0:
        return None
    depth = 0
    for i in range(open_paren, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1:i]
    return None


def scan_text(text, path):
    """Yield (path, normalized_arg, line_no) for each idiom call that sits
    inside a log-macro invocation."""
    # Skip the definitions themselves and their internal forwarding.
    if path in DEFINITIONS:
        return

    scrubbed = blank_literals(text)
    for m in IDIOM_RE.finditer(scrubbed):
        if enclosing_log_macro(scrubbed, m.start()) is None:
            continue
        arg = extract_arg(scrubbed, m.end())
        if arg is None:
            continue
        # Report the argument from the ORIGINAL text so a literal inside it
        # is legible in the allowlist and in the failure message.
        real = extract_arg(text, m.end())
        yield (path, norm(real if real is not None else arg),
               text.count("\n", 0, m.start()) + 1)


def tracked_sources():
    out = subprocess.check_output(
        ["git", "-C", REPO, "ls-files", "src", "contrib", "tests"], text=True
    )
    return [f for f in out.split("\n") if f.endswith((".cpp", ".h", ".inl", ".hpp"))]


def read_allowlist():
    """Rows are `path<TAB>normalized-arg<TAB>reason`. Blank lines and `#`
    comments ignored. The reason is required: a row with no stated bound is
    the thing this gate exists to prevent, written down instead of fixed."""
    if not os.path.exists(ALLOWLIST):
        print("FATAL: allowlist missing at %s" % ALLOWLIST)
        sys.exit(2)
    rows = {}
    for n, raw in enumerate(io.open(ALLOWLIST, encoding="utf-8"), 1):
        line = raw.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 3 or not all(p.strip() for p in parts):
            print("FATAL: %s:%d malformed row (want path<TAB>arg<TAB>reason): %r"
                  % (ALLOWLIST, n, line))
            sys.exit(2)
        rows[(parts[0].strip(), norm(parts[1]))] = parts[2].strip()
    return rows


FIXTURE_BAD = '''
void f(const blobdata &blob) {
  MERROR("sent bad block: "
    << epee::string_tools::buff_to_hex_nodelimer(blob)
    << ", dropping");
}
'''
FIXTURE_OK = '''
void f(const blobdata &blob) {
  MERROR("sent bad block: " << describe_peer_blob(blob) << ", dropping");
  std::string h = epee::string_tools::buff_to_hex_nodelimer(blob);  // not a log
}
'''

# The regression limb. The dump is the LAST argument, so its line also closes
# the macro; and the format string contains parentheses, so a scanner that
# counts them without blanking literals mis-locates the enclosing call. Both
# of these silently dropped real sites in earlier drafts of this gate.
FIXTURE_LAST_ARG = '''
void f(const blobdata &blob) {
  MDEBUG("verify input " << i
    << " (height " << h << ")"
    << " ki=" << epee::string_tools::buff_to_hex_nodelimer(blob));
}
'''


def selftest():
    """A gate that cannot fail proves nothing. Both limbs, because a detector
    that fires on everything passes a positive-only check."""
    bad = list(scan_text(FIXTURE_BAD, "fixture.cpp"))
    ok = list(scan_text(FIXTURE_OK, "fixture.cpp"))
    if len(bad) != 1:
        print("SELFTEST FAIL: positive fixture yielded %d hits, want 1" % len(bad))
        return 1
    if bad[0][1] != "blob":
        print("SELFTEST FAIL: extracted arg %r, want 'blob'" % bad[0][1])
        return 1
    if ok:
        print("SELFTEST FAIL: negative fixture yielded %d hits, want 0" % len(ok))
        return 1
    last = list(scan_text(FIXTURE_LAST_ARG, "fixture.cpp"))
    if len(last) != 1:
        print("SELFTEST FAIL: final-argument fixture yielded %d hits, want 1 "
              "-- the detector is blind to the last argument of a multi-line "
              "log macro, or to parens inside its format string" % len(last))
        return 1
    print("SELFTEST PASS: detector fires on a raw dump in a log macro "
          "(including as the final argument, past parens in the format "
          "string), and not on describe_peer_blob() or a non-log use")
    return 0


def main():
    if "--selftest" in sys.argv:
        return selftest()

    rc = selftest()
    if rc:
        return rc

    # Rule 47: assert the subject exists before reporting on its absence.
    for rel, names in DEFINITIONS.items():
        p = os.path.join(REPO, rel)
        if not os.path.exists(p):
            print("FATAL: %s is gone; the idiom list is stale and this gate "
                  "would pass over a renamed construct." % rel)
            return 2
        body = io.open(p, encoding="utf-8", errors="replace").read()
        for n in names:
            if n not in body:
                print("FATAL: %r no longer defined in %s. It was renamed or "
                      "removed; update IDIOMS/DEFINITIONS before this gate can "
                      "be believed." % (n, rel))
                return 2

    files = tracked_sources()
    if not files:
        print("FATAL: scanned zero C++ sources -- the file list is wrong.")
        return 2

    hits = {}
    for rel in files:
        p = os.path.join(REPO, rel)
        try:
            text = io.open(p, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        if not IDIOM_RE.search(text):
            continue
        for path, arg, line in scan_text(text, rel):
            hits[(path, arg)] = line

    allowed = read_allowlist()
    unlisted = sorted(k for k in hits if k not in allowed)
    stale = sorted(k for k in allowed if k not in hits)

    if unlisted:
        print("FAIL: %d unbounded-looking blob dump(s) inside log macros:"
              % len(unlisted))
        for path, arg in unlisted:
            print("  %s:%d" % (path, hits[(path, arg)]))
            print("      arg: %s" % arg)
        print("")
        print("  Use describe_peer_blob() (digest + length), or truncate to a")
        print("  named constant. If the argument really is bounded, add a row")
        print("  to .log-blob-allowlist stating WHY -- the bound, not 'ok'.")
    if stale:
        print("FAIL: %d stale allowlist row(s) matching nothing in the tree:"
              % len(stale))
        for path, arg in stale:
            print("  %s\t%s" % (path, arg))
        print("")
        print("  The site was removed or its argument changed. Delete the row;")
        print("  a bound stated about code that is gone excuses the next one.")

    if unlisted or stale:
        return 1

    print("PASS: %d allowlisted blob dump(s) in log macros, all with a stated "
          "bound; no unlisted ones." % len(hits))
    return 0


if __name__ == "__main__":
    sys.exit(main())
