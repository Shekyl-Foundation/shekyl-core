#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# RT-P5, sizes part: derive candidate record size classes from a run's
# HTTP message trace, and compare two runs for determinism.
#
# The rule this applies was registered before any registered run, in
# docs/benchmarks/rt_p5_rpc_message_sizes_20261017.md ("How the classes are
# derived"). Changing it after a registered result has been read is a change
# of method, recorded as such in that file, never a quiet edit here.
#
#   derive   RUN_DIR            the per-method table, the candidate tables
#                               for K = 1..8 and what each does to a
#                               submission, as Markdown on stdout
#   compare  RUN_DIR RUN_DIR    the determinism check between two runs;
#                               exit 1 when it fails
#
# RUN_DIR is a directory the instrument wrote (messages.csv,
# transactions.csv, run.json): engine::regtest_e2e::rt_p5 in
# rust/shekyl-engine-core/src/engine/regtest_e2e_rt_p5.rs.

import csv
import json
import os
import sys
from collections import Counter, defaultdict

# RPC_CHANNEL.md §4.4. Neither constant exists in code before RT-W9 step 5;
# the instrument restates the same two numbers.
MAX_RECORD_PLAINTEXT = 65_535
OCCUPANCY_LEN = 2
RECORD_PAYLOAD_MAX = MAX_RECORD_PLAINTEXT - OCCUPANCY_LEN

K_MAX = 8
SUBMIT = "/submit_transaction"

# Registered tolerance for the determinism check: per matched message, the
# larger of these.
DETERMINISM_ABS_BYTES = 64
DETERMINISM_REL = 0.01


def records_of(total):
    """Record plaintext lengths a message of `total` bytes needs, under the
    registered flush policy: one message is one flush, cut into full
    records of RECORD_PAYLOAD_MAX payload bytes and a tail."""
    if total <= 0:
        raise ValueError(f"a message of {total} bytes")
    full, tail = divmod(total, RECORD_PAYLOAD_MAX)
    out = [MAX_RECORD_PLAINTEXT] * full
    if tail:
        out.append(tail + OCCUPANCY_LEN)
    return out


def load(run_dir):
    with open(os.path.join(run_dir, "messages.csv"), newline="") as f:
        messages = list(csv.DictReader(f))
    with open(os.path.join(run_dir, "transactions.csv"), newline="") as f:
        txs = list(csv.DictReader(f))
    with open(os.path.join(run_dir, "run.json")) as f:
        run = json.load(f)
    if not messages:
        raise SystemExit(f"{run_dir}: messages.csv holds no message")
    for m in messages:
        for k in ("head", "body", "framing", "total"):
            m[k] = int(m[k])
        if m["head"] + m["body"] + m["framing"] != m["total"]:
            raise SystemExit(f"{run_dir}: a row whose parts do not add up: {m}")
    return messages, txs, run


class Costs:
    """Padding cost of assigning sorted distinct sizes i..j (inclusive) to a
    class whose length is sizes[j]."""

    def __init__(self, sizes, counts):
        self.sizes = sizes
        self.c = [0]
        self.s = [0]
        for v, n in zip(sizes, counts):
            self.c.append(self.c[-1] + n)
            self.s.append(self.s[-1] + n * v)

    def to(self, i, j, cls):
        n = self.c[j + 1] - self.c[i]
        return cls * n - (self.s[j + 1] - self.s[i])


def optimal_tables(record_lengths, k_max=K_MAX):
    """For K = 1..k_max, the K-class table that minimises total padding over
    `record_lengths`, the largest class fixed at MAX_RECORD_PLAINTEXT.
    Returns {K: (classes ascending, total padding bytes)}."""
    counted = Counter(record_lengths)
    sizes = sorted(counted)
    counts = [counted[v] for v in sizes]
    if sizes[-1] > MAX_RECORD_PLAINTEXT or sizes[0] < OCCUPANCY_LEN:
        raise ValueError("a record outside the class bounds")
    n = len(sizes)
    cost = Costs(sizes, counts)
    inf = float("inf")

    # f[k][j]: least padding for sizes[0..=j] with k classes, the top one
    # at sizes[j]. choice[k][j]: the index the previous class ends at.
    f = [[inf] * n for _ in range(k_max)]
    choice = [[-1] * n for _ in range(k_max)]
    for j in range(n):
        f[1 - 1][j] = cost.to(0, j, sizes[j])

    def solve(k, lo, hi, opt_lo, opt_hi):
        # Divide and conquer: the best split point is monotone in j for this
        # cost (a class's padding is linear in its length).
        if lo > hi:
            return
        mid = (lo + hi) // 2
        best, arg = inf, -1
        for i in range(opt_lo, min(mid, opt_hi + 1)):
            v = f[k - 1][i] + cost.to(i + 1, mid, sizes[mid])
            if v < best:
                best, arg = v, i
        f[k][mid], choice[k][mid] = best, arg
        solve(k, lo, mid - 1, opt_lo, arg if arg >= 0 else opt_hi)
        solve(k, mid + 1, hi, arg if arg >= 0 else opt_lo, opt_hi)

    for k in range(1, k_max - 1):
        solve(k, 0, n - 1, 0, n - 1)

    out = {}
    # K = 1: every record pads to the largest class.
    out[1] = ([MAX_RECORD_PLAINTEXT], cost.to(0, n - 1, MAX_RECORD_PLAINTEXT))
    for K in range(2, k_max + 1):
        # K - 1 classes below the largest, the last ending at j; the rest of
        # the sizes go to the largest class.
        best, arg = inf, -1
        for j in range(n):
            if sizes[j] >= MAX_RECORD_PLAINTEXT:
                break
            v = f[K - 2][j]
            if j + 1 < n:
                v += cost.to(j + 1, n - 1, MAX_RECORD_PLAINTEXT)
            if v < best:
                best, arg = v, j
        if arg < 0:
            out[K] = out[K - 1]
            continue
        classes, k, j = [], K - 2, arg
        while j >= 0 and k >= 0:
            classes.append(sizes[j])
            j = choice[k][j] if k > 0 else -1
            k -= 1
        classes = sorted(classes) + [MAX_RECORD_PLAINTEXT]
        out[K] = (classes, best)
    return out


def class_of(length, classes):
    for c in classes:
        if length <= c:
            return c
    raise ValueError(f"no class holds {length}")


def submission_encoding(messages, txs):
    """A submission's body as a + f * tx_len, from the trace: pair the
    submission requests with the built transactions by size order and
    require one (a, f) for all of them. Returns (a, f, head_bytes) or None."""
    subs = sorted(
        (m for m in messages if m["label"] == SUBMIT and m["direction"] == "request"),
        key=lambda m: m["body"],
    )
    tx_lens = sorted({int(t["tx"]): int(t["tx_len"]) for t in txs}.values())
    if len(subs) != len(tx_lens) or len(subs) < 2:
        return None
    for f in (1, 2):
        a = subs[0]["body"] - f * tx_lens[0]
        if all(m["body"] - f * t == a for m, t in zip(subs, tx_lens)):
            return a, f
    return None


def derive(run_dir):
    messages, txs, run = load(run_dir)
    per_method = defaultdict(list)
    records = []
    record_owner = []
    for m in messages:
        per_method[(m["label"], m["direction"])].append(m["total"])
        for r in records_of(m["total"]):
            records.append(r)
            record_owner.append((m["label"], m["direction"]))

    print(f"# RT-P5 classes: `{run['cell']}` cell\n")
    print(f"Chain height {run['chain_height']}; curve tree {json.dumps(run['curve_tree_info'])}.\n")
    print(f"{len(messages)} messages, {len(records)} records.\n")
    print("## HTTP message sizes per method\n")
    print("| Method | Direction | Count | Min | Median | Max | Records |")
    print("|---|---|---:|---:|---:|---:|---:|")
    for (label, direction), sizes in sorted(per_method.items()):
        s = sorted(sizes)
        recs = sum(len(records_of(x)) for x in s)
        print(f"| `{label}` | {direction} | {len(s)} | {s[0]:,} | {s[len(s) // 2]:,} | {s[-1]:,} | {recs} |")

    tables = optimal_tables(records)
    payload = sum(r - OCCUPANCY_LEN for r in records)
    print("\n## Candidate tables\n")
    print("Padding is the bytes added to reach each record's class, over every record in the trace. "
          "The largest class is fixed at 65,535.\n")
    print("| K | Classes | Padding | Padding / payload |")
    print("|---:|---|---:|---:|")
    for K in range(1, K_MAX + 1):
        classes, pad = tables[K]
        print(f"| {K} | {', '.join(f'{c:,}' for c in classes)} | {pad:,} | {pad / payload:.1%} |")

    print("\n## What shares a submission's class\n")
    print("For each K, the classes a submission request's records fall in, and every other "
          "method and direction with records in those classes (records counted).\n")
    for K in range(1, K_MAX + 1):
        classes, _ = tables[K]
        sub_classes = sorted({class_of(r, classes) for r, o in zip(records, record_owner) if o == (SUBMIT, "request")})
        sharing = Counter(
            o for r, o in zip(records, record_owner)
            if class_of(r, classes) in sub_classes and o != (SUBMIT, "request")
        )
        who = ", ".join(f"`{l}` {d} ×{n}" for (l, d), n in sorted(sharing.items())) or "nothing else"
        print(f"- **K = {K}**: submission records in {', '.join(f'{c:,}' for c in sub_classes)}; shared with {who}.")

    enc = submission_encoding(messages, txs)
    print("\n## A submission at greater tree depth\n")
    if enc is None:
        print("The submission bodies do not fit one encoding of the transaction bytes; no projection is made.")
        return
    a, f = enc
    print(f"A submission body is {a} + {f} × the transaction's wire length, for every submission in this trace. "
          "Each row below is the submission message at that depth, from the weight crate's size predictor; "
          "the head is taken as unchanged except for the length of `content-length`'s digits.\n")
    # The head differs between submissions only in `content-length`'s digits.
    ref = min((m for m in messages if m["label"] == SUBMIT and m["direction"] == "request"),
              key=lambda m: m["body"])
    base_head = ref["head"] - len(str(ref["body"]))
    per_tx = defaultdict(dict)
    about = {}
    for t in txs:
        per_tx[int(t["tx"])][int(t["depth"])] = int(t["predicted_tx_len"])
        about[int(t["tx"])] = (t["wallet"], int(t["inputs"]), int(t["outputs"]), int(t["built_depth"]))
    print("| Tx | Wallet | Inputs × outputs | Built at depth | " + " | ".join(f"d={d}" for d in range(1, 9)) + " |")
    print("|---:|---|---|---:|" + "---:|" * 8)
    for tx in sorted(per_tx):
        wallet, n_in, n_out, depth = about[tx]
        cells = []
        for d in range(1, 9):
            body = a + f * per_tx[tx][d]
            cells.append(f"{base_head + len(str(body)) + body:,}")
        print(f"| {tx} | {wallet} | {n_in} × {n_out} | {depth} | " + " | ".join(cells) + " |")

def compare(run_a, run_b):
    a, _, _ = load(run_a)
    b, _, _ = load(run_b)
    group = lambda ms: {k: sorted(m["total"] for m in ms if (m["wallet"], m["label"], m["direction"]) == k)
                        for k in {(m["wallet"], m["label"], m["direction"]) for m in ms}}
    ga, gb = group(a), group(b)
    failures = []
    for key in sorted(set(ga) | set(gb)):
        xa, xb = ga.get(key, []), gb.get(key, [])
        if len(xa) != len(xb):
            failures.append(f"{key}: {len(xa)} messages against {len(xb)}")
            continue
        for x, y in zip(xa, xb):
            if abs(x - y) > max(DETERMINISM_ABS_BYTES, DETERMINISM_REL * max(x, y)):
                failures.append(f"{key}: {x} against {y}")
                break
    for line in failures:
        print(f"DIFFERS {line}")
    print(f"compared {len(ga)} groups: {'PASS' if not failures else 'FAIL'}")
    return 0 if not failures else 1


def main(argv):
    if len(argv) == 3 and argv[1] == "derive":
        derive(argv[2])
        return 0
    if len(argv) == 4 and argv[1] == "compare":
        return compare(argv[2], argv[3])
    print(__doc__ or "usage: rt_p5_classes.py derive RUN_DIR | compare RUN_DIR RUN_DIR", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
