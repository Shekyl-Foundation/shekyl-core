#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# RT-P9: summarise a run of the handshake round-trip harness
# (rust/shekyl-rpc-channel/examples/rt_p9_handshake_round_trips.rs),
# check its registered gates, and derive the handshake's two deadlines.
#
#   rt_p9_summary.py RUN_DIR    Markdown on stdout
#
# RUN_DIR holds one directory per leg, `onion/` and `lan/`, each with the
# daemon's `server.tsv` and the client's `client.tsv`. The registered shape
# and rule are docs/benchmarks/rt_p9_handshake_round_trips_20261020.md. A
# file that is not that shape is refused before any table is written. A run
# that fails a gate is reported, says VOID, derives nothing and exits 3.

import csv
import math
import os
import sys
from dataclasses import dataclass


LEGS = ("onion", "lan")
REGISTERED_SAMPLES = 300
# Of either leg's connections, at least this share must complete.
COMPLETION_FLOOR = 0.95
# A side's "sent" stamp is taken when its write returns, which can follow
# the bytes' departure, so one side's round trip may read as slightly shorter
# than the other's turn. A shortfall up to this is not a disagreement; on
# loopback the largest seen was 0.6 µs.
AGREEMENT_SLACK_NS = 1_000_000
# Each deadline is this many times the onion leg's 99th percentile, rounded
# up to a whole second.
DEADLINE_FACTOR = 2

SERVER_STAMPS = (
    "message1_received_ns",
    "message2_sent_ns",
    "message3_received_ns",
    "message4_sent_ns",
    "first_record_opened_ns",
    "reply_sent_ns",
)
CLIENT_STAMPS = (
    "connected_ns",
    "message1_sent_ns",
    "message2_received_ns",
    "message3_sent_ns",
    "message4_received_ns",
    "first_record_sent_ns",
    "reply_received_ns",
)
SERVER_COLUMNS = ("accepted", "sample", "ok") + SERVER_STAMPS
CLIENT_COLUMNS = ("sample", "leg", "ok") + CLIENT_STAMPS

# The two deadlines, each from `accept` on the daemon's clock.
DEADLINES = (
    ("message 1", "message1_received_ns"),
    ("whole handshake", "first_record_opened_ns"),
)

CLOCKS = ("median", "p90", "p99", "max")
NS_PER_S = 1_000_000_000


def refuse(message):
    raise SystemExit(message)


def percentile(sorted_values, p):
    """Nearest-rank percentile of an ascending list, p in (0, 100]."""
    if not sorted_values:
        raise ValueError("no samples")
    rank = max(1, math.ceil(p / 100 * len(sorted_values)))
    return sorted_values[rank - 1]


def stats(values):
    ordered = sorted(values)
    return {
        "n": len(ordered),
        "median": percentile(ordered, 50),
        "p90": percentile(ordered, 90),
        "p99": percentile(ordered, 99),
        "max": ordered[-1],
    }


def ms(ns):
    return f"{ns / 1_000_000:,.1f}"


def deadline_seconds(p99_ns):
    """DEADLINE_FACTOR times a 99th percentile, rounded up to a second."""
    return -(-(DEADLINE_FACTOR * p99_ns) // NS_PER_S)


@dataclass(frozen=True)
class Pair:
    sample: int
    server: dict
    client: dict


@dataclass(frozen=True)
class Leg:
    name: str
    attempts: int
    pairs: list
    # Connections the daemon accepted that never reached the first record.
    unpaired_accepts: int

    @property
    def completion(self):
        return len(self.pairs) / self.attempts


def read_rows(path, columns):
    if not os.path.isfile(path):
        refuse(f"{path} is missing")
    with open(path, newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        if tuple(reader.fieldnames or ()) != columns:
            refuse(f"{path} has columns {reader.fieldnames}, not {list(columns)}")
        return list(reader)


def parse_u64(text, where):
    try:
        value = int(text)
    except ValueError:
        refuse(f"{where} is {text!r}")
    if value < 0:
        refuse(f"{where} is {value}")
    return value


def parse_ok(text, where):
    if text not in ("true", "false"):
        refuse(f"{where} ok is {text!r}")
    return text == "true"


def stamps_of(row, names, where, complete):
    """The row's stamps as integers. A complete row has every one, in
    order; a failed row has a prefix of them."""
    values = []
    for name in names:
        text = row[name]
        if text == "":
            break
        values.append(parse_u64(text, f"{where} {name}"))
    if complete and len(values) != len(names):
        refuse(f"{where} is ok but lacks {names[len(values)]}")
    if any(row[name] != "" for name in names[len(values):]):
        refuse(f"{where} has a stamp after a missing one")
    if values != sorted(values):
        refuse(f"{where} stamps go backwards")
    return dict(zip(names, values))


def load_leg(run_dir, name, expected_samples):
    leg_dir = os.path.join(run_dir, name)
    client_path = os.path.join(leg_dir, "client.tsv")
    server_path = os.path.join(leg_dir, "server.tsv")
    clients = read_rows(client_path, CLIENT_COLUMNS)
    servers = read_rows(server_path, SERVER_COLUMNS)

    if len(clients) != expected_samples:
        refuse(f"{client_path} has {len(clients)} samples, not {expected_samples}")
    client_by_sample = {}
    for index, row in enumerate(clients):
        where = f"{client_path} row {index}"
        if parse_u64(row["sample"], f"{where} sample") != index:
            refuse(f"{where} is numbered {row['sample']}")
        if row["leg"] != name:
            refuse(f"{where} names leg {row['leg']!r}")
        ok = parse_ok(row["ok"], where)
        client_by_sample[index] = (ok, stamps_of(row, CLIENT_STAMPS, where, ok))

    server_by_sample = {}
    unpaired = 0
    for index, row in enumerate(servers):
        where = f"{server_path} row {index}"
        if parse_u64(row["accepted"], f"{where} accepted") != index:
            refuse(f"{where} is accept {row['accepted']}")
        ok = parse_ok(row["ok"], where)
        stamps = stamps_of(row, SERVER_STAMPS, where, ok)
        if row["sample"] == "":
            if ok:
                refuse(f"{where} is ok but names no sample")
            unpaired += 1
            continue
        sample = parse_u64(row["sample"], f"{where} sample")
        if sample not in client_by_sample:
            refuse(f"{where} names sample {sample}, which the client never made")
        if sample in server_by_sample:
            refuse(f"{where} names sample {sample} a second time")
        server_by_sample[sample] = (ok, stamps)

    pairs = []
    for sample, (client_ok, client_stamps) in client_by_sample.items():
        server = server_by_sample.get(sample)
        server_ok = server is not None and server[0]
        if client_ok != server_ok:
            refuse(
                f"{name} sample {sample}: the client says ok={client_ok}, "
                f"the daemon ok={server_ok}"
            )
        if client_ok:
            pairs.append(Pair(sample, server[1], client_stamps))
    # A daemon row that names a sample but failed after the first record
    # (the reply could not be sent) counts as an accept that did not pair.
    unpaired += sum(1 for ok, _ in server_by_sample.values() if not ok)
    return Leg(name, len(clients), pairs, unpaired)


def disagreements(leg):
    """Completed samples whose two sides' stamps do not describe one
    exchange: a round trip on one side shorter than the other side's time
    between the same two messages, by more than AGREEMENT_SLACK_NS."""
    found = []
    for pair in leg.pairs:
        c, d = pair.client, pair.server
        client_rt = c["message2_received_ns"] - c["message1_sent_ns"]
        daemon_turn = d["message2_sent_ns"] - d["message1_received_ns"]
        daemon_rt = d["message3_received_ns"] - d["message2_sent_ns"]
        client_turn = c["message3_sent_ns"] - c["message2_received_ns"]
        if (
            client_rt + AGREEMENT_SLACK_NS < daemon_turn
            or daemon_rt + AGREEMENT_SLACK_NS < client_turn
        ):
            found.append(pair.sample)
    return found


@dataclass(frozen=True)
class Verdict:
    void_reasons: list

    @property
    def met(self):
        return not self.void_reasons


def judge(legs):
    reasons = []
    for leg in legs:
        if leg.completion < COMPLETION_FLOOR:
            reasons.append(
                f"{leg.name}: {len(leg.pairs)} of {leg.attempts} completed, "
                f"below {COMPLETION_FLOOR:.0%}"
            )
        bad = disagreements(leg)
        if bad:
            reasons.append(
                f"{leg.name}: the two sides disagree on samples {bad[:10]}"
                + (" and more" if len(bad) > 10 else "")
            )
    return Verdict(reasons)


def series(leg, side, column):
    return [getattr(pair, side)[column] for pair in leg.pairs]


def append_timing(lines, legs, side, columns):
    """One timing table. A leg with no completed handshake has nothing to
    summarise; its completion count is already in the table above."""
    for leg in legs:
        if not leg.pairs:
            continue
        for column in columns:
            summary = stats(series(leg, side, column))
            cells = " | ".join(ms(summary[c]) for c in CLOCKS)
            lines.append(f"| {leg.name} | {column[:-3]} | {summary['n']} | {cells} |")


def render(legs, verdict):
    lines = ["## Completion", ""]
    lines.append("| Leg | Connections | Completed | Share | Accepted by the daemon, not completed |")
    lines.append("|---|---:|---:|---:|---:|")
    for leg in legs:
        lines.append(
            f"| {leg.name} | {leg.attempts} | {len(leg.pairs)} | "
            f"{leg.completion:.1%} | {leg.unpaired_accepts} |"
        )
    lines += ["", "## The daemon, from `accept` (ms)", ""]
    lines.append("| Leg | Stamp | n | " + " | ".join(CLOCKS) + " |")
    lines.append("|---|---|---:|" + "---:|" * len(CLOCKS))
    append_timing(lines, legs, "server", SERVER_STAMPS)
    lines += ["", "## The client, from the start of its connect (ms)", ""]
    lines.append("| Leg | Stamp | n | " + " | ".join(CLOCKS) + " |")
    lines.append("|---|---|---:|" + "---:|" * len(CLOCKS))
    append_timing(lines, legs, "client", CLIENT_STAMPS)

    lines += ["", "## Gates", ""]
    if verdict.met:
        lines.append("Met: every leg completed at least "
                     f"{COMPLETION_FLOOR:.0%}, and on every completed sample the "
                     "two sides' stamps describe one exchange.")
    else:
        lines.append("**VOID.**")
        lines += [f"- {reason}" for reason in verdict.void_reasons]
        lines.append("")
        return "\n".join(lines) + "\n"

    by_name = {leg.name: leg for leg in legs}
    lines += ["", "## The deadlines", ""]
    lines.append(
        f"Each is {DEADLINE_FACTOR} × the onion leg's 99th percentile from "
        "`accept`, rounded up to a whole second. The LAN figure beside it "
        "is the same rule applied to the LAN leg, reported, not used."
    )
    lines.append("")
    lines.append("| Deadline | Onion p99 (ms) | Deadline (s) | LAN p99 (ms) | LAN by the same rule (s) |")
    lines.append("|---|---:|---:|---:|---:|")
    for label, column in DEADLINES:
        onion_p99 = stats(series(by_name["onion"], "server", column))["p99"]
        lan_p99 = stats(series(by_name["lan"], "server", column))["p99"]
        lines.append(
            f"| {label} | {ms(onion_p99)} | {deadline_seconds(onion_p99)} | "
            f"{ms(lan_p99)} | {deadline_seconds(lan_p99)} |"
        )
    return "\n".join(lines) + "\n"


def load(run_dir, expected_samples=REGISTERED_SAMPLES):
    return [load_leg(run_dir, name, expected_samples) for name in LEGS]


def summarise(run_dir, expected_samples=REGISTERED_SAMPLES):
    legs = load(run_dir, expected_samples)
    verdict = judge(legs)
    return render(legs, verdict), verdict


def main(argv):
    args = argv[1:]
    expected = REGISTERED_SAMPLES
    if args[:1] == ["--samples"] and len(args) >= 2:
        # For a dry run, which makes fewer than the registered count.
        expected = parse_u64(args[1], "--samples")
        args = args[2:]
    if len(args) != 1:
        print("usage: rt_p9_summary.py [--samples N] RUN_DIR", file=sys.stderr)
        return 2
    text, verdict = summarise(args[0], expected)
    print(text, end="")
    return 0 if verdict.met else 3


if __name__ == "__main__":
    sys.exit(main(sys.argv))
