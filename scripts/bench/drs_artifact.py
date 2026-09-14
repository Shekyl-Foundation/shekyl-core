#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# DRS-BENCH gate: artifact schema, refusals, §1.3 comparator, and the redb-engine
# blocker probe. The runner that produces artifacts is `drs_bench.py`.
#
# Subject: `docs/design/DAEMON_REDB_STORE.md` §7.4 against §1.3. An artifact is a
# record of every live axis under one set of measurement conditions; `check`
# refuses a ratio from two records that disagree about anything but the engine.

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DESIGN_DOC = os.path.join(ROOT, "docs/design/DAEMON_REDB_STORE.md")
ARTIFACT_GLOB = os.path.join(ROOT, "docs/benchmarks/drs_bench_ibd_*.json")

SCHEMA = "shekyl_drs_bench_v1"

# Frozen 2026-09-12 (DRS-0 slice C) BEFORE any measurement existed. Refining a
# ratio after seeing a number is a threshold CHANGE requiring reopening under
# rule 21. `FrozenThresholds` cross-checks every value against §1.3 in both
# directions; editing either side alone is a red.
FROZEN_AT = "ba4b3c73a"
REFERENCE_HEIGHT = 100_000
IBD_FLOOR_RATIO = 1.25       # <= passes
IBD_HARD_FAIL_RATIO = 1.50   # >  hard-fails after one documented mitigation cycle
PEAK_RSS_RATIO = 2.0         # <= passes

# Allowed set, not a spelling check: the daemon accepts `--db-sync-mode=saf` and
# silently means NOSYNC.
ALLOWED_SYNC_MODES = ("safe",)

# The daemon reports the durability posture it RESOLVED, as
#   Database sync: flags=0x1 (safe), sync_mode=0, threshold=1 blocks
# added for A4 (§4) so that the posture is "explicit rather than a library default
# reached by omission, and that is only checkable from a running node if the node
# says which flags it opened with". The harness reads that line out of the
# subject's own log, which is why `durability.observed` can now be TRUE: earlier
# revisions recorded `false` and said plainly that no readback existed, because
# `mdb_env_get_flags` is in-process and nothing logged the resolved mode. It does
# now, so the claim is measured instead of imposed-and-validated.
RESOLVED_SYNC_RE = r"Database sync: flags=0x([0-9a-f]+)([^,]*), sync_mode=(\d+)"
# Any of these in the resolved line means LMDB was opened without an fsync per
# commit, whatever was asked for.
NOSYNC_MARKERS = ("MDB_NOSYNC", "MDB_MAPASYNC")

# §1.3 requires the disk TYPE. "unknown" is not a type, so it is not a value.
ALLOWED_DISK_CLASSES = ("hdd", "ssd_or_nvme")

# How `disk_class` was established. "undetermined" is what the fingerprint reports
# when it could neither probe nor be told, and `measure` pre-flights that case and
# refuses to start — so an artifact carrying a real class beside an undetermined
# source did not come from `measure`, and is asserting a value nobody established.
# Requiring the provenance is what makes the pre-flight's guarantee CHECKABLE
# rather than merely true of the happy path.
ALLOWED_DISK_CLASS_SOURCES = ("probed", "operator-declared")

# SYSTEM LOAD IS A CONDITION OF A WALL-TIME MEASUREMENT, in the same class as
# `fs_type` and `disk_class`: not a detail, a thing without which the number does
# not mean what it says.
#
# Measured on this machine, same fixture, same inputs, only the machine's other
# work differing: idle gave 198.6-202.5 s wall at 751-758 CPU-s (3.74-3.79x);
# at a 5-minute load average of 8.6 on 16 cores the same run gave 272.7-311.1 s
# wall at 875-939 CPU-s (3.02-3.21x). So wall inflated 36-55% AND CPU inflated
# 16-24% -- CPU time is NOT a contention-robust substitute for a quiet machine,
# it only inflates less. A 1.25x floor is well inside that band, which is why the
# load has to be on the artifact rather than in someone's memory of the run.
#
# Recorded, NOT thresholded. §1.3 states no load limit and inventing one here
# would be exactly the pre-registration violation this harness exists to avoid;
# the rule is that a ratio needs two runs at comparable RECORDED load, and the
# artifact is what lets a reader check that.
LOADAVG_FIELDS = ("loadavg_1m_at_start", "loadavg_1m_at_end", "loadavg_5m_at_end")

ENGINE_DEFAULT_LMDB = "daemon-default-lmdb (no engine switch exists)"

# Every selector this gate knows, mapped to the engine it actually selects. An
# artifact's `engine` must equal the engine its selector selects, in BOTH
# directions: `redb` claimed under the LMDB default is a relabelled run, and
# `lmdb` claimed under a redb selector is equally incoherent -- the earlier check
# caught only the first, so a hand-authored artifact could pass by inverting it.
#
# There is deliberately NO redb entry. The runner has no engine selection path:
# it records ENGINE_DEFAULT_LMDB unconditionally because the daemon always opens
# LMDB. Until a real selection path exists and records its own provenance, an
# `engine: redb` artifact cannot be produced OR validated -- so the first run
# after DRS-E1 lands cannot spend a full measurement on LMDB and discover it at
# shutdown. Adding the engine here is part of wiring the redb arm, not a
# precondition for it.
ENGINE_SELECTORS = {ENGINE_DEFAULT_LMDB: "lmdb"}

# A STATED BOUND ON WHAT A FIXTURE GENERALISES TO, recorded for the same reason as
# `fs_type`: it is a condition of the measurement, not a detail.
#
# A coinbase-only chain holds no non-coinbase transaction, so it carries no
# transaction PRUNABLE REGION — the part of a tx covered by the
# `txs_prunable_hash` table that already exists in `db_lmdb.h`. Store-size and IBD
# figures taken on such a fixture are therefore measured on the block shape LEAST
# sensitive to any scheme that discards prunable bytes, and they do not transfer to
# a fixture containing transactions.
#
# Recorded as a TRIGGER rather than a conclusion: when a tx-bearing fixture exists,
# re-take the baseline instead of reusing these numbers — the store-work share of
# the total rises, and that share is what §1.3's ratio is trying to see.
PRUNABLE_ABSENT = ("absent by construction: coinbase-only fixture, no non-coinbase "
                   "transaction and therefore no txs_prunable_hash region")

# fsync against tmpfs/ramfs has no backing store to flush, so `safe` is
# indistinguishable from MDB_NOSYNC.
DURABILITY_DEFEATING_FS = ("tmpfs", "ramfs")

# Filesystems on which an fsync is believed to reach stable storage. Deliberately
# an ALLOWED SET rather than a denylist: over-inclusion here is a false red, which
# is safe, whereas a denylist of two values admits every placeholder -- "unknown",
# "undetermined", "" -- on the one field that decides whether DRS-D9 could hold at
# all. A filesystem absent from both lists is REFUSED rather than assumed, and
# adding one is a deliberate act with a reason, not a silent default.
DURABLE_FS = ("ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "jfs",
              "reiserfs", "ntfs3", "apfs", "hfsplus", "ufs", "overlay")

PRIMARY_MEASURE = "ibd_wall_time_s"
MEASURE_AXES = {
    "ibd_wall_time_s": {
        "axis": "wall_time", "unit": "s",
        "floor": IBD_FLOOR_RATIO, "hard": IBD_HARD_FAIL_RATIO,
    },
    "peak_rss_bytes": {
        "axis": "memory", "unit": "bytes",
        "floor": PEAK_RSS_RATIO, "hard": PEAK_RSS_RATIO,
    },
    "subject_cpu_s": {
        "axis": "cpu_time", "unit": "s",
        "floor": None, "hard": None,
        "no_threshold": "§1.3 sets no CPU-time threshold; the row exists so "
                        "compute-bound is an observation rather than an inference",
    },
    # Two disk rows because §1.3 names a file-size / logical-size ratio:
    # store_bytes is allocated (operator cost), store_bytes_apparent is file
    # length. They diverge when an engine leaves holes. Neither carries a
    # threshold — the ceiling is set after the first multi-year sim.
    "store_bytes": {
        "axis": "disk", "unit": "bytes",
        "floor": None, "hard": None,
        "no_threshold": "§1.3 states the file-size ceiling is set after the first "
                        "multi-year sim, so a verdict here would be invented",
    },
    "store_bytes_apparent": {
        "axis": "disk", "unit": "bytes",
        "floor": None, "hard": None,
        "no_threshold": "§1.3 states the file-size ceiling is set after the first "
                        "multi-year sim, so a verdict here would be invented",
    },
}

# Deferred measures. These are comments the harness can grep, not probes:
# a probe that cannot observe its own blocker would fire while the blocker
# still stood. The former mechanical probe (`redb_engine_sites` / a `new_db()`
# switch detector) was deleted 2026-09-14: the redb arm is a second BINARY,
# never a flag or a switch, so its blocker is a build target, carried in
# FOLLOWUPS.md with a falsifier.
FOLLOWON_MEASURES = {
    "pop_reorg_wall_time_s":
        "best-positioned follow-on: the /pop_blocks RPC already exists, so this "
        "needs a depth schedule and an artifact row, not a new capability.",
    "store_bytes_multi_year":
        "§1.3 states the file-size ceiling is 'set after first multi-year sim', "
        "so no threshold exists to gate against. A measure with no threshold "
        "emits a number with no verdict; landing it would create the appearance "
        "of coverage. Needs the ceiling first, which is a decision, not a "
        "measurement.",
    "free_page_reclaim":
        "needs a long-lived concurrent-reader workload; no such driver exists "
        "in tests/ or scripts/.",
    "peak_rss_attacker_feed":
        "§7.4 names 'attacker-shaped input' without defining it. Choosing a "
        "shape here would invent the threat model this measure is supposed to "
        "test. Needs a definition, which is a design round.",
}


def measure_row(name, value, scenario, denominator):
    """One `measures[]` object whose axis/unit come from MEASURE_AXES."""
    spec = MEASURE_AXES[name]
    return {"name": name, "axis": spec["axis"], "unit": spec["unit"],
            "value": value, "scenario": scenario, "denominator": denominator}


def artifact_refusals(a):
    """Reasons this artifact may not be used as a measurement. Empty == usable.

    Every entry is a condition §1.3 requires be RECORDED. The harness refuses
    to emit, and `check` refuses to read, an artifact missing any of them.
    """
    r = []
    if not isinstance(a, dict):
        return ["artifact is not a JSON object"]
    if a.get("schema_version") != SCHEMA:
        r.append(f"schema_version is {a.get('schema_version')!r}, expected {SCHEMA!r}")
    if a.get("engine") not in ("lmdb", "redb"):
        r.append(f"engine is {a.get('engine')!r}, expected 'lmdb' or 'redb'")
    sel = a.get("engine_selected_by")
    if not sel:
        r.append("engine_selected_by absent — an engine LABEL with no record of how the "
                 "engine was selected cannot be distinguished from a relabelled run")
    elif sel not in ENGINE_SELECTORS:
        r.append(f"engine_selected_by is {sel!r}, which this gate does not know. Known "
                 f"selectors: {sorted(ENGINE_SELECTORS)}. An unknown selector is an "
                 "unverifiable claim about which store was exercised; a redb selector "
                 "belongs here as part of wiring the redb arm, alongside the runner "
                 "path that actually selects it")
    elif a.get("engine") != ENGINE_SELECTORS[sel]:
        r.append(f"engine is {a.get('engine')!r} but engine_selected_by selects "
                 f"{ENGINE_SELECTORS[sel]!r}. The label and the mechanism disagree, so "
                 "one of them is false: as a candidate this would pass §1.3's floor at "
                 "a ratio near 1.0 without the claimed store being exercised at all")
    if a.get("thresholds_frozen_at") != FROZEN_AT:
        r.append(f"thresholds_frozen_at is {a.get('thresholds_frozen_at')!r}, not "
                 f"{FROZEN_AT!r} — this artifact was produced against a different "
                 "freeze era, and routing it through today's ratios would apply "
                 "thresholds it was not measured under")
    if not a.get("git_rev"):
        r.append("git_rev absent — a number with no tree is not reproducible")
    pin = a.get("thresholds_frozen_at")
    if pin != FROZEN_AT:
        r.append(f"thresholds_frozen_at is {pin!r}, expected {FROZEN_AT!r} — a number "
                 "taken under a different pin is not this gate's floor")

    d = a.get("durability")
    if not isinstance(d, dict):
        r.append("durability block absent — §1.3(3): artifacts MUST record durability "
                 "configuration, and DRS-D9 is the policy they must record")
    else:
        if d.get("sync_mode") not in ALLOWED_SYNC_MODES:
            r.append(f"durability.sync_mode is {d.get('sync_mode')!r}; only "
                     f"{list(ALLOWED_SYNC_MODES)} satisfies DRS-D9 on the LMDB path. A "
                     "value the daemon does not recognise falls through to DBF_FAST "
                     "(MDB_NOSYNC) in silence")
        argv = d.get("imposed_argv")
        if not isinstance(argv, list) or not argv:
            r.append("durability.imposed_argv absent — the harness cannot read the env "
                     "flags back, so the argv it imposed IS the record")
        elif not any(x == f"--db-sync-mode={d.get('sync_mode')}" for x in argv):
            r.append(f"durability.imposed_argv does not carry "
                     f"--db-sync-mode={d.get('sync_mode')}, so the recorded mode is not "
                     "the mode that was imposed")
        if d.get("observed") is not True:
            r.append("durability.observed must be true: the daemon reports the flags it "
                     "resolved (A4's enabler), so the posture is observable and an "
                     "artifact that does not observe it is not recording a condition it "
                     "could have measured")
        line = d.get("resolved_log_line")
        if not isinstance(line, str) or not re.search(RESOLVED_SYNC_RE, line):
            r.append(f"durability.resolved_log_line is {str(line)[:60]!r}, which does "
                     "not carry the daemon's resolved sync report. That line IS the "
                     "readback; without it the recorded mode is only what was asked for")
        else:
            hit = [m for m in NOSYNC_MARKERS if m in line]
            if hit:
                r.append(f"durability.resolved_log_line reports {hit} — the store was "
                         f"opened WITHOUT an fsync per commit, so DRS-D9 was not in "
                         f"force whatever sync_mode was requested: {line.strip()[:120]}")
            elif "(safe)" not in line:
                r.append(f"durability.resolved_log_line does not report the safe flag, "
                         f"so the resolved posture is not DRS-D9's: {line.strip()[:120]}")

    env = a.get("environment")
    if not isinstance(env, dict):
        r.append("environment block absent — system load during the run is a condition "
                 "of a wall-time measurement, not a detail: the same fixture on this "
                 "machine moved 36-55% on wall and 16-24% on CPU between an idle box "
                 "and a 5-minute load average of 8.6")
    else:
        for k in LOADAVG_FIELDS:
            v = env.get(k)
            # `isinstance(v, (int, float))` alone is NOT enough, and shipping that was
            # this file's third placeholder defect: the producer's failure sentinel was
            # -1.0, which is a number and so validated as a real load. A load average
            # cannot be negative, so the range check is what makes the type check mean
            # something. The producer no longer emits a numeric sentinel either; this
            # is the second line of defence, for an artifact written by hand.
            if not isinstance(v, (int, float)) or isinstance(v, bool) or v < 0:
                r.append(f"environment.{k} is {v!r} — a wall-time figure whose "
                         "contention is unrecorded, or recorded as an impossible "
                         "negative load, cannot be compared against another")
        if not isinstance(env.get("cpu_count"), int) or env["cpu_count"] < 1:
            r.append("environment.cpu_count absent — a load average means nothing "
                     "without the core count it is relative to")

    h = a.get("hardware")
    if not isinstance(h, dict):
        r.append("hardware block absent — §1.3 requires CPU model, RAM and disk type "
                 "in the artifact")
    else:
        for k in ("cpu_model", "ram_bytes", "disk_class"):
            if not h.get(k):
                r.append(f"hardware.{k} absent or empty")
        src = h.get("disk_class_source")
        if src not in ALLOWED_DISK_CLASS_SOURCES:
            r.append(f"hardware.disk_class_source is {src!r}, not one of "
                     f"{list(ALLOWED_DISK_CLASS_SOURCES)} — a disk class with no record "
                     "of how it was established cannot be told from one asserted by "
                     "hand, and 'undetermined' beside a real class is a value nobody "
                     "established")
        if h.get("disk_class") and h["disk_class"] not in ALLOWED_DISK_CLASSES:
            r.append(f"hardware.disk_class is {h['disk_class']!r}, not one of "
                     f"{list(ALLOWED_DISK_CLASSES)}. §1.3 requires the disk TYPE; a "
                     "placeholder satisfies the field without satisfying the "
                     "requirement")
        fs = h.get("fs_type")
        if not fs:
            r.append("hardware.fs_type absent — it decides whether DRS-D9 could hold "
                     "at all, so it is a measurement condition and not a detail")
        elif fs in DURABILITY_DEFEATING_FS:
            r.append(f"hardware.fs_type is {fs!r}: fsync there has no backing store to "
                     "flush, so DRS-D9 durability was NOT in force and this is a "
                     "RAM-disk number, not a strict-durability baseline")
        elif fs not in DURABLE_FS:
            r.append(f"hardware.fs_type is {fs!r}, which this gate neither trusts nor "
                     f"rejects. Known-durable: {list(DURABLE_FS)}; known-defeating: "
                     f"{list(DURABILITY_DEFEATING_FS)}. Refused rather than assumed — "
                     "this field decides whether DRS-D9 could hold, and a placeholder "
                     "like 'unknown' would otherwise satisfy it. Add the filesystem "
                     "deliberately if fsync reaches stable storage there")

    f = a.get("fixture")
    if not isinstance(f, dict):
        r.append("fixture block absent")
    else:
        if not f.get("nettype"):
            r.append("fixture.nettype absent")
        hr = f.get("height_reached")
        if not isinstance(hr, int) or hr <= 0:
            r.append(f"fixture.height_reached is {hr!r} — a run that reached no height "
                     "produced no measurement")
        if not isinstance(f.get("height_requested"), int):
            r.append("fixture.height_requested absent — without it the artifact cannot "
                     "say whether it fell short of §1.3's reference height")
        v = f.get("verify_exercised")
        if not isinstance(v, dict) or not all(k in v for k in ("pow", "fcmp_pp")):
            r.append("fixture.verify_exercised must state pow and fcmp_pp explicitly; "
                     "§1.3's primary metric names both and a coinbase-only fixture "
                     "exercises only one")
        elif not all(isinstance(v[k], bool) for k in ("pow", "fcmp_pp")):
            # Values, not just keys. `fcmp_pp: "false"` is a TRUTHY string: it would
            # satisfy a presence check and then suppress the shortfall in compare(),
            # letting an artifact claim full verification and take a passing floor.
            r.append(f"fixture.verify_exercised must use real booleans, got "
                     f"{ {k: type(v[k]).__name__ for k in ('pow', 'fcmp_pp')} } — a "
                     "truthy string such as \"false\" satisfies a key check and then "
                     "silently suppresses the verification shortfall")
        if "tx_per_block" not in f:
            r.append("fixture.tx_per_block absent — it is the reason fcmp_pp is not "
                     "exercised, so it belongs in the record")
        # Cross-check against tx_per_block, able to disagree in BOTH directions: a
        # coinbase-only fixture must report the prunable region absent, and a
        # tx-bearing one must not claim absence-by-construction. Either field
        # changing alone is a red, which is what separates this from a restatement
        # of tx_per_block.
        pr = f.get("prunable_region")
        if not pr:
            r.append("fixture.prunable_region absent — it bounds what this baseline "
                     "generalises to, a fixture with no prunable region being the "
                     "block shape least sensitive to discarding prunable bytes")
        elif f.get("tx_per_block") == 0 and pr != PRUNABLE_ABSENT:
            r.append(f"fixture.tx_per_block is 0 but prunable_region says {pr[:60]!r}; "
                     "a coinbase-only fixture has no prunable region to report")
        elif isinstance(f.get("tx_per_block"), int) and f["tx_per_block"] > 0 \
                and pr == PRUNABLE_ABSENT:
            r.append(f"fixture.tx_per_block is {f['tx_per_block']} but prunable_region "
                     "claims absence by construction, which holds only for a "
                     "coinbase-only fixture")
        # The generation pair, cross-checked in BOTH directions. These fields are
        # legitimately ABSENT when the seed was reused and nothing was generated —
        # that is the point of recording them — so the rule is consistency, not
        # presence: blocks generated implies a positive observed duration, and no
        # blocks generated implies no duration. Either alone is a run reporting
        # work it did not time, or a time for work it did not do.
        # The subject syncs to the seed's tip, so these are the same number. A
        # divergence means either a partial sync (which `measure` refuses outright)
        # or an artifact edited after the fact; both make the height unusable as the
        # comparability key it is.
        sh, hr = f.get("seed_height"), f.get("height_reached")
        if isinstance(sh, int) and isinstance(hr, int) and sh != hr:
            r.append(f"fixture.seed_height is {sh} but height_reached is {hr} — the "
                     "subject syncs to the seed's tip, so a difference means the run "
                     "did not converge or the record was altered")

        gb, gw = f.get("blocks_generated"), f.get("generation_wall_s")
        if isinstance(gb, int) and gb > 0:
            if not isinstance(gw, (int, float)) or isinstance(gw, bool) or gw <= 0:
                r.append(f"fixture.blocks_generated is {gb} but generation_wall_s is "
                         f"{gw!r} — blocks were generated and their duration was not "
                         "observed, so any rate derived from this pair is invented")
        elif gw is not None:
            r.append(f"fixture.generation_wall_s is {gw!r} while blocks_generated is "
                     f"{gb!r} — a generation duration with no blocks generated")

        peers = f.get("peers_used")
        if not isinstance(peers, int) or peers < 1:
            r.append(f"fixture.peers_used is {peers!r} — IBD wall time scales with the "
                     "peer count, so a missing or zero count is not a measurement of "
                     "the same experiment")

    ms = a.get("measures")
    if not isinstance(ms, list) or not ms:
        r.append("measures absent or empty")
        return r
    seen = []
    for i, m in enumerate(ms):
        if not isinstance(m, dict):
            r.append(f"measures[{i}] is not an object")
            continue
        name = m.get("name")
        if name not in MEASURE_AXES:
            r.append(f"measures[{i}].name is {name!r}, not one of "
                     f"{sorted(MEASURE_AXES)}")
            continue
        if name in seen:
            r.append(f"measures name {name!r} is duplicated")
        seen.append(name)
        spec = MEASURE_AXES[name]
        val = m.get("value")
        if not isinstance(val, (int, float)) or val <= 0:
            r.append(f"measures[{i}] ({name}) value is {val!r} — a zero or negative "
                     "figure is a failed observation, not a measurement")
        if m.get("axis") != spec["axis"]:
            r.append(f"measures[{i}] ({name}) axis is {m.get('axis')!r}, expected "
                     f"{spec['axis']!r} — state the axis a figure is on")
        if m.get("unit") != spec["unit"]:
            r.append(f"measures[{i}] ({name}) unit is {m.get('unit')!r}, expected "
                     f"{spec['unit']!r}")
        if not m.get("scenario"):
            r.append(f"measures[{i}] ({name}) scenario absent — an IBD RSS figure "
                     "must not be readable as §7.4's attacker-feed row")
    missing = [n for n in MEASURE_AXES if n not in seen]
    if missing:
        r.append(f"measures missing required {missing} — an artifact is a record of "
                 "every live axis, not a bag of rows; omitting a thresholded axis "
                 "would skip its floor")
    return r


def _masked_argv(a):
    """Subject argv with engine- and path-specific arguments removed.

    §1.3: "same machine, same binary flags except engine". Data directory and
    ports differ between the two runs by construction and say nothing about the
    engine, so they are masked; everything else must match.
    """
    out = []
    for x in a.get("durability", {}).get("imposed_argv", []):
        # No engine flag is masked: the daemon has none. Masking a speculative
        # `--db-engine` would hide a real difference the day one exists, and the
        # mask belongs in the same change that adds the flag.
        if re.match(r"^--(data-dir|p2p-bind-port|rpc-bind-port|add-exclusive-node|"
                    r"log-file)=", x):
            continue
        out.append(x)
    return out


def _durability_policy(a):
    """The durability block minus the argv, which is compared under the mask."""
    d = dict(a.get("durability", {}))
    d.pop("imposed_argv", None)
    return d


def comparability_refusals(base, cand):
    """Reasons these two artifacts cannot produce a §1.3 ratio."""
    r = []
    for field in ("thresholds_frozen_at",):
        if base.get(field) != cand.get(field):
            r.append(f"{field} differs ({base.get(field)!r} vs {cand.get(field)!r}) — "
                     "the two runs were measured against different frozen thresholds")
    if base.get("git_rev") != cand.get("git_rev"):
        r.append(f"git_rev differs ({str(base.get('git_rev'))[:9]} vs "
                 f"{str(cand.get('git_rev'))[:9]}) — §1.3 requires the same binary and "
                 "flags with only the engine differing, so a ratio across trees can "
                 "attribute a consensus or code change to the engine")
    if base.get("engine") == cand.get("engine"):
        r.append(f"both artifacts are engine={base.get('engine')!r}; §1.3's floor is a "
                 "ratio BETWEEN engines. Two same-engine runs are a regression "
                 "comparison, which this gate does not define thresholds for")
    if base.get("hardware") != cand.get("hardware"):
        r.append("hardware blocks differ — cross-machine absolute times are not "
                 "load-bearing, so a ratio across machines is not the floor §1.3 froze")
    # imposed_argv lives inside the durability block but is compared SEPARATELY,
    # under the path/port mask: the two runs differ in data directory and ports
    # by construction. Comparing the block wholesale would refuse every real pair.
    if _durability_policy(base) != _durability_policy(cand):
        r.append("durability blocks differ — a ratio between different durability "
                 "policies measures the policy, not the engine")
    bf, cf = base.get("fixture", {}), cand.get("fixture", {})
    # NOT compared, deliberately, and both would be false reds:
    #   height_requested -- two runs that ASKED for different heights but REACHED the
    #     same one did the same work, and `height_reached` is what is compared.
    #   schema_version -- both artifacts are validated against SCHEMA individually,
    #     so they cannot differ while both are usable.
    # Left alone rather than mechanically added: a refusal that cannot correspond to
    # a real difference trains readers to ignore refusals.
    for k in ("nettype", "height_reached", "reference_height", "verify_exercised",
              "tx_per_block", "peers_used", "prunable_region"):
        if bf.get(k) != cf.get(k):
            r.append(f"fixture.{k} differs ({bf.get(k)!r} vs {cf.get(k)!r}) — the two "
                     "runs did not do the same work")
    if _masked_argv(base) != _masked_argv(cand):
        r.append("subject argv differs beyond engine and paths: "
                 f"{_masked_argv(base)} vs {_masked_argv(cand)}")
    bn = {m["name"] for m in base.get("measures", []) if isinstance(m, dict)}
    cn = {m["name"] for m in cand.get("measures", []) if isinstance(m, dict)}
    if PRIMARY_MEASURE not in bn & cn:
        r.append(f"{PRIMARY_MEASURE} is not present on both artifacts; it is §1.3's "
                 "primary metric and the floor is defined on it")
    needed = {n for n, s in MEASURE_AXES.items() if s["floor"] is not None}
    skipped = sorted(needed - (bn & cn))
    if skipped:
        r.append(f"thresholded measures {skipped} are not present on both artifacts; "
                 "omitting one skips its floor")
    return r


def saturation_notes(a, tag):
    """Contention notes for one artifact. Empty when the machine was not saturated.

    `loadavg > cpu_count` is the DEFINITION of more runnable work than cores, not a
    threshold anyone chose, which is why it is safe to report here: §1.3 states no
    load limit and inventing one would be the pre-registration violation this
    harness exists to prevent. So this SURFACES contention and never changes a
    verdict. Measured on this machine, same fixture and inputs: 198.6-202.5 s wall
    idle against 415.8 s at a 1-minute load of 27 on 16 cores. A 1.25x floor is
    far inside that, so a ratio taken across two differently-loaded runs measures
    the machine's other work.
    """
    env = a.get("environment") or {}
    n = env.get("cpu_count") or 0
    out = []
    for k in ("loadavg_1m_at_start", "loadavg_1m_at_end"):
        v = env.get(k)
        if isinstance(v, (int, float)) and n and v > n:
            out.append(f"{tag}: {k} was {v:.2f} on {n} cores — the machine had more "
                       f"runnable work than cores, so this run's ABSOLUTE wall time is "
                       f"contention-inflated and is not a reference figure")
    return out


def compare(base, cand):
    """The §1.3 verdict. Callers must have validated both artifacts first."""
    bm = {m["name"]: m["value"] for m in base["measures"]}
    cm = {m["name"]: m["value"] for m in cand["measures"]}
    rows, worst = [], "PASS"
    rank = {"PASS": 0, "BAND": 1, "OVER": 2, "NO_THRESHOLD": 0}
    for name in sorted(bm.keys() & cm.keys()):
        spec = MEASURE_AXES[name]
        axis, unit, floor, hard = spec["axis"], spec["unit"], spec["floor"], spec["hard"]
        b, c = bm[name], cm[name]
        if b == 0:
            if floor is None:
                v, note = "NO_THRESHOLD", "baseline is zero; a ratio would be undefined"
            else:
                v, note = "OVER", ("baseline is zero; a ratio is undefined so this "
                                   "cannot pass the floor")
            rows.append({"name": name, "axis": axis, "unit": unit, "baseline": b,
                         "candidate": c, "ratio": None, "verdict": v, "note": note})
            if rank[v] > rank[worst]:
                worst = v
            continue
        ratio = c / b
        if floor is None:
            v, note = "NO_THRESHOLD", spec.get("no_threshold", "§1.3 states no threshold")
        elif ratio <= floor:
            v, note = "PASS", f"<= {floor}x floor"
        elif ratio > hard:
            v, note = "OVER", (f"> {hard}x — hard fail under §1.3 AFTER one documented "
                               "mitigation cycle. Whether that cycle has happened is a "
                               "human record, not a field here")
        else:
            v, note = "BAND", (f"between {floor}x and {hard}x — §1.3 makes this a "
                               "decision-log call: accept or mitigate")
        rows.append({"name": name, "axis": axis, "unit": unit, "baseline": b,
                     "candidate": c, "ratio": round(ratio, 4), "verdict": v,
                     "note": note})
        if rank[v] > rank[worst]:
            worst = v
    short = []
    for a, tag in ((base, "baseline"), (cand, "candidate")):
        f = a["fixture"]
        if f["height_reached"] < REFERENCE_HEIGHT:
            short.append(f"{tag} reached height {f['height_reached']} of §1.3's "
                         f"reference {REFERENCE_HEIGHT}")
        if not f["verify_exercised"].get("fcmp_pp"):
            short.append(f"{tag} exercised NO FCMP++ verification "
                         f"(tx_per_block={f.get('tx_per_block')})")
        if not f["verify_exercised"].get("pow"):
            # §1.3's primary metric names PoW as well, and a run without it is a
            # different experiment -- previously recorded and never surfaced.
            short.append(f"{tag} exercised NO PoW verification, which §1.3's primary "
                         "metric requires as in real sync")
    contention = (saturation_notes(base, "baseline") +
                  saturation_notes(cand, "candidate"))
    benv, cenv = base.get("environment") or {}, cand.get("environment") or {}
    load_note = (f"baseline load {benv.get('loadavg_1m_at_start')}->"
                 f"{benv.get('loadavg_1m_at_end')}, candidate load "
                 f"{cenv.get('loadavg_1m_at_start')}->{cenv.get('loadavg_1m_at_end')} "
                 f"on {benv.get('cpu_count')} cores. §1.3 sets no load limit, so this is "
                 f"reported and NOT thresholded; a ratio needs two runs at comparable "
                 f"recorded load")
    return {"schema_version": "shekyl_drs_bench_compare_v1",
            "load_conditions": load_note, "contention_notes": contention,
            "thresholds_frozen_at": FROZEN_AT, "baseline_engine": base["engine"],
            "candidate_engine": cand["engine"], "rows": rows, "verdict": worst,
            "fixture_shortfalls": short}




def fs_type(path):
    """Filesystem type backing `path`, by longest matching mount point."""
    real = os.path.realpath(path)
    best, best_type = "", ""
    try:
        with open("/proc/mounts", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 3:
                    continue
                mp = parts[1].replace("\\040", " ")
                if (real == mp or real.startswith(mp.rstrip("/") + "/")) and \
                        len(mp) > len(best):
                    best, best_type = mp, parts[2]
    except OSError:
        return ""
    return best_type


def probe_disk_class(path):
    """'hdd' / 'ssd_or_nvme' from sysfs, or None when it cannot be determined.

    Returns None rather than a placeholder so the caller must decide. btrfs,
    zfs and overlay present an anonymous st_dev with no /sys/dev/block entry.
    """
    try:
        st = os.stat(path)
        maj, mnr = os.major(st.st_dev), os.minor(st.st_dev)
        for rot in (f"/sys/dev/block/{maj}:{mnr}/queue/rotational",
                    f"/sys/dev/block/{maj}:{mnr}/../queue/rotational"):
            if os.path.exists(rot):
                with open(rot, encoding="utf-8") as fh:
                    return "hdd" if fh.read().strip() == "1" else "ssd_or_nvme"
    except OSError:
        pass
    return None


def hardware_fingerprint(path, declared_disk_class=None):
    """CPU / RAM / disk / fs fingerprint. disk_class is omitted until known.

    Does not emit 'unknown': that placeholder is what let a tmpfs run publish
    a figure, and a required field that can hold it cannot fail.
    """
    cpu = ""
    with open("/proc/cpuinfo", encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    ram = 0
    with open("/proc/meminfo", encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("MemTotal:"):
                ram = int(line.split()[1]) * 1024
                break
    probed = probe_disk_class(path)
    if probed:
        disk, source = probed, "probed"
    elif declared_disk_class:
        disk, source = declared_disk_class, "operator-declared"
    else:
        disk, source = None, "undetermined"
    out = {"cpu_model": cpu, "ram_bytes": ram, "disk_class_source": source,
           "fs_type": fs_type(path), "cpu_count": os.cpu_count()}
    if disk is not None:
        out["disk_class"] = disk
    return out


def measurement_preflight(sync_mode, daemon, work_dir, seed_dir, disk_class):
    """Refusals that must fire before any daemon starts or cargo runs.

    Same conditions `artifact_refusals` will apply to the finished record, so
    a day of generation is not spent on a number the gate would decline.
    """
    r = []
    if sync_mode not in ALLOWED_SYNC_MODES:
        r.append(f"--sync-mode={sync_mode!r} refused before any daemon was started. "
                 f"Only {list(ALLOWED_SYNC_MODES)} satisfies DRS-D9, and the daemon "
                 "accepts an unrecognised value by silently falling back to DBF_FAST "
                 "(MDB_NOSYNC), so a typo here would measure the wrong durability "
                 "and say nothing.")
    if not os.path.isfile(daemon):
        r.append(f"{daemon} is not a file — build the daemon in THIS worktree; a "
                 "binary from another tree measures another tree")
    for label, d in (("--work-dir", work_dir), ("--seed-dir", seed_dir)):
        if not d:
            continue
        fs = fs_type(d)
        if fs in DURABILITY_DEFEATING_FS:
            r.append(f"{label}={d} is on {fs}, where fsync has no backing store to "
                     "flush. DRS-D9 durability cannot hold there, so the run would "
                     "produce a RAM-disk number labelled as a strict-durability "
                     "baseline. Point it at real storage.")
    if work_dir and probe_disk_class(work_dir) is None and not disk_class:
        r.append(f"the disk class of {work_dir} could not be probed: its filesystem "
                 f"({fs_type(work_dir) or 'unreadable'}) reports no sysfs "
                 "queue/rotational node, which is normal for btrfs, zfs and overlay. "
                 "§1.3 requires the disk type in the artifact and the validator "
                 "refuses a placeholder, so pass --disk-class hdd|ssd_or_nvme. It is "
                 "recorded as operator-declared, not probed.")
    return r
