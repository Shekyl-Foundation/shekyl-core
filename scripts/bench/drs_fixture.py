#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The one synthetic DRS-bench artifact. Both selftests build from this.
# A second copy would let one module's control pass a fixture the other
# module's gate has already refused.

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import drs_artifact as D  # noqa: E402


# The two readbacks, as each store writes them at open. The LMDB line is
# `core::init`'s; the redb line is the Rust node's `store_durability_line`.
LMDB_READBACK = ("2026-09-13T00:00:00Z INFO global: Database sync: "
                 "flags=0x1 (safe), sync_mode=3, threshold=1 blocks")
REDB_READBACK = ("2026-10-30T13:35:30.989265Z  INFO shekyl_node: Store durability: "
                 "immediate (an fsync per commit, DRS-D9; redb Durability::Immediate)")


def hex_fill(byte):
    """`HASH_HEX_CHARS` lowercase hex digits, every byte the same.

    A block hash and a sha256 are that spelling. The fill is how a test
    names one without writing the digit out `HASH_HEX_CHARS` times.
    """
    if isinstance(byte, bool) or not isinstance(byte, int) or not 0 <= byte <= 0xFF:
        raise ValueError(f"{byte!r} is not a byte")
    return f"{byte:02x}" * (D.HASH_HEX_CHARS // 2)


# One chain tip and two binary identities. The comparability control needs
# both sides to name the same tip. The hashes are provenance: they may
# differ, and the pair still compares.
TIP_HASH = hex_fill(0xAB)
SUBJECT_SHA256 = hex_fill(0xCD)
SEED_SHA256 = hex_fill(0xEF)


def valid_artifact(engine="lmdb", **over):
    a = {
        "schema_version": D.SCHEMA,
        "engine": engine,
        "engine_selected_by": D.ENGINE_DEFAULT_LMDB if engine == "lmdb" else
                              D.ENGINE_DEFAULT_REDB,
        "git_rev": "0123456789abcdef",
        "thresholds_frozen_at": D.FROZEN_AT,
        "durability": {
            "policy": "DRS-D9 full-fsync-per-commit",
            "sync_mode": "safe" if engine == "lmdb" else "immediate",
            "imposed_argv": ["--network", "regtest", "--dev-difficulty", "1",
                             "--data-dir", "/x/subject",
                             "--clearnet-listen", "127.0.0.1:1",
                             "--rpc-admin-listen", "127.0.0.1:2",
                             "--p2p-closed-peer", "127.0.0.1:3"],
            "observed": True,
            "resolved_log_line": LMDB_READBACK if engine == "lmdb" else REDB_READBACK,
            "readback": D.durability_readback_note(True),
        },
        "environment": {"loadavg_1m_at_start": 0.3, "loadavg_1m_at_end": 0.4,
                        "loadavg_5m_at_end": 0.35, "cpu_count": 8,
                        "note": "quiet"},
        "hardware": {"cpu_model": "Test CPU", "ram_bytes": 1 << 34,
                     "disk_class": "ssd_or_nvme", "disk_class_source": "probed",
                     "fs_type": "ext4", "cpu_count": 8},
        "fixture": {
            "nettype": "fakechain", "height_reached": 200, "height_requested": 200,
            "top_block_hash": TIP_HASH,
            "subject_binary_sha256": SUBJECT_SHA256,
            "seed_binary_sha256": SEED_SHA256,
            "reference_height": D.REFERENCE_HEIGHT, "tx_per_block": 0,
            "prunable_region": D.PRUNABLE_ABSENT,
            "verify_exercised": {"pow": True, "fcmp_pp": False},
            "seed_height": 200, "peers_used": 1,
        },
        "probe": {"window_s": 100.0, "samples": 100, "median_ms": 1.2,
                  "p99_ms": 9.0, "max_ms": 40.0, "stall_ms": 1500.0, "stalls": 0,
                  "stalled_s": 0.0, "first_stall_t": None},
        "measures": [
            {"name": "ibd_wall_time_s", "axis": "wall_time", "unit": "s",
             "value": 100.0, "scenario": "ibd_coinbase_only"},
            {"name": "subject_cpu_s", "axis": "cpu_time", "unit": "s",
             "value": 400.0, "scenario": "ibd_coinbase_only"},
            {"name": "peak_rss_bytes", "axis": "memory", "unit": "bytes",
             "value": 1 << 30, "scenario": "ibd_coinbase_only"},
            {"name": "store_bytes", "axis": "disk", "unit": "bytes",
             "value": 1 << 20, "scenario": "ibd_coinbase_only"},
            {"name": "store_bytes_apparent", "axis": "disk", "unit": "bytes",
             "value": 1 << 20, "scenario": "ibd_coinbase_only"},
        ],
    }
    a.update(over)
    return a
