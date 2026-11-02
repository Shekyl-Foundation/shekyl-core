#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The durability readback and the seed binary. Split from
# `test_drs_bench.py` so that file stays the refusals and the comparison.
# The synthetic artifact both files mutate is `drs_fixture.valid_artifact`.

import hashlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import drs_artifact as D  # noqa: E402
import drs_bench as R  # noqa: E402
from drs_fixture import (LMDB_READBACK, REDB_READBACK,  # noqa: E402
                         valid_artifact)


class SeedDaemon(unittest.TestCase):
    """`--seed-daemon` is the archived C++ binary. The subject is `--daemon`.

    A missing default would make the baseline run a different seed from the
    one this file's other tests assume, and a seed that followed the subject
    after the flip would regenerate the chain instead of serving the LMDB
    the C++ wrote.
    """

    def test_an_unnamed_seed_binary_is_the_subject_binary(self):
        self.assertEqual(R.binary_for("seed", "/tree/shekyld", None),
                         "/tree/shekyld")
        self.assertEqual(R.binary_for("subject", "/tree/shekyld", None),
                         "/tree/shekyld")

    def test_the_seed_binary_is_not_used_for_the_subject(self):
        self.assertEqual(R.binary_for("seed", "/flip/shekyld", "/archive/shekyld"),
                         "/archive/shekyld")
        self.assertEqual(R.binary_for("subject", "/flip/shekyld", "/archive/shekyld"),
                         "/flip/shekyld")


class RedbReadback(unittest.TestCase):
    def test_the_redb_selector_is_the_readback_and_nothing_else(self):
        """The redb arm (the flip binary, DRS-X) has one selection path: the
        daemon's own readback names the store it opened. A redb artifact
        validates under that selector alone; under the LMDB default, a
        flag that never existed, or an unknown word it is refused."""
        self.assertEqual(D.ENGINE_SELECTORS[D.ENGINE_DEFAULT_REDB], "redb")
        self.assertEqual(D.artifact_refusals(valid_artifact("redb")), [])
        for sel in [D.ENGINE_DEFAULT_LMDB, "--db-engine=redb", "whatever"]:
            a = valid_artifact("redb")
            a["engine_selected_by"] = sel
            self.assertTrue(D.artifact_refusals(a),
                            f"an engine=redb artifact validated under selector {sel!r}")

    def test_refuses_an_engine_label_the_readback_contradicts(self):
        """The readback is the selection mechanism, so a label it does not
        name is a relabelled run whichever way it is turned."""
        a = valid_artifact("lmdb")
        a["durability"]["resolved_log_line"] = REDB_READBACK
        a["durability"]["sync_mode"] = "immediate"
        r = D.artifact_refusals(a)
        self.assertTrue(any("readback names" in x and "redb" in x for x in r), r)
        b = valid_artifact("redb")
        b["durability"]["resolved_log_line"] = LMDB_READBACK
        b["durability"]["sync_mode"] = "safe"
        r = D.artifact_refusals(b)
        self.assertTrue(any("readback names" in x and "lmdb" in x for x in r), r)

    def test_refuses_a_redb_store_opened_without_an_fsync_per_commit(self):
        """redb's `Eventual` and `None` defer the fsync; only `Immediate` is
        DRS-D9. The line's two spellings must also agree."""
        for variant in ("Eventual", "None"):
            a = valid_artifact("redb")
            a["durability"]["sync_mode"] = variant.lower()
            a["durability"]["resolved_log_line"] = (
                f"INFO shekyl_node: Store durability: {variant.lower()} (an fsync per "
                f"commit, DRS-D9; redb Durability::{variant})")
            r = D.artifact_refusals(a)
            self.assertTrue(any("WITHOUT an fsync" in x for x in r), (variant, r))
        a = valid_artifact("redb")
        a["durability"]["resolved_log_line"] = (
            "INFO shekyl_node: Store durability: immediate (an fsync per commit, "
            "DRS-D9; redb Durability::Eventual)")
        r = D.artifact_refusals(a)
        self.assertTrue(any("do not name the same" in x for x in r), r)


class ReadbackLine(unittest.TestCase):
    def test_one_parse_names_the_store_and_the_open(self):
        """Engine, mode, and the DRS-D9 verdict are one value. A second
        parse of the same line cannot disagree with the first."""
        lmdb = D.readback_of(LMDB_READBACK)
        self.assertEqual((lmdb.engine, lmdb.mode, lmdb.refusals), ("lmdb", "safe", ()))
        redb = D.readback_of(REDB_READBACK)
        self.assertEqual((redb.engine, redb.mode, redb.refusals),
                         ("redb", "immediate", ()))
        self.assertIsNone(D.readback_of(None))
        self.assertIsNone(D.readback_of("nothing"))

    def test_resolved_line_reader_ignores_nothing_and_strips_ansi(self):
        """The readback reader: it must find the daemon's colourised line and return
        it without terminal control bytes, and return None when the line is absent
        rather than a stand-in."""
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as fh:
            fh.write("\x1b[2mts\x1b[0m \x1b[32m INFO\x1b[0m global: Database sync: "
                     "flags=0x1 (safe), sync_mode=3, threshold=1 blocks\n")
            good = fh.name
        self.addCleanup(os.unlink, good)
        line = R._resolved_sync_line(good)
        self.assertIsNotNone(line)
        self.assertNotIn("\x1b", line)
        self.assertIn("flags=0x1 (safe)", line)
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as fh:
            fh.write("nothing relevant here\n")
            bare = fh.name
        self.addCleanup(os.unlink, bare)
        self.assertIsNone(R._resolved_sync_line(bare))
        self.assertIsNone(R._resolved_sync_line("/nonexistent/x.log"))

    def test_resolved_line_reader_reads_the_rust_stores_report(self):
        """The flip binary writes its readback through tracing to the log
        file it is given, not to the console; the reader must know the line."""
        d = tempfile.mkdtemp()
        log = os.path.join(d, "subject.daemon.log")
        with open(log, "w", encoding="utf-8") as fh:
            fh.write("other\n" + REDB_READBACK + "\n")
        line = R._resolved_sync_line(log)
        self.assertIsNotNone(line)
        self.assertIn("Durability::Immediate", line)
        self.assertEqual(D.resolved_sync_mode(line), "immediate")
        self.assertEqual(D.engine_of_line(line), "redb")
        self.assertEqual(D.engine_of_line(LMDB_READBACK), "lmdb")
        self.assertIsNone(D.engine_of_line("nothing"))

    def test_readback_is_read_from_the_daemons_log_file_first(self):
        """Each spawn is given `--log-file`; the console is the fallback for a
        daemon that prints its log there (the archived C++ seed does both).
        The pair is the line and the file it was read from."""
        d = tempfile.mkdtemp()
        daemon_log = os.path.join(d, "subject.daemon.log")
        console = os.path.join(d, "subject.log")
        with open(console, "w", encoding="utf-8") as fh:
            fh.write(LMDB_READBACK + "\n")
        line, found = R._readback_line(daemon_log, console)
        self.assertIn("(safe)", line)
        self.assertEqual(found, console)
        with open(daemon_log, "w", encoding="utf-8") as fh:
            fh.write(REDB_READBACK + "\n")
        line, found = R._readback_line(daemon_log, console)
        self.assertIn("Durability::Immediate", line)
        self.assertEqual(found, daemon_log)
        self.assertEqual(
            R._readback_line(daemon_log, console,
                             os.path.getsize(daemon_log),
                             os.path.getsize(console)),
            (None, None))

    def test_resolved_line_reader_reads_only_this_spawns_bytes(self):
        """The seed's log is appended across runs. Read from this spawn's offset,
        an earlier run's `safe` report cannot stand in for this run's."""
        d = tempfile.mkdtemp()
        log = os.path.join(d, "seed.log")
        with open(log, "w", encoding="utf-8") as fh:
            fh.write("INFO global: Database sync: flags=0x1 (safe), "
                     f"sync_mode={D.DB_NOSYNC_ORDINAL}, threshold=1 blocks\n")
        since = os.path.getsize(log)
        with open(log, "a", encoding="utf-8") as fh:
            fh.write("INFO global: Database sync: flags=0x2 (fast: MDB_NOSYNC), "
                     "sync_mode=0, threshold=250000000 bytes\n")
        self.assertIn("(fast: MDB_NOSYNC)", R._resolved_sync_line(log, since))
        self.assertIn("(safe)", R._resolved_sync_line(log))
        self.assertIsNone(R._resolved_sync_line(log, os.path.getsize(log)))

    def test_a_missing_readback_names_both_logs(self):
        """A miss names the log file the spawn was given and the console.
        The flip binary writes the report to the file and nothing to the
        console, so a refusal that names only the console points at a file
        that was never going to hold the line."""
        daemon_log = "/nonexistent/subject.daemon.log"
        console = "/nonexistent/subject.log"
        msg = R._readback_refusal("subject", None, None, daemon_log, console)
        self.assertIn("does not carry the daemon's resolved sync report", msg)
        self.assertIn(daemon_log, msg)
        self.assertIn(console, msg)
        self.assertEqual(msg.count("\nsee "), 2)

    def test_a_readback_that_is_not_drs_d9_names_the_file_it_came_from(self):
        """A hit names the file the line was read from, once."""
        line = ("INFO global: Database sync: flags=0x2 (fast: MDB_NOSYNC), "
                "sync_mode=0, threshold=1 blocks")
        found = "/work/subject.daemon.log"
        msg = R._readback_refusal(
            "subject", line, found, found, "/work/subject.log")
        self.assertIn("\nsee " + found, msg)
        self.assertEqual(msg.count("\nsee "), 1)

    def test_the_note_names_which_binary_served_the_chain(self):
        same = D.durability_readback_note(True)
        other = D.durability_readback_note(False)
        self.assertIn("same binary", same)
        self.assertIn("another binary", other)
        self.assertNotEqual(same, other)

    def test_a_binary_is_named_by_its_sha256(self):
        d = tempfile.mkdtemp()
        one = os.path.join(d, "one")
        two = os.path.join(d, "two")
        with open(one, "wb") as fh:
            fh.write(b"one")
        with open(two, "wb") as fh:
            fh.write(b"two")
        hashed = R.binary_sha256(one)
        self.assertEqual(hashed, hashlib.sha256(b"one").hexdigest())
        self.assertTrue(D.is_hex64(hashed))
        self.assertNotEqual(hashed, R.binary_sha256(two))


class LmdbOpen(unittest.TestCase):
    def test_the_mode_is_read_out_of_the_readback(self):
        """The parenthetical's open, independent of the sync_mode integer."""
        nosync = D.DB_NOSYNC_ORDINAL
        async_ordinal = D.BLOCKCHAIN_DB_SYNC_MODE.index("db_async")
        for line, mode in (
                (f"Database sync: flags=0x{D.DBF_SAFE:x} (safe), sync_mode={nosync}, "
                 "threshold=1 blocks", "safe"),
                (f"Database sync: flags=0x{D.DBF_FAST:x} (fast: MDB_NOSYNC), "
                 f"sync_mode={async_ordinal}, threshold=250000000 bytes", "fast"),
                (f"Database sync: flags=0x{D.DBF_FASTEST:x} (fastest: MDB_NOSYNC|"
                 f"MDB_WRITEMAP|MDB_MAPASYNC), sync_mode={async_ordinal}, "
                 "threshold=1000 blocks", "fastest")):
            with self.subTest(mode=mode):
                self.assertEqual(D.resolved_sync_mode(line), mode)
        self.assertIsNone(D.resolved_sync_mode("no report here"))
        self.assertIsNone(D.resolved_sync_mode(None))

    def test_only_db_nosync_with_the_safe_open_is_drs_d9(self):
        """`(safe)` with sync_mode=0 is db_defaultsync: the open that lets a sync
        turn the fsync off. The integer is on the line written at open."""
        def line(ordinal, flags=D.DBF_SAFE, words="safe"):
            return (f"Database sync: flags=0x{flags:x} ({words}), "
                    f"sync_mode={ordinal}, threshold=1 blocks")

        self.assertEqual(D.resolved_line_refusals(line(D.DB_NOSYNC_ORDINAL)), [])
        for ordinal, name in enumerate(D.BLOCKCHAIN_DB_SYNC_MODE):
            if ordinal == D.DB_NOSYNC_ORDINAL:
                continue
            with self.subTest(name=name):
                reasons = D.resolved_line_refusals(line(ordinal))
                self.assertTrue(any(name in reason and "db_nosync" in reason
                                    for reason in reasons), reasons)
        self.assertTrue(any("not a blockchain_db_sync_mode" in reason
                            for reason in D.resolved_line_refusals(line(9))))

    def test_flags_and_the_parenthetical_must_name_the_same_open(self):
        line = (f"Database sync: flags=0x{D.DBF_SAFE:x} (fast: MDB_NOSYNC), "
                f"sync_mode={D.DB_NOSYNC_ORDINAL}, threshold=1 blocks")
        reasons = D.resolved_line_refusals(line)
        self.assertTrue(any("do not name the same open" in reason for reason in reasons),
                        reasons)
        self.assertTrue(any("MDB_NOSYNC" in reason for reason in reasons), reasons)

    def test_bits_beside_the_open_do_not_change_the_verdict(self):
        """RDONLY and SALVAGE are not durability opens. Beside `safe` at
        db_nosync they still are DRS-D9; alone they are not."""
        beside = D.DBF_SAFE | D.DBF_RDONLY | D.DBF_SALVAGE
        line = (f"Database sync: flags=0x{beside:x} (safe) (salvage), "
                f"sync_mode={D.DB_NOSYNC_ORDINAL}, threshold=1 blocks")
        self.assertEqual(D.resolved_line_refusals(line), [])




class SyncProfileLine(unittest.TestCase):
    """The subject's per-block profile is read from the owner's log line.

    The defect each case names: a reader that takes the first line (the
    profile of an earlier, shorter sync), one that is fooled by the log's
    colour escapes, and one that invents a profile where the daemon logged
    none or logged JSON that does not parse.
    """

    def _log(self, lines):
        fh = tempfile.NamedTemporaryFile("w", suffix=".log", delete=False)
        self.addCleanup(os.unlink, fh.name)
        fh.write("\n".join(lines) + "\n")
        fh.close()
        return fh.name

    def test_the_last_profile_line_is_read_through_colour_escapes(self):
        first = ('2026-11-01T00:00:00Z INFO shekyl_chain_sync_runtime::owner: '
                 + R.PROFILE_MARK + ' target_height=Some(10) profile={"transit_blocks":9}')
        last = ('\x1b[32m INFO\x1b[0m shekyl_chain_sync_runtime::owner: '
                + R.PROFILE_MARK + ' \x1b[3mtarget_height\x1b[0m\x1b[2m=\x1b[0mSome(100) '
                '\x1b[3mprofile\x1b[0m\x1b[2m=\x1b[0m'
                '{"mode":"light (cache-only; no dataset)","transit_blocks":99}')
        profile = R._sync_profile(self._log(["unrelated", first, "other", last]))
        self.assertEqual(profile, {"mode": "light (cache-only; no dataset)",
                                   "transit_blocks": 99})

    def test_no_profile_line_is_none(self):
        self.assertIsNone(R._sync_profile(self._log(["a line", "Store durability: x"])))
        self.assertIsNone(R._sync_profile("/nonexistent/x.log"))

    def test_a_profile_that_does_not_parse_is_none(self):
        broken = R.PROFILE_MARK + ' target_height=None profile={"transit_blocks":'
        self.assertIsNone(R._sync_profile(self._log([broken])))

if __name__ == "__main__":
    unittest.main(verbosity=2)
