#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Selftest for `drs_bench.py`. Needs no daemon and no measurement.
#
# A GREEN ASSERTION IS THE WEAK ONE. "the artifact was accepted" says the
# validator accepted this input, not that it accepted it for the right reason —
# the named defect may well produce green too. So almost every test here is
# FATAL-shaped: it takes ONE valid artifact, breaks exactly ONE field, and
# asserts the refusal names that field. `test_control_*` is what makes those
# reds mean anything: it proves the unmutated artifact passes, so a refusal that
# fires must have been caused by the mutation and not by a fixture that was
# broken all along. Before adding a test, name the defect and say which way it
# would go; if it also goes green, it proves nothing and belongs in the FATAL
# form instead.

import glob
import json
import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import drs_artifact as D  # noqa: E402
import drs_bench as R  # noqa: E402


def valid_artifact(engine="lmdb", **over):
    a = {
        "schema_version": D.SCHEMA,
        "engine": engine,
        "engine_selected_by": D.ENGINE_DEFAULT_LMDB if engine == "lmdb" else
                              "--db-engine=redb",
        "git_rev": "0123456789abcdef",
        "thresholds_frozen_at": D.FROZEN_AT,
        "durability": {
            "policy": "DRS-D9 full-fsync-per-commit",
            "sync_mode": "safe",
            "imposed_argv": ["--regtest", "--db-sync-mode=safe", "--data-dir=/x/subject",
                             "--p2p-bind-port=1", "--rpc-bind-port=2"],
            "observed": True,
            "resolved_log_line": "2026-09-13T00:00:00Z INFO global: Database sync: "
                                 "flags=0x1 (safe), sync_mode=0, threshold=1 blocks",
            "readback": "the subject daemon's own resolved-flags report",
        },
        "environment": {"loadavg_1m_at_start": 0.3, "loadavg_1m_at_end": 0.4,
                        "loadavg_5m_at_end": 0.35, "cpu_count": 8,
                        "note": "quiet"},
        "hardware": {"cpu_model": "Test CPU", "ram_bytes": 1 << 34,
                     "disk_class": "ssd_or_nvme", "disk_class_source": "probed",
                     "fs_type": "ext4", "cpu_count": 8},
        "fixture": {
            "nettype": "fakechain", "height_reached": 200, "height_requested": 200,
            "reference_height": D.REFERENCE_HEIGHT, "tx_per_block": 0,
            "prunable_region": D.PRUNABLE_ABSENT,
            "verify_exercised": {"pow": True, "fcmp_pp": False},
            "seed_height": 200, "peers_used": 1,
        },
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


class FrozenThresholds(unittest.TestCase):
    """§1.3's numbers are pre-registered. This is the guard against fitting one
    to a measurement after the fact, which rule 21 makes a reopening rather
    than a refinement.

    The duplication here is DELIBERATE and must not be "cleaned up" by reading
    the constants from the module: the module holds the OPERATIVE value and the
    doc holds the REGISTERED one, and the whole point is to detect them
    diverging. Deduplicating would delete the check.
    """

    @classmethod
    def setUpClass(cls):
        with open(D.DESIGN_DOC, encoding="utf-8") as fh:
            text = fh.read()
        m = re.search(r"^### 1\.3 .*?(?=^### )", text, re.M | re.S)
        assert m, "§1.3 not found in the design doc — this test's subject is absent"
        cls.section = m.group(0)

    def test_operative_constants_are_the_registered_literals(self):
        self.assertEqual(D.IBD_FLOOR_RATIO, 1.25)
        self.assertEqual(D.IBD_HARD_FAIL_RATIO, 1.50)
        self.assertEqual(D.PEAK_RSS_RATIO, 2.0)
        self.assertEqual(D.REFERENCE_HEIGHT, 100_000)
        self.assertEqual(D.FROZEN_AT, "ba4b3c73a")

    def test_each_constant_still_appears_in_section_1_3(self):
        """Fails in BOTH directions, which is what makes it a cross-check and
        not a containment assertion: edit the doc's ratio and the rendered
        needle is absent; edit the module's constant and the needle it renders
        is absent. Either side alone going red is the finding."""
        for needle in (f"{D.IBD_FLOOR_RATIO:.2f}×",
                       f"{D.IBD_HARD_FAIL_RATIO:.2f}×",
                       f"{D.PEAK_RSS_RATIO:g}×",
                       f"H = {D.REFERENCE_HEIGHT:_}",
                       D.FROZEN_AT):
            with self.subTest(needle=needle):
                self.assertIn(needle, self.section,
                              f"{needle!r} is not in §1.3: the harness and the frozen "
                              "doc disagree, so one of them was edited alone")


class ArtifactRefusals(unittest.TestCase):

    def test_control_the_reference_artifact_is_accepted(self):
        """The control for every mutation test below. If this ever fails, those
        reds stop proving anything: they would fire on a fixture that was
        already invalid rather than on the field each one breaks."""
        self.assertEqual(D.artifact_refusals(valid_artifact()), [])

    def _refuse(self, mutate, needle):
        a = valid_artifact()
        mutate(a)
        r = D.artifact_refusals(a)
        self.assertTrue(r, f"expected a refusal mentioning {needle!r}, got none")
        self.assertTrue(any(needle in x for x in r),
                        f"refusals did not mention {needle!r}: {r}")

    def test_refuses_missing_durability_block(self):
        self._refuse(lambda a: a.pop("durability"), "durability block absent")

    def test_refuses_sync_mode_outside_the_allowed_set(self):
        """The silent-fallthrough guard. `--db-sync-mode=saf` is accepted by the
        daemon and means DBF_FAST (MDB_NOSYNC) with no diagnostic, so a typo
        would otherwise produce a confidently-labelled NOSYNC number."""
        def m(a):
            a["durability"]["sync_mode"] = "saf"
            a["durability"]["imposed_argv"] = ["--db-sync-mode=saf"]
        self._refuse(m, "only ['safe'] satisfies DRS-D9")

    def test_refuses_fast_sync_mode_explicitly(self):
        def m(a):
            a["durability"]["sync_mode"] = "fast"
            a["durability"]["imposed_argv"] = ["--db-sync-mode=fast"]
        self._refuse(m, "MDB_NOSYNC")

    def test_refuses_when_recorded_mode_is_not_the_imposed_mode(self):
        """Records `safe` while having imposed something else — the exact shape
        of a mislabelled measurement, and invisible to a check that only reads
        the label."""
        self._refuse(lambda a: a["durability"].__setitem__(
            "imposed_argv", ["--regtest", "--db-sync-mode=fast"]),
            "is not the mode that was imposed")

    def test_refuses_missing_imposed_argv(self):
        self._refuse(lambda a: a["durability"].pop("imposed_argv"),
                     "imposed_argv absent")

    def test_refuses_an_unobserved_durability_posture(self):
        """The daemon reports the flags it resolved (A4's enabler), so the posture is
        observable. An artifact that does not observe it is failing to record a
        condition it could have measured. This inverts an earlier revision, which
        required `observed: false` because no readback existed."""
        self._refuse(lambda a: a["durability"].__setitem__("observed", False),
                     "must be true")

    def test_refuses_a_missing_resolved_flags_line(self):
        self._refuse(lambda a: a["durability"].pop("resolved_log_line"),
                     "That line IS the readback")

    def test_refuses_a_resolved_line_reporting_nosync(self):
        """THE ONE THAT MATTERS: the daemon says it opened with MDB_NOSYNC while the
        artifact claims sync_mode safe. Before the readback, this artifact was
        indistinguishable from a correct one — the label agreed with itself."""
        for marker in ("MDB_NOSYNC", "MDB_MAPASYNC"):
            with self.subTest(marker=marker):
                self._refuse(lambda a, m=marker: a["durability"].__setitem__(
                    "resolved_log_line",
                    f"INFO global: Database sync: flags=0x2 (fast: {m}), sync_mode=2, "
                    f"threshold=1 blocks"), "opened WITHOUT an fsync per commit")

    def test_refuses_a_resolved_line_without_the_safe_flag(self):
        self._refuse(lambda a: a["durability"].__setitem__(
            "resolved_log_line",
            "INFO global: Database sync: flags=0x10 (salvage), sync_mode=0, "
            "threshold=1 blocks"), "does not report the safe flag")

    def test_refuses_a_non_report_string_as_the_readback(self):
        self._refuse(lambda a: a["durability"].__setitem__(
            "resolved_log_line", "some other log line entirely"),
            "does not carry the daemon's resolved sync report")

    def test_refuses_missing_environment_block(self):
        """System load is a condition of a wall-time measurement: the same fixture
        on this machine moved 36-55% on wall between idle and load 8.6/16 cores,
        and a 1.25x floor sits well inside that band."""
        self._refuse(lambda a: a.pop("environment"), "environment block absent")

    def test_refuses_a_negative_load_average(self):
        """A load average cannot be negative, and this is the test that matters:
        the producer's ORIGINAL failure sentinel was -1.0, which is a number and
        so passed an isinstance-only check. The first version of this test used
        None — a value the code never emitted — so it could not fail on the real
        path. Test the sentinel the producer actually produces."""
        for k in D.LOADAVG_FIELDS:
            with self.subTest(field=k):
                self._refuse(lambda a, k=k: a["environment"].__setitem__(k, -1.0),
                             "impossible negative load")

    def test_refuses_non_numeric_load_average(self):
        self._refuse(lambda a: a["environment"].__setitem__(
            "loadavg_1m_at_start", None), "loadavg_1m_at_start")

    def test_refuses_a_boolean_load_average(self):
        """`isinstance(True, int)` is True in Python, so a bool would satisfy a
        numeric check and then compare as 1."""
        self._refuse(lambda a: a["environment"].__setitem__(
            "loadavg_1m_at_end", True), "loadavg_1m_at_end")

    def test_the_producer_emits_no_numeric_sentinel_on_failure(self):
        """Pins the PRODUCER, not just the validator: if os.getloadavg is
        unavailable, `_loadavg` must return None rather than any number, so a
        failed observation has no representation that could validate."""
        import drs_bench as R
        real = os.getloadavg
        os.getloadavg = lambda: (_ for _ in ()).throw(OSError("no"))
        try:
            self.assertIsNone(R._loadavg())
        finally:
            os.getloadavg = real

    def test_refuses_missing_cpu_count_for_the_load(self):
        self._refuse(lambda a: a["environment"].pop("cpu_count"),
                     "load average means nothing without the core count")

    def test_refuses_missing_hardware(self):
        self._refuse(lambda a: a.pop("hardware"), "hardware block absent")

    def test_refuses_empty_cpu_model(self):
        self._refuse(lambda a: a["hardware"].__setitem__("cpu_model", ""),
                     "hardware.cpu_model")

    def test_refuses_missing_disk_class_source(self):
        """Provenance for the disk class: without it, a probed value cannot be told
        from one asserted by hand."""
        self._refuse(lambda a: a["hardware"].pop("disk_class_source"),
                     "hardware.disk_class_source")

    def test_refuses_undetermined_source_beside_a_real_disk_class(self):
        """`measure` pre-flights the undeterminable case and refuses to start, so
        this combination cannot come from the harness. Requiring the provenance is
        what makes that pre-flight guarantee checkable."""
        self._refuse(lambda a: a["hardware"].__setitem__("disk_class_source",
                                                         "undetermined"),
                     "a value nobody established")

    def test_refuses_generated_blocks_with_no_observed_duration(self):
        """Both directions of the generation pair, which is why it is a cross-check
        and not a presence check. The fields are legitimately absent when the seed
        was reused."""
        self._refuse(lambda a: (a["fixture"].__setitem__("blocks_generated", 200),
                                a["fixture"].__setitem__("generation_wall_s", None)),
                     "their duration was not observed")

    def test_refuses_zero_duration_for_generated_blocks(self):
        self._refuse(lambda a: (a["fixture"].__setitem__("blocks_generated", 200),
                                a["fixture"].__setitem__("generation_wall_s", 0)),
                     "their duration was not observed")

    def test_refuses_a_duration_with_no_blocks_generated(self):
        self._refuse(lambda a: a["fixture"].__setitem__("generation_wall_s", 99.0),
                     "no blocks generated")

    def test_refuses_placeholder_disk_class(self):
        """§1.3 requires the disk TYPE. "unknown" is non-empty, so a mere
        presence check accepts it — a required field satisfied by a placeholder
        is a requirement that cannot fail. The harness emitted exactly this on
        its first real run."""
        self._refuse(lambda a: a["hardware"].__setitem__("disk_class", "unknown"),
                     "a placeholder satisfies the field")

    def test_refuses_a_relabelled_lmdb_run(self):
        """The daemon has no engine switch, so an artifact labelled redb while
        selected by the daemon default IS an LMDB run — and as a candidate it would
        pass §1.3's floor at a ratio near 1.0 with no redb store in existence."""
        a = valid_artifact("redb")
        a["engine_selected_by"] = D.ENGINE_DEFAULT_LMDB
        r = D.artifact_refusals(a)
        self.assertTrue(any("label and the mechanism disagree" in x for x in r), r)

    def test_refuses_the_inverted_label_mechanism_mismatch(self):
        """The other direction, which the first version of this check missed: a
        contradictory pair passed simply by being inverted."""
        a = valid_artifact("lmdb")
        a["engine"] = "lmdb"
        a["engine_selected_by"] = "--db-engine=redb"
        r = D.artifact_refusals(a)
        self.assertTrue(any("does not know" in x for x in r), r)

    def test_refuses_an_unknown_engine_selector(self):
        self._refuse(lambda a: a.__setitem__("engine_selected_by", "magic"),
                     "which this gate does not know")

    def test_redb_artifacts_are_unreachable_until_a_selector_exists(self):
        """The F7 guarantee made checkable. The runner has no redb selection path,
        so no redb selector is known and an `engine: redb` artifact can be neither
        produced nor validated. Adding the selector is part of wiring the redb arm;
        this test turns red then, which is the reminder."""
        self.assertNotIn("redb", set(D.ENGINE_SELECTORS.values()))
        for sel in list(D.ENGINE_SELECTORS) + ["--db-engine=redb", "whatever"]:
            a = valid_artifact("redb")
            a["engine_selected_by"] = sel
            self.assertTrue(D.artifact_refusals(a),
                            f"an engine=redb artifact validated under selector {sel!r}")

    def test_refuses_missing_engine_selected_by(self):
        self._refuse(lambda a: a.pop("engine_selected_by"), "engine_selected_by absent")

    def test_refuses_placeholder_fs_type(self):
        """Same defect as `disk_class: "unknown"`, on the field that decides whether
        DRS-D9 could hold. A two-value denylist let every placeholder through."""
        for ph in ("unknown", "undetermined", "n/a"):
            with self.subTest(fs=ph):
                self._refuse(lambda a, ph=ph: a["hardware"].__setitem__("fs_type", ph),
                             "neither trusts nor rejects")

    def test_accepts_the_known_durable_filesystems(self):
        """The allowed set must actually admit real filesystems, or the gate fails
        closed on everything and would be deleted rather than heeded."""
        for fs in ("ext4", "xfs", "btrfs", "zfs"):
            with self.subTest(fs=fs):
                a = valid_artifact()
                a["hardware"]["fs_type"] = fs
                self.assertEqual(D.artifact_refusals(a), [])

    def test_refuses_truthy_string_verification_flags(self):
        """`fcmp_pp: "false"` is a TRUTHY string: it satisfies a key check and then
        suppresses the shortfall in compare(), letting an artifact claim full
        verification and take a passing floor."""
        self._refuse(lambda a: a["fixture"]["verify_exercised"].__setitem__(
            "fcmp_pp", "false"), "must use real booleans")

    def test_refuses_a_tmpfs_measurement(self):
        """fsync on tmpfs has no backing store to flush, so `safe` and
        MDB_NOSYNC are indistinguishable and DRS-D9 was never in force. The
        number is real; what it measures is a RAM disk."""
        self._refuse(lambda a: a["hardware"].__setitem__("fs_type", "tmpfs"),
                     "RAM-disk number")

    def test_refuses_ramfs_too(self):
        self._refuse(lambda a: a["hardware"].__setitem__("fs_type", "ramfs"),
                     "DRS-D9 durability was NOT in force")

    def test_refuses_missing_fs_type(self):
        self._refuse(lambda a: a["hardware"].pop("fs_type"), "hardware.fs_type absent")

    def test_refuses_zero_height_reached(self):
        self._refuse(lambda a: a["fixture"].__setitem__("height_reached", 0),
                     "produced no measurement")

    def test_refuses_verify_exercised_without_fcmp_key(self):
        """Omitting the key is not the same as recording false: it lets §1.3's
        'FCMP++ + PoW verify enabled as in real sync' stand unqualified."""
        self._refuse(lambda a: a["fixture"]["verify_exercised"].pop("fcmp_pp"),
                     "must state pow and fcmp_pp explicitly")

    def test_refuses_missing_prunable_region(self):
        """It bounds what the baseline generalises to: a coinbase-only fixture is
        the block shape least sensitive to discarding prunable bytes, so figures
        taken here do not transfer to a tx-bearing fixture."""
        self._refuse(lambda a: a["fixture"].pop("prunable_region"),
                     "fixture.prunable_region absent")

    def test_refuses_coinbase_only_claiming_a_prunable_region(self):
        self._refuse(lambda a: a["fixture"].__setitem__("prunable_region",
                                                        "1234 bytes measured"),
                     "has no prunable region to report")

    def test_refuses_tx_bearing_fixture_claiming_absence_by_construction(self):
        """The other direction, which is what makes this a cross-check and not a
        restatement of tx_per_block: absence-by-construction holds only for a
        coinbase-only fixture."""
        self._refuse(lambda a: a["fixture"].__setitem__("tx_per_block", 12),
                     "claims absence by construction")

    def test_refuses_missing_tx_per_block(self):
        self._refuse(lambda a: a["fixture"].pop("tx_per_block"), "tx_per_block absent")

    def test_refuses_a_different_freeze_era(self):
        """An artifact measured against different frozen thresholds must not be
        routed through today's ratios."""
        self._refuse(lambda a: a.__setitem__("thresholds_frozen_at", "deadbeef"),
                     "different freeze era")

    def test_refuses_seed_height_disagreeing_with_height_reached(self):
        """The subject syncs to the seed's tip, so these are one number."""
        self._refuse(lambda a: a["fixture"].__setitem__("seed_height", 12345),
                     "syncs to the seed's tip")

    def test_refuses_wrong_schema_version(self):
        self._refuse(lambda a: a.__setitem__("schema_version", "other_v9"),
                     "schema_version")

    def test_refuses_unknown_engine(self):
        self._refuse(lambda a: a.__setitem__("engine", "sqlite"), "engine is")

    def test_refuses_missing_git_rev(self):
        self._refuse(lambda a: a.pop("git_rev"), "git_rev absent")

    def test_refuses_measure_on_the_wrong_axis(self):
        self._refuse(lambda a: a["measures"][0].__setitem__("axis", "memory"),
                     "state the axis a figure is on")

    def test_refuses_measure_without_a_scenario(self):
        """An IBD RSS figure with no scenario reads as §7.4's attacker-feed row,
        which has no definition and no measurement."""
        self._refuse(lambda a: a["measures"][1].pop("scenario"), "scenario absent")

    def test_refuses_negative_value(self):
        self._refuse(lambda a: a["measures"][0].__setitem__("value", -1.0), "value is")

    def test_refuses_empty_measures(self):
        self._refuse(lambda a: a.__setitem__("measures", []), "measures absent or empty")

    def test_refuses_a_zero_on_a_thresholded_axis(self):
        """0.0 validates as a number and reads as 'used no time/RSS'. Same
        placeholder-satisfies-the-field defect as disk_class 'unknown'."""
        self._refuse(lambda a: a["measures"][0].__setitem__("value", 0),
                     "failed observation")

    def test_refuses_omitting_a_thresholded_axis(self):
        """§1.3 froze IBD wall time AND peak RSS. A bag of rows that omits RSS
        would skip that floor and still PASS."""
        self._refuse(lambda a: a.__setitem__(
            "measures", [m for m in a["measures"] if m["name"] != "peak_rss_bytes"]),
            "missing required")

    def test_refuses_missing_peers_used(self):
        self._refuse(lambda a: a["fixture"].pop("peers_used"), "peers_used")

    def test_refuses_zero_peers(self):
        self._refuse(lambda a: a["fixture"].__setitem__("peers_used", 0),
                     "missing or zero count")

    def test_refuses_a_mismatched_frozen_pin(self):
        self._refuse(lambda a: a.__setitem__("thresholds_frozen_at", "deadbeef"),
                     "thresholds_frozen_at")


class Comparability(unittest.TestCase):

    def _pair(self):
        return valid_artifact("lmdb"), valid_artifact("redb")

    def _refuse(self, mutate, needle):
        b, c = self._pair()
        mutate(b, c)
        r = D.comparability_refusals(b, c)
        self.assertTrue(r, f"expected a refusal mentioning {needle!r}, got none")
        self.assertTrue(any(needle in x for x in r),
                        f"refusals did not mention {needle!r}: {r}")

    def test_control_a_matched_pair_is_comparable(self):
        b, c = self._pair()
        self.assertEqual(D.comparability_refusals(b, c), [])

    def test_control_datadir_and_ports_are_masked(self):
        """Paths and ports differ between the two runs by construction and say
        nothing about the engine. If the mask broke, EVERY real comparison
        would refuse — so this control is what keeps the mask honest."""
        b, c = self._pair()
        c["durability"]["imposed_argv"] = ["--regtest", "--db-sync-mode=safe",
                                           "--data-dir=/other/path",
                                           "--p2p-bind-port=99", "--rpc-bind-port=98"]
        self.assertEqual(D.comparability_refusals(b, c), [])

    def test_refuses_differing_freeze_era_between_artifacts(self):
        self._refuse(lambda b, c: c.__setitem__("thresholds_frozen_at", "cafebabe"),
                     "different frozen thresholds")

    def test_refuses_differing_reference_height(self):
        self._refuse(lambda b, c: c["fixture"].__setitem__("reference_height", 50000),
                     "fixture.reference_height differs")

    def test_height_requested_may_differ_when_reached_matches(self):
        """Deliberately NOT a refusal: two runs that asked for different heights but
        reached the same one did the same work. A refusal that cannot correspond to
        a real difference trains readers to ignore refusals."""
        b, c = self._pair()
        c["fixture"]["height_requested"] = b["fixture"]["height_requested"] - 1
        self.assertEqual(D.comparability_refusals(b, c), [])

    def test_refuses_artifacts_from_different_trees(self):
        """§1.3 requires the same binary with only the engine differing, so a ratio
        across trees can attribute a consensus change to the engine."""
        self._refuse(lambda b, c: c.__setitem__("git_rev", "deadbeefc"),
                     "git_rev differs")

    def test_refuses_same_engine_pair(self):
        self._refuse(lambda b, c: c.__setitem__("engine", "lmdb"),
                     "ratio BETWEEN engines")

    def test_refuses_differing_durability(self):
        self._refuse(lambda b, c: c["durability"].__setitem__("policy", "relaxed"),
                     "durability blocks differ")

    def test_refuses_differing_hardware(self):
        self._refuse(lambda b, c: c["hardware"].__setitem__("cpu_model", "Other CPU"),
                     "hardware blocks differ")

    def test_refuses_differing_height_reached(self):
        self._refuse(lambda b, c: c["fixture"].__setitem__("height_reached", 150),
                     "fixture.height_reached differs")

    def test_refuses_differing_prunable_region(self):
        self._refuse(lambda b, c: c["fixture"].__setitem__("prunable_region",
                                                           "present, 900 KB"),
                     "fixture.prunable_region differs")

    def test_refuses_differing_peer_count(self):
        """IBD wall time scales with the number of peers serving it, so equal
        heights at different peer counts are not the same experiment."""
        self._refuse(lambda b, c: c["fixture"].__setitem__("peers_used", 4),
                     "fixture.peers_used differs")

    def test_refuses_differing_verify_exercised(self):
        self._refuse(lambda b, c: c["fixture"].__setitem__(
            "verify_exercised", {"pow": True, "fcmp_pp": True}),
            "fixture.verify_exercised differs")

    def test_refuses_argv_differing_beyond_engine_and_paths(self):
        self._refuse(lambda b, c: c["durability"]["imposed_argv"].append(
            "--block-sync-size=1000"), "subject argv differs")

    def test_refuses_when_primary_measure_is_absent(self):
        self._refuse(lambda b, c: c.__setitem__(
            "measures", [m for m in c["measures"] if m["name"] != "ibd_wall_time_s"]),
            "is not present on both artifacts")


class Verdicts(unittest.TestCase):

    def _cmp(self, wall_ratio=1.0, rss_ratio=1.0, height=200, fcmp=False):
        b = valid_artifact("lmdb")
        c = valid_artifact("redb")
        for a in (b, c):
            a["fixture"]["height_reached"] = height
            a["fixture"]["verify_exercised"] = {"pow": True, "fcmp_pp": fcmp}
        cm = {m["name"]: m for m in c["measures"]}
        bm = {m["name"]: m for m in b["measures"]}
        cm["ibd_wall_time_s"]["value"] = bm["ibd_wall_time_s"]["value"] * wall_ratio
        cm["peak_rss_bytes"]["value"] = int(bm["peak_rss_bytes"]["value"] * rss_ratio)
        self.assertEqual(D.comparability_refusals(b, c), [], "fixture must be comparable")
        return D.compare(b, c)

    def _row(self, rep, name):
        return next(r for r in rep["rows"] if r["name"] == name)

    def test_at_the_floor_exactly_passes(self):
        rep = self._cmp(wall_ratio=1.25)
        self.assertEqual(self._row(rep, "ibd_wall_time_s")["verdict"], "PASS")

    def test_just_above_the_floor_is_band_not_over(self):
        rep = self._cmp(wall_ratio=1.26)
        self.assertEqual(self._row(rep, "ibd_wall_time_s")["verdict"], "BAND")
        self.assertEqual(rep["verdict"], "BAND")

    def test_at_the_hard_fail_line_exactly_is_still_band(self):
        """§1.3 hard-fails on '> 1.50x', so 1.50 itself is the band. An
        off-by-one here would hard-fail a value the doc accepts for a
        decision-log call."""
        rep = self._cmp(wall_ratio=1.50)
        self.assertEqual(self._row(rep, "ibd_wall_time_s")["verdict"], "BAND")

    def test_band_is_not_silently_a_pass(self):
        """§1.3 makes the band a decision-log call, so `check` exits 0 — and a
        silent zero is how a band becomes a de facto pass. The report must say so."""
        rep = self._cmp(wall_ratio=1.3)
        self.assertEqual(rep["verdict"], "BAND")
        row = self._row(rep, "ibd_wall_time_s")
        self.assertIn("decision-log", row["note"])

    def test_above_the_hard_fail_line_is_over(self):
        rep = self._cmp(wall_ratio=1.6)
        self.assertEqual(self._row(rep, "ibd_wall_time_s")["verdict"], "OVER")
        self.assertEqual(rep["verdict"], "OVER")

    def test_rss_above_two_x_is_over(self):
        rep = self._cmp(rss_ratio=2.5)
        self.assertEqual(self._row(rep, "peak_rss_bytes")["verdict"], "OVER")
        self.assertEqual(rep["verdict"], "OVER")

    def test_store_bytes_has_no_threshold_and_says_so(self):
        """§1.3 states the file-size ceiling is set only after a multi-year sim,
        so this row must not silently read as a pass."""
        rep = self._cmp()
        self.assertEqual(self._row(rep, "store_bytes")["verdict"], "NO_THRESHOLD")

    def test_cpu_row_has_no_threshold(self):
        """§1.3 sets no CPU-time threshold; the row exists so "compute-bound"
        can be an observation instead of an inference."""
        rep = self._cmp()
        self.assertEqual(self._row(rep, "subject_cpu_s")["verdict"], "NO_THRESHOLD")

    def test_apparent_store_row_also_has_no_threshold(self):
        rep = self._cmp()
        self.assertEqual(self._row(rep, "store_bytes_apparent")["verdict"],
                         "NO_THRESHOLD")

    def test_worst_verdict_wins_over_a_passing_row(self):
        rep = self._cmp(wall_ratio=1.0, rss_ratio=2.5)
        self.assertEqual(self._row(rep, "ibd_wall_time_s")["verdict"], "PASS")
        self.assertEqual(rep["verdict"], "OVER")

    def test_saturated_run_is_flagged_without_changing_the_verdict(self):
        """`loadavg > cores` is the definition of more runnable work than cores, so
        reporting it invents no threshold. It must SURFACE and must NOT move the
        verdict: §1.3 sets no load limit, and quietly failing a run for being busy
        would be exactly the pre-registration violation this harness prevents."""
        b = valid_artifact("lmdb"); c = valid_artifact("redb")
        c["environment"]["loadavg_1m_at_end"] = 27.0  # 8 cores in the fixture
        self.assertEqual(D.comparability_refusals(b, c), [],
                         "load must not become a comparability refusal")
        rep = D.compare(b, c)
        self.assertTrue(any("more runnable work than cores" in x
                            for x in rep["contention_notes"]), rep["contention_notes"])
        self.assertEqual(rep["verdict"], "PASS",
                         "a contention note must not change the §1.3 verdict")

    def test_quiet_run_has_no_contention_note(self):
        rep = D.compare(valid_artifact("lmdb"), valid_artifact("redb"))
        self.assertEqual(rep["contention_notes"], [])

    def test_shortfall_names_the_height_and_the_missing_fcmp(self):
        rep = self._cmp(height=200)
        self.assertTrue(any("reached height 200" in s
                            for s in rep["fixture_shortfalls"]))
        self.assertTrue(any("NO FCMP++" in s for s in rep["fixture_shortfalls"]))

    def test_absent_pow_is_reported_as_a_shortfall(self):
        """Recorded but never surfaced before: §1.3's primary metric names PoW, so a
        run without it is a different experiment and must say so."""
        b = valid_artifact("lmdb"); c = valid_artifact("redb")
        for a in (b, c):
            a["fixture"]["verify_exercised"] = {"pow": False, "fcmp_pp": False}
        rep = D.compare(b, c)
        self.assertTrue(any("NO PoW verification" in x for x in rep["fixture_shortfalls"]),
                        rep["fixture_shortfalls"])

    def test_no_shortfall_at_reference_height_with_fcmp(self):
        rep = self._cmp(height=D.REFERENCE_HEIGHT, fcmp=True)
        self.assertEqual(rep["fixture_shortfalls"], [])

    def test_zero_thresholded_baseline_fail_closes(self):
        """Defense in depth: even if a zero wall time slipped past the
        validator, compare must not PASS the floor on an undefined ratio."""
        b, c = valid_artifact("lmdb"), valid_artifact("redb")
        b["measures"][0]["value"] = 0
        rep = D.compare(b, c)
        self.assertEqual(self._row(rep, "ibd_wall_time_s")["verdict"], "OVER")
        self.assertEqual(rep["verdict"], "OVER")


class MalformedInput(unittest.TestCase):

    def test_non_object_artifact_is_refused_not_crashed(self):
        """A syntactically valid non-object -- null, a list -- previously reached
        `comparability_refusals`, which reads both sides with `.get` and raised
        AttributeError: a malformed input crashed the gate instead of being
        rejected by it."""
        for bad in (None, [], "x", 3):
            with self.subTest(value=bad):
                r = D.artifact_refusals(bad)
                self.assertTrue(r, f"{bad!r} produced no refusal")
                self.assertTrue(any("not a JSON object" in x for x in r), r)


class InputErrors(unittest.TestCase):
    """A gate reports verdicts; a traceback is not one. Each of these exited
    through a stack trace before, saying where the script broke rather than what
    was wrong with the input — the same defect as reaching the comparability check
    with a non-object, one layer further out."""

    def _cli(self, *args):
        import subprocess
        return subprocess.run([sys.executable,
                               os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                            "drs_bench.py")] + list(args),
                              capture_output=True, text=True)

    def test_missing_artifact_is_a_verdict_not_a_traceback(self):
        p = self._cli("validate", "/nonexistent/artifact.json")
        self.assertEqual(p.returncode, 1)
        self.assertNotIn("Traceback", p.stderr + p.stdout)
        self.assertIn("no such artifact", p.stderr)

    def test_unparseable_json_is_a_verdict_not_a_traceback(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            fh.write("not json{")
            bad = fh.name
        self.addCleanup(os.unlink, bad)
        p = self._cli("validate", bad)
        self.assertEqual(p.returncode, 1)
        self.assertNotIn("Traceback", p.stderr + p.stdout)
        self.assertIn("not valid JSON", p.stderr)

    def test_resolved_line_reader_ignores_nothing_and_strips_ansi(self):
        """The readback reader: it must find the daemon's colourised line and return
        it without terminal control bytes, and return None when the line is absent
        rather than a stand-in."""
        import drs_bench as R
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

    def test_a_directory_is_a_verdict_not_a_traceback(self):
        p = self._cli("validate", tempfile.mkdtemp())
        self.assertEqual(p.returncode, 1)
        self.assertNotIn("Traceback", p.stderr + p.stdout)
        self.assertIn("is a directory", p.stderr)


class FollowonRegistry(unittest.TestCase):

    def test_every_followon_names_a_blocker(self):
        for name, why in D.FOLLOWON_MEASURES.items():
            with self.subTest(name=name):
                self.assertIsInstance(why, str)
                self.assertGreater(len(why), 40,
                                   "a named blocker must say what is blocking, not just "
                                   "that something is (rule 22)")

    def test_no_followon_silently_shares_a_name_with_a_live_measure(self):
        """A follow-on that also appears in MEASURE_AXES would be emitted and
        deferred at the same time."""
        self.assertEqual(set(D.MEASURE_AXES) & set(D.FOLLOWON_MEASURES), set())

    def test_followons_do_not_claim_to_be_probed(self):
        """Nothing probes the redb arm any more -- it is a second binary, never
        a switch, so the source probe was deleted 2026-09-14. Labelling a
        follow-on PROBED with nothing driving a probe is a check that cannot
        fail, and that is truer now than when a probe existed."""
        self.assertNotIn("PROBED", D.FOLLOWON_MEASURES)
        self.assertIsInstance(next(iter(D.FOLLOWON_MEASURES.values())), str)


class CommittedArtifacts(unittest.TestCase):
    """The in-tree JSON files are this gate's subject. A selftest that only
    mutates a synthetic fixture stays green if those files are deleted or
    edited to satisfy a future check (rule 47)."""

    def test_in_tree_artifacts_exist_and_validate(self):
        paths = sorted(glob.glob(D.ARTIFACT_GLOB))
        self.assertTrue(paths, "no committed DRS-BENCH artifacts; this gate's "
                               "subject is absent")
        for p in paths:
            with self.subTest(path=os.path.basename(p)):
                with open(p, encoding="utf-8") as fh:
                    a = json.load(fh)
                self.assertEqual(D.artifact_refusals(a), [], p)


class Preflight(unittest.TestCase):

    def test_refuses_an_unrecognised_sync_mode_before_spawn(self):
        r = D.measurement_preflight(
            sync_mode="fast", daemon=__file__,
            work_dir=".", seed_dir=".", disk_class="ssd_or_nvme")
        self.assertTrue(any("MDB_NOSYNC" in x for x in r), r)

    def test_refuses_a_missing_daemon_binary(self):
        r = D.measurement_preflight(
            sync_mode="safe",
            daemon=os.path.join(tempfile.mkdtemp(), "no-such-shekyld"),
            work_dir=".", seed_dir=".", disk_class="ssd_or_nvme")
        self.assertTrue(any("is not a file" in x for x in r), r)

    def test_control_a_sane_lmdb_preflight_is_empty(self):
        r = D.measurement_preflight(
            sync_mode="safe", daemon=__file__,
            work_dir=".", seed_dir=".", disk_class="ssd_or_nvme")
        # work_dir '.' may still lack a sysfs rotational node; declaring the
        # class is what makes this a control rather than a probe of this box.
        self.assertFalse(any("engine switch" in x or "MDB_NOSYNC" in x
                             or "is not a file" in x for x in r), r)


class HardwareFingerprint(unittest.TestCase):

    def test_does_not_emit_unknown_as_a_disk_class(self):
        hw = D.hardware_fingerprint(".", declared_disk_class=None)
        self.assertNotEqual(hw.get("disk_class"), "unknown")
        if "disk_class" not in hw:
            self.assertEqual(hw["disk_class_source"], "undetermined")
            self.assertTrue(D.artifact_refusals(valid_artifact(
                hardware={**hw, "cpu_model": "Test CPU", "ram_bytes": 1,
                          "fs_type": "ext4", "cpu_count": 1})))

    def test_declared_class_is_recorded_as_declared(self):
        hw = D.hardware_fingerprint(".", declared_disk_class="hdd")
        if hw.get("disk_class_source") != "probed":
            self.assertEqual(hw["disk_class"], "hdd")
            self.assertEqual(hw["disk_class_source"], "operator-declared")


class RunnerImport(unittest.TestCase):
    """The CLI module must keep loading after the split; a missing import is
    how the gate and the runner would come to disagree about the schema."""

    def test_runner_uses_the_gate_module(self):
        self.assertIs(R.A.SCHEMA, D.SCHEMA)
        self.assertIs(R.A.artifact_refusals, D.artifact_refusals)


if __name__ == "__main__":
    unittest.main(verbosity=2)
