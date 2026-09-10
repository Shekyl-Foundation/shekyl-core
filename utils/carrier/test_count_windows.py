#!/usr/bin/env python3
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# Tests for count_windows.py. The load-bearing assertions are:
#
#   * a framed WINDOW_BYTES message (m_cb = WINDOW_BODY) is counted
#   * m_cb of WINDOW_BYTES is not (that was the false filter)
#   * WINDOW_BODY ± 1 are not (the filter is exact, not a band)
#   * proxy→node (src port 9050) is ignored
#   * SOCKS bytes before the signature do not hide a window
#   * summary jitter is the per-flow aggregate, not the merged timestamp series
#   * --expect-zero fails when a window is present
#
# A test that would also pass if the filter were `abs(n - 20480) < 64` is
# not coverage of the method.
#
# Run: python3 utils/carrier/test_count_windows.py

from __future__ import annotations

import io
import json
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import count_windows as cw


def levin_msg(body_len, extra_prefix=b""):
    body = b"\xab" * body_len
    hdr = (
        cw.LEVIN_SIGNATURE
        + struct.pack("<Q", body_len)
        + bytes(
            [
                0,  # have_to_return_data
            ]
        )
        + struct.pack("<I", 2002)  # command (unused by the counter)
        + struct.pack("<i", 0)
        + struct.pack("<I", 1)  # REQUEST
        + struct.pack("<I", 1)  # protocol v1
    )
    assert len(hdr) == cw.HEADER_SIZE
    return extra_prefix + hdr + body


def framed_window(extra_prefix=b""):
    """A noise_notify(WINDOW_BYTES)-shaped message: framed size, not m_cb."""
    blob = levin_msg(cw.WINDOW_BODY, extra_prefix=extra_prefix)
    assert len(blob) - len(extra_prefix) == cw.WINDOW_BYTES
    return blob


def ipv4_tcp(src, sport, dst, dport, seq, payload):
    def ip4(a):
        return bytes(int(x) for x in a.split("."))

    tcp = struct.pack(">HHII", sport, dport, seq, 0)
    tcp += struct.pack(">HHHH", (5 << 12), 8192, 0, 0)  # data offset 5, window
    tcp += payload
    ip = struct.pack(
        ">BBHHBBBBH",
        0x45,
        0,
        20 + len(tcp),
        0,
        0,
        0,
        64,
        6,
        0,
    )
    ip += ip4(src) + ip4(dst) + tcp
    return ip


def write_pcap(path, packets, linktype=cw.DLT_RAW):
    """packets: list of (ts_float, frame_bytes). Little-endian microsecond pcap."""
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHIIII", cw.PCAP_MAGIC_LE, 2, 4, 0, 0, 65535, linktype))
        for ts, frame in packets:
            sec = int(ts)
            usec = int(round((ts - sec) * 1e6))
            fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            fh.write(frame)


def segmented(src, sport, dst, dport, seq0, blob, ts0, mss=1400, dt=0.001):
    """Split blob across TCP segments so reassembly is actually exercised."""
    out = []
    off = 0
    seq = seq0
    t = ts0
    while off < len(blob):
        chunk = blob[off : off + mss]
        out.append((t, ipv4_tcp(src, sport, dst, dport, seq, chunk)))
        off += len(chunk)
        seq += len(chunk)
        t += dt
    return out


class CountWindows(unittest.TestCase):
    def _run(self, packets, **kwargs):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as fh:
            path = fh.name
        try:
            write_pcap(path, packets)
            flows = cw.count_windows(cw.read_pcap_packets(path), **kwargs)
            return cw.summarise(flows), path
        finally:
            os.unlink(path)

    def test_exact_window_is_counted(self):
        blob = framed_window()
        pkts = segmented("127.0.0.1", 40000, "127.0.0.1", 9050, 1, blob, 1000.0)
        s, _ = self._run(pkts)
        self.assertEqual(s["n"], 1)
        self.assertEqual(s["payload_bytes"], cw.WINDOW_BYTES)
        self.assertEqual(s["window_body_bytes"], cw.WINDOW_BODY)

    def test_one_byte_short_is_excluded(self):
        blob = levin_msg(cw.WINDOW_BODY - 1)
        pkts = segmented("127.0.0.1", 40000, "127.0.0.1", 9050, 1, blob, 1000.0)
        s, _ = self._run(pkts)
        self.assertEqual(s["n"], 0)

    def test_one_byte_long_is_excluded(self):
        blob = levin_msg(cw.WINDOW_BODY + 1)
        pkts = segmented("127.0.0.1", 40000, "127.0.0.1", 9050, 1, blob, 1000.0)
        s, _ = self._run(pkts)
        self.assertEqual(s["n"], 0)

    def test_mcb_equal_to_window_bytes_is_excluded(self):
        # The old filter treated WINDOW_BYTES as m_cb. noise_notify never
        # emits that: it would be a 20 513-byte frame, not a window.
        blob = levin_msg(cw.WINDOW_BYTES)
        pkts = segmented("127.0.0.1", 40000, "127.0.0.1", 9050, 1, blob, 1000.0)
        s, _ = self._run(pkts)
        self.assertEqual(s["n"], 0)

    def test_proxy_to_node_is_ignored(self):
        blob = framed_window()
        # src port 9050: this is proxy→node, the direction the method excludes.
        pkts = segmented("127.0.0.1", 9050, "127.0.0.1", 40000, 1, blob, 1000.0)
        s, _ = self._run(pkts)
        self.assertEqual(s["n"], 0)

    def test_socks_prefix_does_not_hide_a_window(self):
        socks = b"\x05\x01\x00" + b"\x05\x00\x00\x01" + b"\x00" * 6
        blob = framed_window(extra_prefix=socks)
        pkts = segmented("127.0.0.1", 40000, "127.0.0.1", 9050, 1, blob, 1000.0)
        s, _ = self._run(pkts)
        self.assertEqual(s["n"], 1)

    def test_interval_histogram_is_per_completion_time(self):
        a = framed_window()
        b = framed_window()
        pkts = segmented("127.0.0.1", 40000, "127.0.0.1", 9050, 1, a, 10.0)
        seq = 1 + len(a)
        pkts += segmented(
            "127.0.0.1", 40000, "127.0.0.1", 9050, seq, b, 10.0 + 4.000
        )
        s, _ = self._run(pkts)
        self.assertEqual(s["n"], 2)
        self.assertEqual(s["interval_buckets"].get("in_jitter"), 1)
        self.assertEqual(s["interval_buckets"].get("below_min", 0), 0)

    def test_metronome_lands_below_min_when_faster_than_3333(self):
        a = framed_window()
        b = framed_window()
        pkts = segmented("127.0.0.1", 40000, "127.0.0.1", 9050, 1, a, 10.0)
        pkts += segmented(
            "127.0.0.1", 40000, "127.0.0.1", 9050, 1 + len(a), b, 10.0 + 1.000
        )
        s, _ = self._run(pkts)
        self.assertEqual(s["interval_buckets"].get("below_min"), 1)

    def test_jitter_summary_is_per_flow_not_merged(self):
        # Two healthy channels at 5 s. Interleaved, the merged series has
        # 2.5 s gaps (below_min). Defect 2 is per-channel; the summary must
        # not report that false metronome.
        w = framed_window()
        pkts = segmented("127.0.0.1", 40000, "127.0.0.1", 9050, 1, w, 10.0)
        pkts += segmented(
            "127.0.0.1", 40000, "127.0.0.1", 9050, 1 + len(w), w, 15.0
        )
        pkts += segmented("127.0.0.1", 40001, "127.0.0.1", 9050, 1, w, 12.5)
        pkts += segmented(
            "127.0.0.1", 40001, "127.0.0.1", 9050, 1 + len(w), w, 17.5
        )
        s, _ = self._run(pkts)
        self.assertEqual(s["n"], 4)
        self.assertEqual(s["interval_buckets"].get("in_jitter"), 2)
        self.assertEqual(s["interval_buckets"].get("below_min", 0), 0)

    def test_one_flow_metronome_is_visible_in_summary(self):
        w = framed_window()
        pkts = segmented("127.0.0.1", 40000, "127.0.0.1", 9050, 1, w, 10.0)
        pkts += segmented(
            "127.0.0.1", 40000, "127.0.0.1", 9050, 1 + len(w), w, 15.0
        )
        pkts += segmented("127.0.0.1", 40001, "127.0.0.1", 9050, 1, w, 10.0)
        pkts += segmented(
            "127.0.0.1", 40001, "127.0.0.1", 9050, 1 + len(w), w, 11.0
        )
        s, _ = self._run(pkts)
        self.assertEqual(s["interval_buckets"].get("in_jitter"), 1)
        self.assertEqual(s["interval_buckets"].get("below_min"), 1)

    def test_expect_zero_exits_nonzero(self):
        blob = framed_window()
        pkts = segmented("127.0.0.1", 40000, "127.0.0.1", 9050, 1, blob, 1000.0)
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as fh:
            path = fh.name
        try:
            write_pcap(path, pkts)
            buf = io.StringIO()
            err = io.StringIO()
            old_out, old_err = sys.stdout, sys.stderr
            sys.stdout, sys.stderr = buf, err
            try:
                rc = cw.main([path, "--expect-zero", "--json"])
            finally:
                sys.stdout, sys.stderr = old_out, old_err
            self.assertEqual(rc, 1)
        finally:
            os.unlink(path)

    def test_expect_zero_ok_on_empty(self):
        other = levin_msg(100)
        pkts = segmented("127.0.0.1", 40000, "127.0.0.1", 9050, 1, other, 1000.0)
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as fh:
            path = fh.name
        try:
            write_pcap(path, pkts)
            buf = io.StringIO()
            old_out, old_err = sys.stdout, sys.stderr
            sys.stdout, sys.stderr = buf, buf
            try:
                rc = cw.main([path, "--expect-zero", "--json"])
            finally:
                sys.stdout, sys.stderr = old_out, old_err
            self.assertEqual(rc, 0)
        finally:
            os.unlink(path)

    def test_truncated_snaplen_is_loud(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as fh:
            path = fh.name
            fh.write(struct.pack("<IHHIIII", cw.PCAP_MAGIC_LE, 2, 4, 0, 0, 96, cw.DLT_RAW))
            frame = ipv4_tcp("127.0.0.1", 1, "127.0.0.1", 9050, 1, b"x" * 200)
            fh.write(struct.pack("<IIII", 1, 0, 96, len(frame)))
            fh.write(frame[:96])
        try:
            with self.assertRaises(cw.PcapError) as ctx:
                list(cw.read_pcap_packets(path))
            self.assertIn("-s 0", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_json_round_trip_keys(self):
        blob = framed_window()
        pkts = segmented("127.0.0.1", 40000, "127.0.0.1", 9050, 1, blob, 1000.0)
        s, _ = self._run(pkts)
        encoded = json.loads(json.dumps(s))
        self.assertEqual(encoded["window_bytes"], 20480)
        self.assertEqual(encoded["window_body_bytes"], 20447)
        self.assertEqual(encoded["n"], 1)


if __name__ == "__main__":
    unittest.main()
