#!/usr/bin/env python3
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# §3.1c(i) counter: exact-WINDOW_BYTES levin payloads on node→proxy sockets.
#
# COVER_TRAFFIC_RESTORATION.md forbids counting IP bytes, forbids a size
# range, and forbids subtracting fluff. This program implements that filter
# and nothing else. Relaxing WINDOW_BYTES from an exact match is the defect
# the method names — the tests fail if it becomes a range.
#
# Capture (subject host, as root if tcpdump needs it; -s 0 is not optional):
#
#   tcpdump -i lo -s 0 -w arm.pcap 'tcp and dst port 9050'
#
# Count:
#
#   python3 utils/carrier/count_windows.py arm.pcap
#   python3 utils/carrier/count_windows.py --expect-zero arm.pcap   # arm A
#
# SOCKS5 wrapping is skipped by scanning the reassembled TCP stream for the
# levin signature (01 21 01 01 01 01 01 01). A false hit is 2^-64.

from __future__ import annotations

import argparse
import collections
import json
import struct
import sys

# Pinned to rust/shekyl-relay-privacy/src/params/carrier.rs. Do not "improve"
# the match into a band: a carrier emission is always precisely this size.
WINDOW_BYTES = 20_480
NOISE_MIN_DELAY_MS = 3_333
NOISE_DELAY_JITTER_MS = 3_334  # inclusive width → U[3333, 6667]
JITTER_HI_MS = NOISE_MIN_DELAY_MS + NOISE_DELAY_JITTER_MS

# rust/shekyl-levin/src/header.rs — little-endian on the wire.
LEVIN_SIGNATURE = bytes.fromhex("0121010101010101")
HEADER_SIZE = 33
MAX_BODY = 100_000_000  # LEVIN_DEFAULT_MAX_PACKET_SIZE; larger is a false sig

# pcap link types we will see on `tcpdump -i lo`.
DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW = 12
DLT_RAW_ALT = 101
DLT_IPV4 = 228
DLT_IPV6 = 229
DLT_LINUX_SLL = 113
DLT_LINUX_SLL2 = 276
DLT_LOOP = 108

PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1
PCAP_MAGIC_NS_LE = 0xA1B23C4D
PCAP_MAGIC_NS_BE = 0x4D3CB2A1


class PcapError(Exception):
    pass


def _u16(b, off, be):
    return struct.unpack_from(">H" if be else "<H", b, off)[0]


def _u32(b, off, be):
    return struct.unpack_from(">I" if be else "<I", b, off)[0]


def read_pcap_packets(path):
    """Yield (ts_sec_float, linktype, frame_bytes). Refuses truncated snap."""
    with open(path, "rb") as fh:
        hdr = fh.read(24)
        if len(hdr) < 24:
            raise PcapError("pcap global header truncated")
        magic = struct.unpack_from("<I", hdr, 0)[0]
        if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
            be = False
            ns = magic == PCAP_MAGIC_NS_LE
        elif magic in (PCAP_MAGIC_BE, PCAP_MAGIC_NS_BE):
            be = True
            ns = magic == PCAP_MAGIC_NS_BE
        else:
            raise PcapError("unrecognised pcap magic 0x%08x" % magic)
        linktype = _u32(hdr, 20, be)
        pkt_hdr = struct.Struct(">IIII" if be else "<IIII")
        while True:
            ph = fh.read(16)
            if not ph:
                return
            if len(ph) < 16:
                raise PcapError("pcap packet header truncated")
            ts_sec, ts_sub, incl, orig = pkt_hdr.unpack(ph)
            frame = fh.read(incl)
            if len(frame) < incl:
                raise PcapError("pcap packet body truncated")
            if incl < orig:
                raise PcapError(
                    "snaplen truncated a packet (%d < %d); recapture with -s 0"
                    % (incl, orig)
                )
            if ns:
                ts = ts_sec + ts_sub / 1e9
            else:
                ts = ts_sec + ts_sub / 1e6
            yield ts, linktype, frame


def _l3_from_frame(linktype, frame):
    """Return the IP datagram, or None if this frame is not IP."""
    if linktype in (DLT_RAW, DLT_RAW_ALT, DLT_IPV4, DLT_IPV6):
        return frame
    if linktype == DLT_EN10MB:
        if len(frame) < 14:
            return None
        ethertype = struct.unpack_from(">H", frame, 12)[0]
        if ethertype == 0x0800 or ethertype == 0x86DD:
            return frame[14:]
        if ethertype == 0x8100 and len(frame) >= 18:
            inner = struct.unpack_from(">H", frame, 16)[0]
            if inner in (0x0800, 0x86DD):
                return frame[18:]
        return None
    if linktype in (DLT_NULL, DLT_LOOP):
        if len(frame) < 4:
            return None
        return frame[4:]
    if linktype == DLT_LINUX_SLL:
        if len(frame) < 16:
            return None
        proto = struct.unpack_from(">H", frame, 14)[0]
        if proto in (0x0800, 0x86DD):
            return frame[16:]
        return None
    if linktype == DLT_LINUX_SLL2:
        if len(frame) < 20:
            return None
        proto = struct.unpack_from(">H", frame, 0)[0]
        if proto in (0x0800, 0x86DD):
            return frame[20:]
        return None
    raise PcapError("unsupported pcap linktype %d" % linktype)


def parse_tcp_segment(ip_datagram):
    """Return (src, sport, dst, dport, seq, payload) or None."""
    if not ip_datagram:
        return None
    ver = ip_datagram[0] >> 4
    if ver == 4:
        if len(ip_datagram) < 20:
            return None
        ihl = (ip_datagram[0] & 0x0F) * 4
        if ip_datagram[9] != 6:
            return None
        src = "%d.%d.%d.%d" % tuple(ip_datagram[12:16])
        dst = "%d.%d.%d.%d" % tuple(ip_datagram[16:20])
        tcp = ip_datagram[ihl:]
    elif ver == 6:
        if len(ip_datagram) < 40:
            return None
        if ip_datagram[6] != 6:
            return None
        src = _v6(ip_datagram[8:24])
        dst = _v6(ip_datagram[24:40])
        tcp = ip_datagram[40:]
    else:
        return None
    if len(tcp) < 20:
        return None
    sport, dport = struct.unpack_from(">HH", tcp, 0)
    seq = struct.unpack_from(">I", tcp, 4)[0]
    doff = (tcp[12] >> 4) * 4
    payload = tcp[doff:]
    return src, sport, dst, dport, seq, payload


def _v6(raw):
    parts = struct.unpack(">HHHHHHHH", raw)
    return ":".join("%x" % p for p in parts)


class Flow:
    __slots__ = ("next_seq", "buf", "windows_ts")

    def __init__(self):
        self.next_seq = None
        self.buf = bytearray()
        self.windows_ts = []

    def push(self, seq, payload, ts, window_bytes):
        if not payload:
            return
        if self.next_seq is None:
            self.next_seq = seq
        if seq > self.next_seq:
            # Gap: localhost SOCKS is in-order; a gap is a dropped segment.
            # Drop the half-parsed levin rather than invent a body length.
            self.buf.clear()
            self.next_seq = seq
        elif seq < self.next_seq:
            skip = self.next_seq - seq
            if skip >= len(payload):
                return
            payload = payload[skip:]
            seq = self.next_seq
        self.buf.extend(payload)
        self.next_seq = seq + len(payload)
        self._drain(ts, window_bytes)

    def _drain(self, ts, window_bytes):
        buf = self.buf
        while True:
            i = buf.find(LEVIN_SIGNATURE)
            if i < 0:
                if len(buf) > HEADER_SIZE - 1:
                    del buf[: len(buf) - (HEADER_SIZE - 1)]
                return
            if i:
                del buf[:i]
            if len(buf) < HEADER_SIZE:
                return
            body = struct.unpack_from("<Q", buf, 8)[0]
            if body > MAX_BODY:
                del buf[0]
                continue
            need = HEADER_SIZE + body
            if len(buf) < need:
                return
            if body == window_bytes:
                self.windows_ts.append(ts)
            del buf[:need]


def iter_node_to_proxy(packets, proxy_port):
    for ts, linktype, frame in packets:
        ip = _l3_from_frame(linktype, frame)
        seg = parse_tcp_segment(ip) if ip is not None else None
        if seg is None:
            continue
        src, sport, dst, dport, seq, payload = seg
        if dport != proxy_port:
            continue
        yield ts, (src, sport, dst, dport), seq, payload


def count_windows(packets, proxy_port=9050, window_bytes=WINDOW_BYTES):
    flows = collections.OrderedDict()
    for ts, key, seq, payload in iter_node_to_proxy(packets, proxy_port):
        flow = flows.get(key)
        if flow is None:
            flow = Flow()
            flows[key] = flow
        flow.push(seq, payload, ts, window_bytes)
    return flows


def intervals_ms(timestamps):
    out = []
    for a, b in zip(timestamps, timestamps[1:]):
        out.append((b - a) * 1000.0)
    return out


def classify_interval(ms):
    if ms < NOISE_MIN_DELAY_MS:
        return "below_min"
    if ms > JITTER_HI_MS:
        return "above_jitter"
    return "in_jitter"


def summarise(flows):
    all_ts = []
    per_flow = []
    for key, flow in flows.items():
        ts = flow.windows_ts
        iv = intervals_ms(ts)
        buckets = collections.Counter(classify_interval(m) for m in iv)
        per_flow.append(
            {
                "src": "%s:%d" % (key[0], key[1]),
                "dst": "%s:%d" % (key[2], key[3]),
                "n": len(ts),
                "intervals_ms": [round(m, 3) for m in iv],
                "buckets": dict(buckets),
            }
        )
        all_ts.extend(ts)
    all_ts.sort()
    n = len(all_ts)
    iv = intervals_ms(all_ts)
    duration_s = (all_ts[-1] - all_ts[0]) if n >= 2 else 0.0
    payload_bytes = n * WINDOW_BYTES
    rate = (payload_bytes / duration_s) if duration_s > 0 else 0.0
    hist = collections.Counter()
    for m in iv:
        # 250 ms bins, labelled by bin start.
        hist[int(m // 250) * 250] += 1
    return {
        "window_bytes": WINDOW_BYTES,
        "n": n,
        "payload_bytes": payload_bytes,
        "duration_s": duration_s,
        "rate_Bps": rate,
        "interval_buckets": dict(collections.Counter(classify_interval(m) for m in iv)),
        "histogram_250ms": {str(k): hist[k] for k in sorted(hist)},
        "flows": per_flow,
        "jitter_ms": [NOISE_MIN_DELAY_MS, JITTER_HI_MS],
        "tor_only_two_channel_mean_Bps": WINDOW_BYTES * 2 / 5.0,
        "dual_zone_four_channel_mean_Bps": WINDOW_BYTES * 4 / 5.0,
    }


def format_text(summary):
    lines = []
    lines.append(
        "windows=%d payload_bytes=%d duration_s=%.3f rate_Bps=%.3f"
        % (
            summary["n"],
            summary["payload_bytes"],
            summary["duration_s"],
            summary["rate_Bps"],
        )
    )
    lines.append(
        "jitter_band_ms=[%d, %d]  two_ch_mean_Bps=%.3f  four_ch_mean_Bps=%.3f"
        % (
            summary["jitter_ms"][0],
            summary["jitter_ms"][1],
            summary["tor_only_two_channel_mean_Bps"],
            summary["dual_zone_four_channel_mean_Bps"],
        )
    )
    b = summary["interval_buckets"]
    lines.append(
        "intervals below_min=%d in_jitter=%d above_jitter=%d"
        % (b.get("below_min", 0), b.get("in_jitter", 0), b.get("above_jitter", 0))
    )
    if summary["histogram_250ms"]:
        lines.append("histogram_250ms (bin_start:count):")
        for k, v in summary["histogram_250ms"].items():
            lines.append("  %s %s" % (k, v))
    lines.append("flows=%d" % len(summary["flows"]))
    for f in summary["flows"]:
        if f["n"] == 0:
            continue
        lines.append(
            "  %s -> %s  n=%d  buckets=%s"
            % (f["src"], f["dst"], f["n"], f["buckets"] or "{}")
        )
    return "\n".join(lines) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Count exact-WINDOW_BYTES levin payloads on node→proxy (COVER_TRAFFIC_RESTORATION.md §3.1c(i))."
    )
    p.add_argument("pcap", help="tcpdump -i lo -s 0 capture of tcp and dst port 9050")
    p.add_argument("--proxy-port", type=int, default=9050)
    p.add_argument(
        "--expect-zero",
        action="store_true",
        help="arm A rehearsal: exit 1 if any exact-window payload is present",
    )
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    packets = read_pcap_packets(args.pcap)
    flows = count_windows(packets, proxy_port=args.proxy_port)
    summary = summarise(flows)
    if args.json:
        sys.stdout.write(json.dumps(summary, indent=2) + "\n")
    else:
        sys.stdout.write(format_text(summary))
    if args.expect_zero and summary["n"] != 0:
        sys.stderr.write(
            "expect-zero: found %d exact-%d payloads (carrier is not off, or the capture is not node→proxy)\n"
            % (summary["n"], WINDOW_BYTES)
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
