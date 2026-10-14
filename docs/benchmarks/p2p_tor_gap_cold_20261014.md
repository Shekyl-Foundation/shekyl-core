# Tor gap from cold first contact, 2026-10-14

**Status: IN PROGRESS (run A read and corrected 2026-10-14: its
responder-side numbers are not usable; run B stopped at sample 17; both
rerun with lifted spans once logging never blocks, `shekyl-core` #1069;
the derivation and the spans change wait for Rick's reading of the
rerun).** Ruled by Rick, 2026-10-13: the Tor gap is re-derived from cold
first contact, on two responders, before anything else changes (PR-3,
#1056; the brief's revision 4). Ruled again 2026-10-14: three fixes
first (logging never blocks; the gap measures the peer's silence; one
process clock), then the rerun.

## Why

The 2026-09-29 rig (`p2p_cutover_crossbuild_20260929.md`) measured the
Tor gap as the channel-to-session interval on warm circuits between a
dialer and a seed that had already talked: it excluded cold first
contact, where the dialer's managed tor holds no descriptor and builds
its circuits from nothing. `TOR_GAP_WITHIN_NANOS` was set from it at
2.6 s. The first §4 run of PR-3 (attempt 7, 2026-10-13) lost a session
to that gap on a cold contact, and the ruling followed. **These runs
supersede the 2026-09-29 rig for the gap.**

## Instrument (`8359ef531`, debug lines that stay in the code)

In the Tor driver, from the instant it keeps for the channel (the
responder's accept, the dialer's SOCKS success):

- `tor first bytes written` — the writer puts a connection's first
  bytes on the wire: the dialer's handshake request, the responder's
  first reply;
- `tor first bytes read` — the reader takes its first bytes: the
  responder's accept to the request, the dialer's reply;
- `tor session established` (`gap_ns`, already there) — channel to
  session, both sides.

In the dialer, how long after the channel opened the handshake request
was queued (`handshake queued … ns after the channel opened`), so a
client-side delay before the wire is told apart from the wire.

## Rig

Roles, not hosts (rule 37). The client is a stagenet daemon on an x86
fleet host (Ubuntu 24.04), built from a fresh checkout of `8359ef531`
with `-DARCH=default`, with the pinned 15.0.24 Tor Expert Bundle beside
it. **Every sample restarts the client daemon and its managed tor** in a
wiped data directory: no cached descriptor, fresh circuits. The client
names the responder with `--add-peer <onion>:13021` and
`--p2p-disclose-early`; the responder runs the same build with the flag
and stays up for the whole run. Clearnet is bound to loopback on both,
so Tor is the only way between them. Ports and hosts are in
`shekyl-dev`'s usage ledger.

- **Run A:** the responder is the measurement host (x86, Ubuntu 24.04).
- **Run B:** the responder is the floor device (Pi 4, aarch64, rule 76),
  built natively from the same commit, with the pinned 16.0a13 aarch64
  bundle beside it. The same client, the same link.

Per sample the TSV records the outcome, the dialer's SOCKS leg
(`c_proxy_connect_ns`, `c_dial_ns`), the queue delay (`c_queued_ns`),
`c_first_write_ns`, `c_first_read_ns`, `c_gap_ns`, and from the
responder's log, joined by the sample's window, `b_first_read_ns`,
`b_gap_ns` and the responder's close cause. Outcomes other than
`session` are the timeouts, by kind:

- `TransportTimeout:0` — the Tor dial deadline (9.1 s) before SOCKS
  success;
- `LevinHandshakeTimeout:0` — the dialer's gap (2.6 s) after SOCKS
  success, no reply;
- `timeout` — the managed tor did not bootstrap within the sample's 120 s;
- `ProxyRefused:240` — SOCKS reply 0xF0, descriptor not found.

**The rerun's build (ruled 2026-10-14).** The client and both
responders run a measurement build: CMake's `SHEKYL_MEASUREMENT_SPANS`
option lifts the Tor dial and gap deadlines to 120 s
(`shekyl-transport-layer`'s `measurement-spans` feature), so neither
distribution is cut at the deadline it derives. The daemon logs a
warning at start when it is one. `scripts/ci/check_measurement_spans.py`
fails any release path that turns the option on. The rerun also records
`first_frame_ns` on both sides, the gap's new end, and keeps the data
directory of any sample whose Tor does not bootstrap.

Raw rows: `p2p_tor_gap_cold_20261014_runA.tsv`,
`p2p_tor_gap_cold_20261014_runB.tsv`. Percentiles are the nearest-rank
`ceil(p × n)`.

## Run A (100 samples, 02:58Z to 03:58Z)

| Outcome | n |
| --- | --- |
| session | 66 |
| `TransportTimeout:0` | 26 |
| `timeout` (tor bootstrap) | 5 |
| `LevinHandshakeTimeout:0` | 3 |

Over the 66 sessions:

| Series | p50 | p90 | p99 | max |
| --- | --- | --- | --- | --- |
| dialer SOCKS success → request on the wire | 0.4 ms | 0.5 ms | 0.6 ms | 0.6 ms |
| dialer SOCKS success → first reply byte (outbound gap) | 515 ms | 806 ms | 1663 ms | 1663 ms |
| responder accept → first byte read (inbound gap) | 500 ms | 749 ms | 955 ms | 955 ms |
| dialer channel → session | 516 ms | 808 ms | 1664 ms | 1664 ms |
| responder channel → session | 527 ms | 786 ms | 956 ms | 956 ms |
| Tor dial, start → SOCKS success | 4.51 s | 6.36 s | 8.47 s | 8.47 s |

**Readings.** The dialer's own interval has no tail: the pause is not in
the client. Whether it is in the Tor network or in the responder is not
settled by this run (the correction below). The outbound direction is the larger.
Both gap series are censored at the current spans: 3 of the 69 contacts
that reached SOCKS success exceeded the dialer's 2.6 s gap, so the
uncensored p99 is at the gap or above it; 26 of 100 cold dials exceeded
the 9.1 s Tor dial deadline, which the 2026-09-29 floor distribution set
from warm circuits.

**Corrected 2026-10-14: the responder's refusals were its own logging
stalls, not a stray wake.** Four of the responder's 69 accepts ended as
`SessionRefused` or `LevinHandshakeTimeout` on its side (its connections
76, 78, 80, 82), and the client's three `LevinHandshakeTimeout:0`
samples match them. The responder's stderr log layer wrote
synchronously. When a write to stderr stalled, every thread that logged
waited on it: the P2P transport workers and both dialer loops among
them. The instrumented reproduction the same day caught one such stall
at 18 s on the measurement host and four longer than 5 s within an
hour. There the engine fired the gap 0.2 ms late, and the driver took
the wake 15.5 s after. A log line is stamped when it is written, after
the stall, so in run A the accept looked 0.3 to 0.8 s old when the gap
fired; it was older than the 2.6 s gap. The two dialer loops woke in the
same half-millisecond because the same stall released them.
*Records-was:* this section read the refusals as a Discovery wake
delivered to the Transport owner. The instrumented runs found no
misrouted wake, no late engine delivery (Transport worst 0.2 ms) and no
clock offset worth the name (0.49 ms). The fixes: every log sink behind
a bounded queue that drops and counts (`shekyl-core` #1069); the gap ends
at the peer's first complete Levin frame and a fired wake waits one IO
driver turn for the reader (`dc9130534`); one process clock (`9d17708e2`).

**What this does to run A's numbers.** The responder-side series (the
inbound gap, the responder's channel to session) and the outbound gap's
tail can carry responder stalls, and the three client handshake timeouts
are responder stalls. None of them is used for the derivation; the rerun
replaces them. The gap now ends at the first complete frame, so the
rerun records `first_frame_ns` on both sides beside `gap_ns`.

**The 26 client dial timeouts are not client-host stalls** (checked
2026-10-14). The client's clearnet dialer logs a wake about once a
second. Inside every timed-out dial window the largest hole in that
heartbeat is at most 1.50 s, the same as in the successful dials (at
most 1.88 s), and the client's log layer was as synchronous as the
responder's, so a stall would have opened a hole. 26 of 100 cold Tor
dials took longer than the 9.1 s deadline.

**The five `timeout` samples are managed-tor bootstrap failures.** Each
client log ends at `Initializing p2p server` and says nothing more
before the sample is stopped at 120 s: the operator sees a node that is
silent, not one that says Tor has not bootstrapped (FOLLOWUPS).

Also seen (sample 48): the responder's accept came 4.3 s after the
dialer's SOCKS success, after the dialer had timed out and closed; the
inbound gap as instrumented does not see a stall that precedes the
accept, the outbound gap does.

## Run B

Stopped at sample 17 of 100 (04:15Z) when the responder defect was
ruled to be fixed first. Its rows are not recorded; it reruns with A.

## Derivation (D9)

*After both runs and Rick's reading.* `TOR_GAP_WITHIN_NANOS` = 2 × p99 of
the largest distribution across both runs and both directions, labelled
`RustPath`, with this document as the provenance in `spans.rs`; if run B
governs, the floor sets the number. The measurement ledger's Tor-gap row
cites the two debug timings as the samples that can reopen it.
