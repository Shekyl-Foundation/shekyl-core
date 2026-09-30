# P2P differential harness

**Status: OPEN.** The epee recording host is deleted. CI is
`check-goldens` against the option-off parity goldens
(`p2p-harness-seeds`). Option off, on loopback. The comparison is
what the peer receives back and whether the session is established.

## Expected divergences

The loopback transcript records Levin bytes and the session outcome.
It does not observe these stack differences; they are not a filter
on a parity field. After cutover they become standalone CI checks
on the Rust transport (`DeferredInvariant` in `shekyl-p2p-harness`).
That list is in-flight vocabulary, not dead code: the cutover pull
request is the named consumer.

- FIN after zero bytes when a connection fails before the channel exists
  (`fin-after-zero-bytes`);
- typed causes, with the first one recorded winning
  (`typed-cause-first-wins`);
- admission refusal at accept via atomic reservation
  (`admission-reservation`);
- derived deadlines, not epee's (`derived-deadline`);
- no local/remote timer split (`no-timer-split`);
- no TOS setting (`no-tos`).

Seed 32 is the one divergence the transcript can see. After the
handshake response the host queues one byte past the seam send
queue (64 KiB). The seam refuses that buffer (`SendQueueFull`) and
the epee host accepts it. `compare` names that `host-sent` /
`peer-recv` suffix `byte-bounds` only when both sides still start
with the script's handshake response. A difference inside that
prefix is a parity finding. The handshake the peer wrote still has
to match.

## How two stacks are compared

The goldens were recorded from the epee side, C++ in
`boosted_tcp_server`. That server and `epee-host` are deleted. CI
is `check-goldens`. The seam side is Rust. The harness does not
link epee into a Rust test. C++ was the recording reference, not
the behaviour to copy (rule 20).

The typed plan lives in Rust. `NamedSeed` plus `PROPERTY_SEEDS`
(100–115) is the seed table. `AfterHandshake` (`none`, `follow`,
`send-over`, `pause`) is what both hosts do after the first invoke.
`all_seeds()` is the list `check-goldens` runs. There is no second
copy of that list in C++ or in a shell script.

One scripted peer, `shekyl-p2p-harness`'s `peer`, is built on
`shekyl-levin`. It connects to an address, runs a seed, and writes a
transcript: every byte it sent and received, and how the connection
ended. The seed is on the transcript, so a failing case replays
against either host.

Two hosts, each with a recording handler:

- `seam-host`, the Rust host. Until zone bind its socket is the public
  clearnet `listen` with the option off. The session bytes are what
  the seam delivers to the Levin handler. It does not use the
  connector's tests, and it does not open a second admission table.
- `epee-host` (deleted). It hosted `boosted_tcp_server`, served
  one connection, and wrote this transcript. It was the only C++ in
  the harness, and it was not linked into the Rust crate. Handshake
  encode and decode stayed in that binary: that was the epee reference.
  Host behaviour after the invoke was a CLI plan
  (`--after none|follow|send-over|pause`, `--wait-ms`, `--pause-ms`,
  `--settle-ms`, `--over-bytes`). Durations and the send-queue cap
  came from the Rust driver so that binary did not own the seed
  table. A P2P connection enabled epee's rate limiter, whose unset
  target was 16 KiB/s. The harness set that limit to the maximum so
  the recording compared Levin bytes. It did not test the operator
  link budget.

`seam-host SEED TRANSCRIPT` prints `host:port` on stdout, serves
one connection, and writes the host transcript. The deleted
`epee-host` did the same. `peer ADDR SEED TRANSCRIPT` dials that
address. `compare PEER_A HOST_A PEER_B HOST_B` diffs two runs.
`peer`, `seam-host`, and `compare` stay for replay of a kept
`p2p-harness-fail/` directory.

Before the deletion the gate was `run-seeds EPEE_HOST`. It owned the
seed list, ran the seam in-process (in parallel with the epee
process), required the seam run to match the script, and diffed the
two hosts. A mismatch kept the four transcripts under
`p2p-harness-fail/seed-N/`. After the deletion, ctest
`p2p-harness-seeds` is `check-goldens` on the committed goldens.
The test job unpacks `build/` and has no cargo, so CMake copies
`check-goldens`, `peer`, `seam-host`, and `compare` into that tree.
On UNIX without cargo the test still exists and fails: absence of
the bins is not a green skip.

`compare` diffs the two transcripts. A difference in a parity field
(`peer-sent`, `peer-recv`, `peer-end`, `host-delivered`, `host-sent`,
`host-session`) is a finding. A run whose peer and host disagree on
role, version, or direction is a finding before the stacks are
compared. Seed 32 may carry a host-sent suffix the peer has not
read; any other mismatch is a malformed run. An unknown version
line is a parse failure, not a mismatch.

Seed 1 is the handshake invoke. The dialer sends it and waits. The
session is established when the response is back. `the_same_seed_replays_against_the_seam_host`
runs that seed twice against the seam host. `each_leg_matches_the_script_on_the_seam_host`
runs every seed in `all_seeds()` against the seam host and checks
the script.

## Transcript

Version 1 is the format every seed uses except backpressure. Both
writers emit the same version for a seed. `compare` rejects any other
version line, so a drift between them is a parse failure.

The file is UTF-8. One field per line, LF endings, and a trailing LF
after the last line. There is no timestamp. A writer emits exactly
these lines, in this order:

```text
shekyl-p2p-transcript 1
seed <u64 decimal>
role <peer|host>
sent <hex>
recv <hex>
end <established|closed|refused>
```

`seed` is the script. `role` is `peer` or `host`. For a peer, `sent`
is the bytes it wrote and `recv` is the bytes it read. For a host,
`recv` is the bytes delivered to the Levin handler and `sent` is the
bytes that handler sent. Those are the bytes on the connection, the
header included.

Byte fields are lowercase hexadecimal, two digits per byte, no
separators. An empty field is the key, one space, and nothing else.
A digit outside `0-9` and `a-f`, or an odd number of digits, does not
parse.

`end` is `established`, `closed`, or `refused`. `established` means
the handshake response came back. `closed` means the peer closed
before that response. `refused` means the invoke was not a handshake.
It is not a transport cause.

Version 1 rejects an extra line. A missing field, or a version line
other than `shekyl-p2p-transcript 1` or `shekyl-p2p-transcript 2`,
does not parse.

Version 2 is the backpressure seed. It keeps these six lines, then an
event log, and the version line is `shekyl-p2p-transcript 2`. Each
event is one line, in order, with no timestamp:

```text
event wrote <hex>
event read <hex>
event stalled
event resumed
```

`wrote` and `read` use the same hex as `sent` and `recv`. `stalled` is
the moment a write stopped making progress, or the host stopped
reading. `resumed` is the moment that wait ended. A golden's first
line is the version, so the format it uses is on the golden.

## Ordering

Two pull requests, not five steps.

This one finishes the harness. Every seed in `all_seeds()` runs
against both hosts. It merges when that gate is green. A mismatch
that is not seed 32's classified send-queue suffix is fixed in this
pull request.

The cutover is this branch. The zone binding and the
deletion land together: a period where production runs on the seam
with epee still in the tree is not a state anything needs. That
branch carries the zone binding and the call sites that move with it
(socket admission reads the Rust counts, both ban-list writers reach
the Rust list, `m_our_address` comes from Tor publication, `get_info`
reports real socket counts), the cross-build run and the measurements
taken on that build and recorded as run records, then D13's deletions,
the epee goldens, the I2P address type deleted, and the pipe branch
deleted. It merges once, when the run records are in.

UPDATE 2026-09-30: the epee host and `boosted_tcp_server` are
deleted. `p2p-harness-seeds` runs `check-goldens` on the parity
goldens. The measurements are taken on the build that ships, which
is the cutover branch.

## Goldens

Before cutover, the peer runs against both hosts and `compare` diffs
them.

At cutover, the epee host's transcripts for the parity scope — wire
bytes and session outcomes, not a `DeferredInvariant` and not
`byte-bounds` — are recorded as golden transcripts and committed,
keyed by seed. `record-goldens` writes that scope
(`goldens/seed-<n>-peer.txt` and `goldens/seed-<n>-host.txt`): the
version line, the parity fields, and nothing else. Events are omitted.
A send-over suffix past the script's handshake response is omitted.
The six deferred invariants are not transcript fields, so they are
not in the files. Recorded at `88a202195`. Option-off goldens;
re-recorded at the flip per §Goldens. The epee host is deleted
with that server. CI runs `check-goldens` on these files.

After cutover, in CI, the same peer runs every seed against the Rust
transport. Each run checks the goldens (the peer still sees the same
Levin bytes and gets the same session outcome) and the
`DeferredInvariant` checks that need no epee reference: whole messages
only, stopping reading rather than closing under backpressure, one
cause with the first recorded winning, FIN after zero bytes, and the
byte bounds. The epee host is gone; the peer and the script stay.

A golden changes only on purpose. When a ruled change alters the wire
— the flip adding Noise, or fixed-window framing — the goldens are
re-recorded in that same pull request, with the ruling cited. A golden
that changes without a ruling behind it is a regression.

Later the same peer drives the Tor leg, and after LV-3 it tests the
Rust Levin layer. The peer stays; the epee host does not.

## In-process legs

`COMMAND_HANDSHAKE` (1001) is an invoke. A notify for 1001 is not this
exchange. Every handshake in these scripts is the same one: network id
sixteen bytes of `0x11`, IPv4 `0.0.0.0:18080`, support flags 0, height
1, cumulative difficulty 2, difficulty top64 0, top id thirty-two bytes
of `0xab`, top version 0, and a nonce whose first eight bytes are
`1` little-endian. The response is the same node and sync data with an
empty peer list. The script seed selects the leg. It does not mint a
second handshake.

An invoke that is not that handshake gets an empty response for its
command, and the session is `refused`. A notify gets no response. A
close before a whole message is `closed`.

| Seed | Leg |
| --- | --- |
| 1 | Handshake, one write. |
| 2 | That handshake, split after the 29-byte header. |
| 3 | That handshake, one byte per write. |
| 100–115 | That handshake, split on a stride derived from the seed. |
| 10 | `COMMAND_REQUEST_SUPPORT_FLAGS` (1007) invoke whose payload is that command's cap. |
| 11 | The handshake, then a `NOTIFY_NEW_COMPACT_BLOCK` (2008) notify whose payload is that command's 4 MiB cap. |
| 20 | The handshake response, then a `COMMAND_TIMED_SYNC` (1002) notify of the bytes `relay`, queued without waiting for the first to flush. The peer's bytes parse as two whole messages. |
| 30 | The peer closes after 10 bytes of the handshake. |
| 31 | An invoke of 1001 whose payload is not a handshake. |
| 32 | After the handshake response, the host queues one byte more than the seam send cap (64 KiB). The seam refuses that buffer and the epee host accepts it. `compare` names that `host-sent` / `peer-recv` difference `byte-bounds`. The handshake the peer wrote still has to match. |
| 40 | After the handshake response the host stops reading for 400 ms, and the peer writes four 2 MiB `NOTIFY_NEW_COMPACT_BLOCK` notifies. Version 2. |
