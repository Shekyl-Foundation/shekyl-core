# RT-P6, the stranger re-measured with mac1 on the floor device. Registration of 2026-10-20

**State of this record: registered; not yet run.** Results are added under
"Results"; "Registered before the run" is not edited afterwards. An
amendment made before any registered result is read is dated and says
what changed.

## The question

The maintainer ruled on 2026-10-20 that message 1 carries a mac1 checked
before any long-term key is used, and that message-1 decapsulations are
paid from a handshake budget (`RPC_CHANNEL.md` §4.3), with the stranger's
cost re-measured on the floor device. This is that re-measurement. It
asks:

- **A stranger without the bundle:** what does the daemon now spend on
  that stranger's message 1, refused at mac1?
- **A sender with the bundle:** what does a message 1 cost the daemon now
  that it is checked by mac1 and paid from the budget? Two cases: one that
  completes, and one whose tag fails.

RT-P6's registered run (`rt_p6_handshake_cost_20261018.md`) measured the
same daemon before mac1 existed; its method is reused here unchanged
except where this registration says.

## Registered before the run

**Subject.** The handshake of `shekyl-rpc-channel` at the commit carrying
this registration, with mac1 and the budget. Built with `cargo build
--release` under the pinned toolchain (1.94.0), on the floor device, from
a fresh clone of that commit.

**Instrument.** `rust/shekyl-rpc-channel/examples/rt_p6_handshake_cost.rs`,
RT-P6's harness, moved to the new message 1:
- The client's `start` now appends the mac1.
- The daemon's `read_message1` takes a budget and the time, and gets an
  unbounded one: the whole of a core, a day's burst. This run measures what
  a message costs, not how many are admitted; the budget's own tests cover
  admission.
- The harness runs its three parts, as RT-P6 did. Everything in RT-P6's
  "Instrument" section stands, with three kinds of message 1 in place of
  two:
  - **honest:** a message 1 from `Client::start`, mac1 included;
  - **tag_flipped:** that message with the last byte of its Noise tag
    flipped and its mac1 made again over the changed bytes, as a sender
    holding the bundle can. It passes mac1, the key check and the budget,
    and fails at the tag after the decapsulation and the Diffie-Hellman;
  - **no_bundle:** the honest message with the last byte of its mac1
    flipped, as a sender without the bundle sends. It fails at mac1.

  For each message, the daemon's `new` and `read_message1` are two timed
  calls, and the attempt is their sum. Every honest message is accepted
  and no other is.

**Counts, statistics, gates and conditions:** RT-P6's, unchanged.
- **Counts:** 200 warm-ups, then 10,000 of each.
- **Statistics:** nearest-rank median, 90th and 99th percentiles and
  maximum, of the wall and thread-CPU clocks, by
  `scripts/bench/rt_p6_summary.py --mac1`, which reads the three kinds and
  refuses a capture of any other shape.
- **Gates:**
  - the harness's assertions;
  - the under-voltage alarm clear;
  - at least 99 % of the run at the top clock.
- **Conditions:** recorded at the start, before each cell and at the end,
  as RT-P6 did. The standing testnet daemon is left running and its CPU
  recorded, as on 2026-10-19.

**Pinned to core 3, under a quiet claim.** At most two registered
attempts. A void attempt is recorded with its cause, the cause is fixed,
and the second is made under the same lines.

**What is reported:**
- the no-bundle attempt's CPU (the stranger's cost now) at each
  percentile;
- the honest and tag-flipped attempts beside RT-P6's figures for the same
  kinds, and the difference: mac1's cost on a message that passes it;
- the daemon's whole handshake per iteration, which now includes mac1.

**A rule for the budget, fixed now.** The budget charges each admission
`HANDSHAKE_DAEMON_CPU_NANOS` = 2,136,100 ns, RT-P6's 99th percentile of the
daemon's whole handshake. If this run's 99th percentile of the same series
is higher, the constant moves to it in the results PR, with its
measurement-ledger row re-captured on this run. If it is not higher, the
constant stays, and the row records that this run did not move it.

**Captures:** `docs/benchmarks/rt_p6_mac1_stranger_20261020_captures/`,
in RT-P6's shape: the raw files gzipped, the summary, the conditions, the
step log and `SHA256SUMS`.

## Dry run

None yet.

## Results

None yet.
