# RT-P6, the stranger re-measured with mac1 on the floor device. Registration of 2026-10-20

**State of this record: run 2026-10-20; results below.** Results are added under
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

The harness's dry cell (50 of each) ran in the same script, after the
build and a 180 s cool-down, at 05:07:05Z: every step succeeded, all 50
honest messages 1 were accepted and none of the other two kinds was. Its
figures are not data.

## Results

**The registered cell passed every gate. The daemon's handshake p99 rose,
so by the registered rule the budget's constant moves to this run's
2,163.8 µs.** The figures below are the summary (`rt_p6_summary.py
--mac1`), as produced. Captures, with checksums:
[`rt_p6_mac1_stranger_20261020_captures/`](rt_p6_mac1_stranger_20261020_captures/).
The three raw files are there gzipped (`gzip -9n`), with the summary, the
conditions and the run's step log.

### Conditions, recorded as registered

- **Device and build:** the floor device (Raspberry Pi 4, Cortex-A72, 4
  cores, 1.8 GHz top clock), under a quiet claim. The build is
  `5db6eeda8f`, the commit carrying this registration, built in release
  with toolchain 1.94.0 in 171 s.
- **Where the source came from, which is not what was registered.** The
  registration says "a fresh clone of that commit". The first attempt
  cloned from GitHub, which served the device at about 33 KB/s at
  04:50Z, so it was stopped before anything was built. The source used
  was a depth-1 clone of `5db6eeda8f` made on the workstation and copied
  over the LAN, then cloned on the device. The script checked the
  checked-out commit against `5db6eeda8f` by its hash before building. The
  submodules came from the device's own checkout of 2026-09-29: their
  pinned commits are the same at `5db6eeda8f` (`git diff` over the four
  gitlinks is empty), and the harness links none of them.
- **Timing:** a 180 s cool-down, the dry cell, 60 s, then the registered
  cell pinned to core 3, 05:08:05Z to 05:09:25Z (80 s).
- **The standing testnet daemon** was left running, as registered, and
  was active at every reading. It used 1.39 s of CPU over the registered
  cell (139 ticks), against 70 ms in RT-P6's cell. It was not pinned away
  from core 3, so some of that time may have shared the measured core.
  Every handshake step's CPU median is within 2 % of RT-P6's except
  `read_message1`, which carries mac1 (+2.1 %); the tails are where that
  time would show.

| | Before the registered cell | End |
|---|---|---|
| Governor | `ondemand` | `ondemand` |
| SoC temperature | 46.3 °C | 52.6 °C |
| Load, 1 min | 0.17 | 0.89 |
| Under-voltage alarm | 0 | 0 |
| Clock-speed changes, total | 7,565,910 | 7,565,942 |

**Gates.**
- The harness's assertions held: every step succeeded; all 10,000 honest
  messages 1 were accepted, and none of the 10,000 tag-flipped or 10,000
  no-bundle ones.
- The under-voltage alarm stayed clear.
- Time at top clock over the registered cell: 7,946 of 7,954 ticks at 1.8
  GHz, **99.90 %**, against the registered 99 %.

### Each step (µs)

| Side | Step | n | Wall median | Wall p90 | Wall p99 | Wall max | CPU median | CPU p90 | CPU p99 | CPU max |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| client | `start` | 10000 | 879.1 | 891.4 | 900.9 | 1,151.5 | 881.1 | 888.7 | 898.3 | 1,176.4 |
| daemon | `new` | 10000 | 8.5 | 8.6 | 9.1 | 61.8 | 10.0 | 10.1 | 10.7 | 51.3 |
| daemon | `read_message1` | 10000 | 643.9 | 657.1 | 665.2 | 969.2 | 645.7 | 654.3 | 661.1 | 1,005.4 |
| daemon | `write_message2` | 10000 | 856.5 | 869.4 | 877.6 | 1,099.1 | 858.4 | 866.7 | 873.6 | 1,071.6 |
| client | `read_message2` | 10000 | 622.1 | 635.1 | 641.4 | 712.3 | 624.0 | 632.4 | 637.7 | 705.8 |
| client | `write_message3` | 10000 | 345.1 | 353.2 | 367.4 | 429.6 | 346.7 | 354.9 | 364.1 | 378.8 |
| daemon | `read_message3` | 10000 | 358.7 | 378.9 | 380.9 | 513.1 | 360.4 | 376.1 | 377.6 | 398.6 |
| daemon | `write_message4` | 10000 | 240.3 | 247.7 | 260.8 | 399.1 | 242.1 | 249.5 | 258.1 | 410.8 |
| client | `read_message4` | 10000 | 290.6 | 311.4 | 314.0 | 541.1 | 292.5 | 308.6 | 310.5 | 563.8 |
| client | `first_record` | 10000 | 6.8 | 7.1 | 10.0 | 41.8 | 8.3 | 8.6 | 11.9 | 43.7 |
| daemon | `open_first_message` | 10000 | 7.2 | 7.5 | 8.5 | 30.0 | 8.7 | 9.0 | 10.0 | 26.7 |

### Per handshake (µs)

| Total | n | Wall median | Wall p90 | Wall p99 | Wall max | CPU median | CPU p90 | CPU p99 | CPU max |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| client | 10000 | 2,155.7 | 2,172.4 | 2,193.2 | 2,470.9 | 2,160.4 | 2,173.9 | 2,191.9 | 2,502.7 |
| daemon | 10000 | 2,126.7 | 2,135.0 | 2,162.7 | 2,602.6 | 2,132.3 | 2,140.5 | 2,163.8 | 2,652.2 |
| both | 10000 | 4,281.5 | 4,296.9 | 4,346.5 | 5,073.5 | 4,292.0 | 4,305.8 | 4,352.6 | 5,154.9 |

### A stranger's message 1 (µs)

| Kind | Part | n | Accepted | Wall median | Wall p90 | Wall p99 | Wall max | CPU median | CPU p90 | CPU p99 | CPU max |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| honest | `new` | 10000 | 10000 | 8.4 | 9.4 | 15.2 | 101.8 | 9.9 | 11.0 | 16.9 | 80.4 |
| honest | `read_message1` | 10000 | 10000 | 644.0 | 708.9 | 827.7 | 1,087.8 | 645.9 | 712.0 | 823.4 | 1,051.0 |
| honest | `attempt` | 10000 | 10000 | 652.5 | 718.7 | 839.0 | 1,115.4 | 655.8 | 723.4 | 835.9 | 1,082.6 |
| tag_flipped | `new` | 10000 | 0 | 8.5 | 8.6 | 8.9 | 28.3 | 10.0 | 10.1 | 10.6 | 25.2 |
| tag_flipped | `read_message1` | 10000 | 0 | 643.3 | 656.1 | 659.2 | 700.9 | 645.1 | 653.4 | 655.6 | 686.1 |
| tag_flipped | `attempt` | 10000 | 0 | 651.8 | 664.6 | 667.6 | 709.3 | 655.1 | 663.4 | 665.5 | 696.4 |
| no_bundle | `new` | 10000 | 0 | 8.3 | 8.4 | 9.3 | 42.6 | 9.7 | 9.8 | 14.4 | 37.8 |
| no_bundle | `read_message1` | 10000 | 0 | 13.8 | 15.1 | 20.7 | 78.0 | 15.2 | 16.6 | 22.6 | 38.6 |
| no_bundle | `attempt` | 10000 | 0 | 22.1 | 23.4 | 29.9 | 86.3 | 25.0 | 26.3 | 34.1 | 53.5 |

### One record at each class (µs)

| Class (bytes) | Op | n | Wall median | Wall p90 | Wall p99 | Wall max | CPU median | CPU p90 | CPU p99 | CPU max | ns per byte (CPU median) |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 512 | seal | 10000 | 4.2 | 4.2 | 4.6 | 865.2 | 5.6 | 5.6 | 6.2 | 861.4 | 10.96 |
| 512 | open | 10000 | 4.4 | 4.6 | 4.9 | 33.3 | 5.8 | 6.0 | 6.4 | 24.8 | 11.29 |
| 16,384 | seal | 10000 | 113.2 | 119.7 | 144.8 | 999.0 | 114.7 | 121.4 | 139.6 | 984.1 | 7.00 |
| 16,384 | open | 10000 | 111.1 | 117.1 | 133.0 | 193.9 | 112.7 | 118.6 | 129.1 | 144.8 | 6.88 |
| 65,535 | seal | 10000 | 448.9 | 468.4 | 1,278.1 | 1,324.0 | 450.5 | 465.3 | 1,272.1 | 1,326.5 | 6.87 |
| 65,535 | open | 10000 | 441.5 | 458.4 | 464.8 | 506.5 | 443.1 | 456.0 | 460.6 | 487.2 | 6.76 |

### What is reported, as registered

- **A stranger without the bundle now costs the daemon 25.0 µs of CPU at
  the median and 34.1 µs at the 99th percentile** (the `no_bundle`
  attempt: `new`, then `read_message1` refusing at mac1). Before mac1, a
  stranger's message 1 was RT-P6's `tag_flipped` attempt: 641.1 µs at the
  median and 818.5 µs at the 99th percentile. At the 99th percentile that
  is **24 times less**. What is left is building the responder's state
  (`new`, 9.7 µs at the median) and one keyed BLAKE2s over 2,320 bytes
  (`read_message1`, 15.2 µs).
- **mac1 on a message that passes it**, this run against RT-P6, CPU
  median:
  - the honest attempt, 655.8 µs against 640.1 µs, **+15.7 µs**;
  - the tag-flipped attempt, 655.1 µs against 641.1 µs, **+14.0 µs**;
  - the handshake's own `read_message1` step, 645.7 µs against 632.4 µs,
    **+13.3 µs**.

  Each is the size of the no-bundle refusal's `read_message1`, which is
  mac1 alone: the cost is the keyed hash, as expected. The client's
  `start`, which computes the mac1, rose by 5.9 µs at the median (881.1
  against 875.2).
- **The daemon's whole handshake**, which now includes mac1: 2,132.3 µs of
  CPU at the median and **2,163.8 µs at the 99th percentile**, against
  RT-P6's 2,119.1 and 2,136.1. The p99 rose by 27.7 µs (1.3 %).

### The rule for the budget, applied

The daemon's handshake p99 is higher than RT-P6's, so
`HANDSHAKE_DAEMON_CPU_NANOS` moves from 2,136,100 to **2,163,800** in this
PR, and its measurement-ledger row is captured again on this run. At the
ruled share, a quarter of one core, the budget now admits 250,000,000 /
2,163,800 = 115.5, so **115 handshakes a second, 115 at once**, where it
admitted 117. A message 1 that fails at its tag costs the daemon 665.5 µs
at the 99th percentile here, below the 2,163.8 µs charge, so a mix of
admitted attempts is priced at or above its measured p99. That percentile
is not a maximum. The bucket bounds charges,
`charges ≤ share × elapsed + capacity`, with capacity one second of the
share.
