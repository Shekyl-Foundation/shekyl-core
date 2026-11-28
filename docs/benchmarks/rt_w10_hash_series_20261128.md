# RT-W10's hash series on the floor device, 2026-11-28: the RandomX rounding fix

**State of this record: measured 2026-11-28.** It re-measures the
`header` and `max` series of
[`rt_w10_request_cost_20261102.md`](rt_w10_request_cost_20261102.md)
with the RandomX rounding fix
([`RANDOMX_ROUNDING_DECISION.md`](../design/RANDOMX_ROUNDING_DECISION.md)),
and sets `HASH_CPU_NANOS` from it (Rick, 2026-11-28: re-measure it for
the record). The other RT-W10 series are not re-run: no change here
touches a store read or a transaction parse.

## Method

The instrument, the series and the statistic are RT-W10's, unchanged:

- `rust/shekyl-pow-randomx/examples/rt_w10_request_cost.rs` writes
  `hashes.tsv`: one `compute_hash` over a cache derived once and then
  only looked up, for a 136-byte blob (`header`) and a 33,000,128-byte
  blob (`max`).
- 5 warmup calls, not recorded, then 100 samples of each series.
- A series' cost is its thread-CPU 99th percentile
  (`CLOCK_THREAD_CPUTIME_ID`), nearest rank, rank 99 of 100. Wall is
  recorded beside it.
- The harness runs pinned to core 3 at `nice -n 10` and `ionice -c3`.
- RT-W10's gates: every call succeeds (the harness asserts it); no
  series has a thread-CPU 99th percentile of 0; the under-voltage alarm
  (`rpi_volt`, `in0_lcrit_alarm`) stays clear; the pinned core spends at
  least 99 percent of the run at its top clock, by
  `cpufreq/stats/time_in_state` read at both ends.

Two runs, back to back on the same device: the code before the change
(`base`), then the change (`change`).

**Where this run departs from the 2026-11-02 registration, and why:**

- **The device.** This is the second floor device: a Raspberry Pi 4
  Model B Rev 1.2 with 4 GB, whose top clock is 1.5 GHz. The 2026-11-03
  run was on the first, which runs at 1.8 GHz. Both are the floor
  device of
  [`176-device-provisioning-floor`](../../.cursor/rules/176-device-provisioning-floor.mdc),
  and rule 176 says to err toward the slower one.
- **The build.** The binaries were cross-built on a build VM (rustc
  1.94.0, `--release`, target `aarch64-unknown-linux-gnu`, no
  `target-cpu`), and checked by SHA-256 on the device before the run.
  The registration compiled on the device. The release profile is the
  workspace's either way.
- **No standing daemon.** This device runs no testnet daemon, so none
  was up. The registration left the first device's daemon running.
  This run's load is the harness alone.

## Builds

- `base`: git revision 0b94b657cc5d4ce60a7eaf7ae16148442f0d095c, the
  development branch before the change.
- `change`: git revision 2d5f7e1367792ed44497767e6b59bc9e5b7bfdc2. The
  commit after it changes only x86_64 code: built at that commit, the
  harness's aarch64 `.text` section is byte-identical to this build's.

## Conditions

| | `base` | `change` |
|---|---|---|
| window (UTC) | 12:05:02 to 12:10:29 | 12:11:29 to 12:17:07 |
| one-minute load, start / end | 0.98 / 1.00 | 0.42 / 1.00 |
| governor | `ondemand` | `ondemand` |
| SoC temperature, start / end (m°C) | 52,095 / 53,069 | 49,660 / 51,608 |
| under-voltage alarm | 0 / 0 | 0 / 0 |
| core 3 at 1.5 GHz (jiffies of 10 ms) | 32,685 of 32,688 | 33,773 of 33,778 |
| standing daemon | none | none |

Both runs pass the 99 percent clock gate (99.99 and 99.99 percent).

## Results

**Thread-CPU, nearest rank, n = 100, the 99th percentile at rank 99.**

| Series | `base` CPU p99 (ns) | `change` CPU p99 (ns) | change | `change` wall p99 (ns) |
| --- | --- | --- | --- | --- |
| `header` (136 bytes) | 1,480,596,442 | 1,526,655,460 | +3.1 % | 1,530,305,830 |
| `max` (33,000,128 bytes) | 1,608,490,012 | 1,663,419,916 | +3.4 % | 1,667,542,930 |

The `change` header series' CPU median was 1,523,925,546 ns and its
maximum 1,529,852,792 ns. The `base` header series' maximum was
1,517,246,194 ns, one sample; its median was 1,475,280,562 ns.

**The constant.** `HASH_CPU_NANOS` = 1,526,655,460, the `change` header
CPU p99. At the hash budget's quarter-core share it is earned every
6,107 ms. Of the move from 1,290,885,199 (2026-11-03), most is the
device: at the base revision this device's header p99 is
1,480,596,442. The rounding fix adds 3.1 percent.

**Captures:** `rt_w10_hash_series_20261128_captures/`: `hashes-base.tsv`,
`hashes-change.tsv`, the conditions at both ends of each run, and
`SHA256SUMS`.
