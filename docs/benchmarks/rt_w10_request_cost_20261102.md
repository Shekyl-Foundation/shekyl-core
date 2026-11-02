# RT-W10: what a bounded request may cost on the floor device. Registration of 2026-11-02

**State of this record: registered, not yet measured.** The section
"Registered before the run" is not edited after a result is read. Results
are added under "Results". A run that is not the floor device is not data.

`RPC_CHANNEL.md` §6.3 (RT-O9.4) bounds three computations for every
connection except the host's administrator: one `calc_pow`, the number of
headers a request may ask `fill_pow_hash` for, and the span of
`get_coinbase_tx_sum`. The inherited batch caps stay as they are. Until
this run's numbers are in the handlers, a bounded caller is refused those
three; the refusal is the state before the numbers, not the policy.

## Registered before the run

**Subject.** One `compute_hash` over a cache derived once and then only
looked up, which is the production path (`CacheStore::lookup`, never
derive). Two lengths:

- `header`, 136 bytes, [`MIN_POW_BLOB_SIZE`](../../rust/shekyl-wire/src/block.rs):
  a header's PoW preimage. This is one `fill_pow_hash`, and it is the blob
  an honest `calc_pow` submits.
- `max`, 33,000,128 bytes, [`MAX_BLOCK_BLOB_SIZE`](../../rust/shekyl-wire/src/block.rs):
  the longest blob `calc_pow` will hash.

And one height of `get_coinbase_tx_sum`, in four pieces, because a
coinbase-only block does not list the transactions a full block parses:

- `block`: `ReadSnapshot::block` of one height. The call verifies the body
  against `block_info`, so the sample includes that lookup.
- `block_info`: `ReadSnapshot::block_info` of one height. `coins_through`
  does this twice per request, at the two ends of the range.
- `tx_get`: `ReadSnapshot::tx_record` of the chain's genesis miner
  transaction. A listed spend's row is larger; the lookup's cost is this
  sample, and the bytes are the parse below.
- `pruned`: `Transaction::read` of the `txs_pruned` row of the spend in
  `rust/shekyl-wire/tests/fixtures/pruned_tx_hash_parity_v1.json`. The row
  is `write_segments().pruned` of that transaction, and `read` is the call
  `fees_at` makes on it. The fixture's `pruned_hex` is the served base
  (`pruned ‖ pqc_auths`), which is a different byte string and is not
  timed.

The store is a chain of 32 coinbase-only blocks, connected through the
fixture `connect_chain` under `RuleSet::GENESIS`. Samples cycle those
heights. The pages are hot after the warmup. A cold span costs more; the
bound below is the hot cost, and it is reopened when a cold-span p99 on
this device is more than twice the hot p99 (falsify by that comparison
on a later run of this harness).

**Instrument.**

- `rust/shekyl-pow-randomx/examples/rt_w10_request_cost.rs` writes
  `hashes.tsv`.
- `shekyl-chain-store`'s ignored test `rt_w10_coinbase_span_cost` writes
  `coinbase.tsv`.
- `shekyl-wire`'s ignored test `rt_w10_listed_tx_parse` writes `parse.tsv`
  and `constants.tsv`.

Linux only. Any other host compiles the example and exits without a run,
because the clock is `CLOCK_THREAD_CPUTIME_ID` and the host is the Pi 4.
Each sample is one call. The thread-CPU read brackets the wall read, so
the CPU sample includes the two wall reads and the wall sample does not
include `clock_gettime`. Warmup is 5 calls and is not recorded. Then 100
samples of each series. A file that already exists is not overwritten.

The summary is `scripts/bench/rt_w10_summary.py`. Its tests are
`scripts/bench/test_rt_w10_summary.py`, run in CI. Percentiles are
nearest-rank, the same function as RT-P6. For 100 samples the 99th
percentile is rank 99.

**The unit a height is priced at.** The penalty limit at the full-reward
zone is `2 × MIN_BLOCK_WEIGHT` (`block_weight_full_reward_zone_bytes` is
300,000; the shipped multiple is 2). The listed weight is that limit minus
`COINBASE_RESERVE`. The number of pruned parses in one height is that
weight divided by the measured segment's length, rounded up. A higher
effective median raises the penalty limit. This span is for the zone.
Reopen it when a connected chain's penalty limit exceeds 600,000 bytes —
falsify by `block_weight_limit(effective_median) > 600_000`.

**Derivation.** *Amended 2026-11-02, before any result was read.* The
first registration took a series' cost as the greater of its wall and
thread-CPU 99th percentiles, and voided a series whose wall 99th
percentile was more than four times its thread-CPU 99th percentile. The
probe before the run found the one-minute load already above 4, with the
standing daemons busy, so a sample's wall time includes waiting for a
core. That wait is not the call. A series' cost is its thread-CPU 99th
percentile. Wall is still recorded. A series whose thread-CPU 99th
percentile is 0 is void: the clock did not see the call.

The per-request ceiling `C` is the `header` series' cost. A hash is not
divisible, and a header hash is the work `fill_pow_hash` does once.

- `calc_pow`: one hash. The blob a bounded caller may submit is `max`
  when that series' cost is at most `C`, and `header` otherwise.
- `fill_pow_hash`: `floor(C / header cost)` headers. That is 1.
- `get_coinbase_tx_sum`: a span of `H` heights costs two `block_info`
  reads plus `H` heights. One height is one `block` plus the listed-weight
  count of (`tx_get` + `pruned`). `H` is `floor((C − overhead) / per_height)`,
  or 0 when `C` does not cover the two endpoint reads. Adding the endpoint
  reads on top of `block`, which already checks `block_info`, overstates
  the request and makes the span smaller.

A 0 is a served bound of nothing: the operation does not fit in one
header-hash, so a bounded caller is still refused, and the refusal names
that the measured cost does not fit.

**Timeouts, not measured here.** hyper 1.12 has one timer for reading
request headers, and it arms again when the connection goes idle waiting
for the next request line. The header-read bound is the message-1 deadline
RT-P9 already measured, 4 seconds. The idle bound would be that plus the
quarter-core second §4.3 charges, 5 seconds, and the one timer cannot say
both. It is set to 4 seconds, the tighter of the two. Both listeners use
it. A body that drips after the headers is outside this timer; the body
limit remains the bound on those bytes.

**Gates.** A run that fails any of these is void, and the failure is recorded:

- Every sample's call succeeds. The harness asserts it.
- No series is void by the thread-CPU rule above.
- The kernel's under-voltage alarm (`rpi_volt`, `in0_lcrit_alarm`) stays
  clear.
- The pinned core spends at least 99 percent of the timed run at its top
  clock speed, by `cpufreq/stats/time_in_state` read at both ends.
  `vcgencmd get_throttled` needs root on that device and is not readable,
  as RT-P4 recorded.

**Conditions recorded at the start and the end of the timed run:**

- the governor and the SoC temperature;
- the one-minute load;
- the under-voltage alarm;
- the time-at-speed counters and the count of clock-speed changes;
- whether the standing testnet daemon is active.

The standing testnet daemon stays up. The harness is pinned to core 3
with `taskset -c 3`, at `nice -n 10` and `ionice -c3`. The compile uses
two jobs at the same nice and ionice. Nothing else on the device is
stopped or reconfigured. The checkout is a fresh tree of the commit this
registration is in, in a directory no other lane is using.

**Captures:** `docs/benchmarks/rt_w10_request_cost_20261102_captures/`,
written after the run: the four raw files, the summary, the conditions,
and `SHA256SUMS`.

## Results

Not run.
