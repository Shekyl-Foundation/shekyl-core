# `SF-D3`: does Tor give each read its own circuit? 2026-10-07

`SF-D3` was reopened and ruled on 2026-10-07: every archival shard read
presents SOCKS credentials of its own, so that Tor's `IsolateSOCKSAuth`
puts it on a rendezvous circuit no other read is on
([`ARCHIVAL_SHARD_FETCH.md`](../design/ARCHIVAL_SHARD_FETCH.md) `SF-D3`).
The client's tests show what it presents. This asks Tor what it did.

## Reading

**It does.** In every run that reached the comparison (six of eight):

- **A stall retry inside one read rode the same circuit** as the attempt
  that stalled.
- **A second read of the same shard, from the same persona, rode a
  different circuit.**
- **Both were rendezvous circuits** (`HS_CLIENT_REND`), in the four runs
  whose instrument read that correctly.
- **Tor started no descriptor fetch for the new credentials**: 0 during
  the retry and 0 during the second read, in all six. The onion's
  descriptor, fetched once under other credentials while the apparatus
  came up, was reused. That is `BA-T31`'s descriptor-cache item, for
  this Tor version.

| Run | Started (UTC) | Tree | Stall retry on the same circuit | Second read on a different circuit | Descriptor fetches (retry / second read) | Test |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 14:08:09 | uncommitted, before `71b41cb6cf` | yes | yes | 0 / 0 | failed: instrument |
| 2 | 14:11:32 | `71b41cb6cf` | not reached | not reached | — | failed: the stall retry failed at the dial |
| 3 | 14:13:09 | `44b87b4216` | yes | yes | 0 / 0 | failed: instrument |
| 4 | 14:17:43 | `44b87b4216` | yes | yes | 0 / 0 | passed |
| 5 | 14:21:14 | `44b87b4216` | not reached | not reached | — | failed: the second read stalled |
| 6 | 14:25:44 | `ddef0527f5` | yes | yes | 0 / 0 | passed |
| 7 | 14:27:07 | `ddef0527f5` | yes | yes | 0 / 0 | passed |
| 8 | 14:29:10 | `ddef0527f5` | yes | yes | 0 / 0 | passed |

The raw output of all eight is
[`sfd3_read_isolation_20261007.txt`](sfd3_read_isolation_20261007.txt).

## The four runs that did not pass

None of them is a failure of isolation.

- **Runs 1 and 3: the instrument.** The test read a circuit's purpose and
  got `HS_VANGUARDS` for the second read's circuit. Tor builds circuits
  ahead and repurposes one as the rendezvous. Run 1 did not subscribe to
  the event that reports the change (`CIRC_MINOR`). Run 3 did, and then
  looked the purpose up in the oldest window first and read the stale
  value. The comparison of circuits was right both times; the purpose
  check was wrong. Fixed in `71b41cb6cf` and `ddef0527f5`.
- **Run 2: the stall retry itself failed**, at the dial, with SOCKS reply
  `0x01`. The test then made one retry where `SF-D6` allows two. Fixed in
  `44b87b4216`.
- **Run 5: the second read's first attempt stalled** on the body. Only
  the first read took its stall retries. Fixed in `ddef0527f5`.

Runs 2 and 5 are two stalls in a few dozen fetches of a 64 KB object.
That is too few to be a rate, and it is not what this run measures, but
it is the cost the ruling names: a circuit per read means a circuit
build per read. `BA-T31` measures it.

## What ran

- **The test:** `read_isolation` in `shekyl-sp-t3-spike`
  (`each_read_rides_its_own_rendezvous_circuit_and_a_stall_retry_stays_on_it`),
  built on a development box as a static binary and copied to the node.
  Runs 6 to 8 are the committed test at `ddef0527f5`.
- **The apparatus:** two managed Tor processes on one node, one serving
  one persona's onion and one the client's, with the production serving
  endpoint and the production fetch client between them over the public
  Tor network.
- **What it does:** a fetch bounded so that it stalls after the dial;
  the same header again, which is a stall retry; then a new read of the
  same shard. It reads the client Tor's `STREAM`, `CIRC`, `CIRC_MINOR`
  and `HS_DESC` events and matches each stream to its read by the SOCKS
  username, which is the read's nonce.
- **Tor:** 0.4.9.11, the pinned Tor Expert Bundle 15.0.17, launched by
  the managed launch with no `Isolate*` option set.
- **Where:** an internal x86_64 node, 2026-10-07 14:08Z to 14:30Z.

## What it does not show

- One persona, one node, one Tor version, one half hour.
- It compares circuit identifiers. It does not show the two circuits
  share no relay, and they share the client's entry guard by design.
- Circuit identifiers are compared and not recorded: the control client
  keeps them out of every log.
- The descriptor result is for a descriptor already cached. It does not
  say what a first read of a persona costs.
