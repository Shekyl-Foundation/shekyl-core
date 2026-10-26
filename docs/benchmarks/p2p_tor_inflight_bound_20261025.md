# The Tor connector's in-flight dial bound, derived 2026-10-25

**Status: DERIVED, not yet measured.** `in_flight_bound(Tor)` = 5
(`rust/shekyl-dialer/src/fill.rs`). The floor-device measurements (below,
"To be measured") move it to Measured or reopen it. Register:
`DAEMON_RELAY_PRIVACY.md` §97, row "In-flight dial bound". Brief: the
dialer in-flight bound, revision 2 (Rick, 2026-10-25), item 6.

## What the bound is, and what it is not

The bound limits how many dials a connector has outstanding. It does not
change the rate: the owner loop still launches at most one attempt per wake,
and the wakes are still `0.5 s + U(0, 1 s)` apart (R3). Since revision 2 each
attempt is a task on the transport runtime, so a slow dial no longer stops
the loop's wakes; before it, the loop thread sat inside each dial and no
second dial could start whatever the bound said.

Every `Keep` dial is also under the connector's target: the `Keep` count
includes pending `Keep` attempts. A dial that is still running, including a
dead one waiting out its deadline, holds a target slot until it ends.

## The rule

The smallest bound whose **median** time to fill the Tor connector's target
(`MIN_PROVISIONED_OUT_PEERS` = 12) from empty is within **one stem epoch,
600 s**, when **half the draws are dead** and run to the 120 s dial deadline.
Never more than the target.

- **The time, 600 s.** The relay redraws its stem graph from the node's
  outbound edges every epoch (`min_epoch_secs` 600, `DAEMON_RELAY_PRIVACY.md`;
  the paper's "epochs on the order of 10 minutes"). The Tor target is the
  degree the embargo is provisioned at (`MIN_PROVISIONED_OUT_PEERS`, F-8b):
  below it the embargo is under-provisioned, a privacy loss. Filling within
  one epoch of a boot or a respawn means the first full epoch draws from a
  full degree.
- **The fraction, one half.** The per-session intake cap admits 24 distinct
  addresses per session per 24 h (`SESSION_INTAKE_CAP` = 2 × `DISCLOSE_COUNT`,
  D-S1). Half the draws dead is the share at which the smallest attacker's
  plants equal an honest pool at the white diversity floor (48): two sessions
  plant 2 × 24 = 48. A larger attacker plants more, and the table shows what
  that costs. The only clean observation of naturally dead draws is the
  2026-10-14 cold-contact rerun against live responders: 4 of 200 dials ran
  past 120 s and 2 were refused, about 3%, a floor, not a design point. The
  Linux acceptance runs of 2026-10-23 to 25 blocked the link on purpose and
  give no natural share.
- **The dial times.** A live draw's dial time is drawn from the 189 measured
  cold-contact sessions of the 2026-10-14 rerun (both responders; mean 20.4 s,
  median 6.4 s, p90 65.3 s, p99 112.7 s;
  `p2p_tor_gap_cold_20261014_rerunA.tsv`, `_rerunB.tsv`). Cold contact is the
  boot and respawn case: no descriptor cached, circuits built from nothing.
  The client in those runs was an x86 host; the floor device as client is
  what the measurement below checks.

## The model

`p2p_tor_inflight_bound_20261025_model.py` (run it with `python3 -I`). One
launch per wake at R3's spacing; a launch needs a free slot and kept plus
pending keeps under the target; a live draw ends at its sampled dial time
and is kept, a dead one ends at 120 s and is not. Every draw is a `Keep`:
gray holds at least the diversity floor, so rule (b) keeps. Time to fill is
when kept sessions reach 12. `p2p_tor_inflight_bound_20261025_grid.tsv`
holds 2,000 seeded runs per cell.

Median (p90) seconds to fill 12 Tor sessions from empty:

| Bound | f = 0.00 | f = 0.25 | f = 0.50 | f = 0.75 | f = 0.90 |
| --- | --- | --- | --- | --- | --- |
| 1 | 238 (396) | 709 (1137) | 1643 (2493) | 4419 (6456) | 13015 (18393) |
| 2 | 140 (226) | 393 (636) | 920 (1383) | 2403 (3545) | 6918 (9941) |
| 3 | 118 (163) | 299 (499) | 664 (1049) | 1825 (2708) | 5116 (7682) |
| 4 | 114 (139) | 263 (430) | 595 (961) | 1531 (2355) | 4281 (6559) |
| 5 | 112 (129) | 254 (397) | 522 (861) | 1364 (2164) | 3853 (6055) |
| 6 | 112 (125) | 252 (388) | 499 (855) | 1326 (2061) | 3515 (5799) |
| 8 | 112 (122) | 251 (382) | 491 (779) | 1216 (1935) | 3390 (5535) |
| 12 | 112 (122) | 251 (380) | 493 (842) | 1209 (1954) | 3269 (5375) |

**Five.** At half the draws dead, four sits on the horizon: 595 s in this
grid and 603 s in a separate 4,000-run set, inside the sampling noise of
600 s. Five clears it with margin: 522 s here, 517 s in the 4,000-run set.

**Past six the fill stops improving**, at about 490 s with half the draws
dead. The cause is the target, not the bound: a dead `Keep` holds a target
slot for its full 120 s, so with kept plus pending keeps at 12 no further
dial starts however many slots are free. A bound above six would buy almost
nothing and widen the burst the node shows its Tor.

## Fingerprinting (TSR-Q9)

Tor 0.4.9.14's own limit on concurrent client circuit construction is
`MaxClientCircuitsPending`, 32 by default (`doc/man/tor.1.txt`; `config.c`).
It counts only general and descriptor-fetch circuits
(`CIRCUIT_PURPOSE_COUNTS_TOWARDS_MAXPENDING`, `src/core/or/circuitlist.h`);
an onion connect's introduction and rendezvous circuits do not count, so the
limit barely constrains concurrent onion dials. Five concurrent onion
connects keep at most five descriptor fetches pending, under a sixth of the
allowance a stock client is built to use, and are the shape of a client with
a few onion services open at once. The bound is not set from that limit; it
is checked against it.

## Dead-onion stalling: what holding every slot costs

To hold all five Tor slots continuously an attacker needs every draw dead.
Each slot runs at most 30 dials an hour when every dial runs to 120 s.

- **On `dev` today**, a failed draw leaves gray: each dead onion is used
  once. Holding five slots for an hour consumes 5 × 30 = 150 dead onions an
  hour, 3,600 a day. At 24 admitted addresses per session per day that is
  150 attacker sessions, against 30 at bound one. The cost grows with the
  bound, and so does what it buys: the attacker must also outnumber the
  honest drawable pool by enough that every draw lands on a plant.
- **Once the gray lifecycle lands (#1189)**, a failed draw cools in place
  (2 min doubling to 1 h) instead of leaving gray. A dead onion at the cap is
  drawable once an hour and holds a slot for at most 120 s of it, so holding
  five slots continuously needs 5 × 3,600 / 120 = 150 planted onions at the
  cap, planted once: about 7 sessions within one intake span. Against that,
  every honest onion in gray is drawn at the same rate, so the planted share
  of the drawable pool, not the bound, decides how much of the time the
  slots are held.

Either way the bound does not make the node easier to stall: at bound one a
single dead draw stalled the whole connector for 120 s; at five it holds a
fifth of it.

## Floor run 1, 2026-10-25/26 (`a3b5ff4ad`, before the gray lifecycle merged)

A check of the async attempt mechanics and of this model, **not of the final
head**: the binaries predate #1189's merge into #1190, so a failed draw
leaves gray and Tor makes one attempt per test. Client: the floor device
(Pi 4), a native build, the pinned bundle (tor 0.4.9.14), stagenet, Tor
only, cold per sample. Responders: the measurement host, one light Levin
responder behind 64 onion services and 64 onion services whose target
blackholes (Tor answers 0x06 at its timeout). A probe before the series:
live onions 55 of 64 reachable, dead onions 55 of 64 answering 0x06; the
rest had not published. Rig, scripts and logs are in shekyl-dev's data
(`inflight-bound/2026-10-25-floor`).

Seconds from the Tor link becoming usable to the 12th kept Tor session:

| Case | Bound 1 median (samples) | Bound 5 median (samples) |
| --- | --- | --- |
| cold, no dead (gray 64) | 190 (5) | 258 (5) |
| cold, half dead (gray 128) | 1396 (5) | 731 (5) |
| refill after a Tor respawn | 679 (3) | 141 (3) |

At half dead the model gave 1643 s and 522 s. With 64 onions in gray, bound
5 spent most launches on `Confirm` dials (one sample: 15 keeps, 45
confirms): each slot's draw leaves gray, gray falls under the diversity
floor within a few draws, and the fill rule confirms instead of keeping.
That is the fill rule, out of scope, and it is why bound 5 is not faster
with no dead draws here. With 128 in gray the fill stayed mostly keeps and
bound 5 halved the median.

## To be measured (floor device, claimed in the usage ledger first)

- Time to fill the Tor target from empty at bound 1 and at bound 5: on a cold
  boot; after a Tor respawn; with gray seeded with a stated share of dead
  onions.
- Whether the floor device as client keeps the dial-time distribution this
  model drew from.

Below the diversity floor, which is today's testnet (14 nodes against 48),
rule (b) never keeps, so the slots past the first become `Confirm` dials
until white reaches the floor. That is the fill rule, out of scope here; the
testnet measurement will show it, and it is reported, not changed.
