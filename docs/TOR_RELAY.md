# Running a Tor relay beside Shekyl

This is the **operator** form of
[`design/TOR_COVER_POSTURE.md`](design/TOR_COVER_POSTURE.md) (TRC). This page
does not add requirements the contract does not already carry.

**A relay gives Tor capacity back. It does not hide your node's sends.**
A measurement of a node using its own relay's Tor found no cover:
- the node's own circuits go through its entry-guard connections, which
  carry about half a percent of the relay's traffic;
- an observer of those connections picks out the node's own transaction
  sends.

No Tor configuration hides when a node sends today, with a relay or
without one. The protocol's cover traffic is being redesigned. Run a relay
to contribute to the Tor network (see Reciprocity), not to protect the
node.

## What to run

A **non-exit** Tor relay (middle or guard), in a **separate process** from
`shekyld`, with a **separate lifecycle**. Pointing the node at the relay's
Tor gives it no cover, so the bind below is optional, not a requirement.

- **Non-exit only.** No exit policy. "Run a relay" without that qualifier
  produces an exit and an abuse complaint. The project does not ask operators
  to handle exit abuse, and the contribution does not need exit traffic.
  Set `ExitRelay 0` (or an equivalent reject-all exit policy).
- **Separate process from `shekyld`.** Relay throughput and uptime are
  remotely measurable (that is how Tor bandwidth authorities work). A relay
  inside the daemon process would turn the daemon's uptime into a probeable
  signal. You must be able to restart the node without restarting the relay,
  and the reverse. Do not add relay flags to the daemon-spawned managed Tor.
- **Optional: the node on the relay's Tor.** This bind gives no cover. If
  you use it anyway, set `tor = operator` and point `tor-socks` at **this**
  instance's SocksPort. With `tor = operator` the daemon starts no Tor of
  its own. For inbound on this relay, publish an onion service on this
  process and name it with `tor-onion` and `tor-onion-listen` (a stable
  onion). Without `tor-onion` the node is dial-only over Tor.
  The address-hiding outbound target is not an option. It is
  `MIN_PROVISIONED_OUT_PEERS` (12): the hidden outbound sessions, those
  whose connector hides this node's address, from which the relay draws
  the hidden stem slot that this node's own transactions ride
  (`DAEMON_RELAY_PRIVACY.md` §95.3). *Records-was: "the pool an
  originated transaction rotates over"; `HOP0_OUTBOUND_TARGET`, 4.*
  The D-5 receiver's outbound count stayed 0 because its one dial closed
  before the handshake.

```bash
./shekyld --tor operator --tor-socks 127.0.0.1:9050 \
          --tor-onion <your-onion>.onion:11021 --tor-onion-listen 127.0.0.1:<local>
```

SocksPort `9050` here is the **relay process's** SOCKS, not a second Tor.
Replace it with that instance's actual SocksPort. `tor-onion` is the
HiddenService this same process publishes, with the virtual port peers dial
(the network's P2P port, 11021 on mainnet, is the usual choice), and
`tor-onion-listen` is the local endpoint its `HiddenServicePort` forwards to.

- **Not a Shekyl setting, flag, or consensus input.** Path selection stays
  entirely Tor's.
  Never prefer Shekyl-operated relays for Shekyl circuits.

Follow the [Tor Project's relay documentation](https://community.torproject.org/relay/)
for the relay itself.

**Size the host for the relay and the daemon together; `MaxMemInQueues`
alone does not.** Unset, Tor sizes that option at three quarters of
physical memory and does not know `shekyld` shares the machine. On a 4 GB
host with no swap, a relay at 1 MB/s beside the daemon was killed by the
kernel twice in one evening before Tor's own limit was reached. With
`MaxMemInQueues 512 MBytes` the kernel killed it 67 times inside the
measurement, all of them in one surge, and 16 times more after the
horizon, while the cap was killing circuits. The cap bounds Tor's
queues. Across that capped run the process held 0.7 to 1.6 GiB, and the
daemon held up to 1.4 GiB:
[`benchmarks/trc1_carried_traffic_20261012.md`](benchmarks/trc1_carried_traffic_20261012.md),
final result 6. That is one host's record, not a sizing rule. Set the cap
by hand anyway, so Tor gives up circuits before the kernel takes the
process. Do not copy a torrc from this page into an exit
configuration. Wallet Tor stays a separate instance (PWD-E9); this page is
the daemon overlay posture.

## What you are trading

- **A listed relay IP advertises "runs Tor,"** not "runs Shekyl." If Shekyl
  operators adopt relaying disproportionately, that population correlation
  can strengthen over time. That is why this is a recommendation, never a
  requirement.
- **A relay on the node's host** puts that host's IP in a public
  directory. A relay on another host keeps the two apart.
- **A new relay carries little for days** while consensus weight builds,
  so its contribution ramps up.

## Reciprocity

Shekyl consumes Tor capacity (onion services, overlay P2P, archival fetches).
The project's commitment is to contribute more relay capacity than the
network consumes, and to make that contribution legible — Foundation-operated
non-exit relays in a named consensus family, plus operator relays such as
this one. Sizing of that offset is a Foundation measurement, not an operator
quota.

## See also

- The posture and the measurement that reopened it:
  [`design/TOR_COVER_POSTURE.md`](design/TOR_COVER_POSTURE.md)
- Tor / I2P P2P usage: [`ANONYMITY_NETWORKS.md`](ANONYMITY_NETWORKS.md),
  [`USER_GUIDE.md`](USER_GUIDE.md) § Anonymity Networks
- The protocol carrier:
  [`design/COVER_TRAFFIC_RESTORATION.md`](design/COVER_TRAFFIC_RESTORATION.md)
