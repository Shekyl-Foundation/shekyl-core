# Running a Tor relay beside Shekyl

This is the **operator** form of a ruled cover posture. The contract is
[`design/TOR_COVER_POSTURE.md`](design/TOR_COVER_POSTURE.md) (TRC). This page
does not add requirements the contract does not already carry.

**Cover on the Tor zone is an operator choice, not a protocol default.** A
Shekyl node that does not run a relay still works. It does not receive the
wire-observer resistance that a non-exit relay's traffic volume provides. The
daemon will not check, warn, or refuse on that basis — nothing inside the node
can tell whether the uplink currently provides cover.

## What to run

A **non-exit** Tor relay (middle or guard), in a **separate process** from
`shekyld`, with a **separate lifecycle** — and the node's Tor **client must
be that same Tor process**. Mixing is originated cells on the relay's existing
OR connections. A second client Tor keeps Shekyl circuits on their own
connections; a wire observer can still separate originated bursts from relay
volume.

Topology:

```text
shekyld  -- SOCKS / overlay inbound -->  operator Tor (non-exit relay)
                                      -- OR connections --> Tor network
```

Not: `shekyld` → managed ephemeral Tor (originated cells, uncovered) beside a
relay Tor whose volume never sees those cells.

- **Non-exit only.** No exit policy. "Run a relay" without that qualifier
  produces an exit and an abuse complaint. The project does not ask operators
  to handle exit abuse, and exit traffic is not what this posture needs for
  cover. Set `ExitRelay 0` (or an equivalent reject-all exit policy).
- **Separate process from `shekyld`.** Relay throughput and uptime are
  remotely measurable (that is how Tor bandwidth authorities work). A relay
  inside the daemon process would turn the daemon's uptime into a probeable
  signal. You must be able to restart the node without restarting the relay,
  and the reverse. Do not add relay flags to the daemon-spawned managed Tor.
- **Same Tor process as the node's client.** Set `tor = operator` and point
  `tor-socks` at **this** instance's SocksPort. With `tor = operator` the
  daemon starts no Tor of its own, so there is no second client. For
  inbound on this relay, publish an onion service on this process and name
  it with `tor-onion` and `tor-onion-listen` (a stable onion). Without
  `tor-onion` the node is dial-only over Tor. `tor-socks` pointing at a
  SocksPort that is not this relay is still uncovered.
  The address-hiding outbound target is not an option. It is
  `MIN_PROVISIONED_OUT_PEERS` (12): the hidden outbound sessions, those
  whose connector hides this node's address, from which the relay draws
  the hidden stem slot that this node's own transactions ride
  (`DAEMON_RELAY_PRIVACY.md` §95.3). *Records-was: "the pool an
  originated transaction rotates over"; `HOP0_OUTBOUND_TARGET`, 4.*
  The D-5 receiver's outbound count stayed 0 because its one dial closed
  before the handshake. Overlay inbound on this process is the mixing
  topology for inbound — inbound on a second Tor is uncovered inbound.

```bash
./shekyld --tor operator --tor-socks 127.0.0.1:9050 \
          --tor-onion <your-onion>.onion:11021 --tor-onion-listen 127.0.0.1:<local>
```

SocksPort `9050` here is the **relay process's** SOCKS, not a second Tor.
Replace it with that instance's actual SocksPort. `tor-onion` is the
HiddenService this same process publishes, with the virtual port peers dial
(the network's P2P port, 11021 on mainnet, is the usual choice), and
`tor-onion-listen` is the local endpoint its `HiddenServicePort` forwards to.

- **Not a Shekyl setting, flag, or consensus input.** Do not look for a
  daemon option that "enables cover." Path selection stays entirely Tor's.
  Never prefer Shekyl-operated relays for Shekyl circuits.

Follow the [Tor Project's relay documentation](https://community.torproject.org/relay/)
for the relay itself.

**Set `MaxMemInQueues` by hand on a small host.** Unset, Tor sizes it at
three quarters of physical memory and does not know `shekyld` shares the
machine. On a 4 GB host with no swap, a relay at 1 MB/s beside the daemon
was killed by the kernel twice in one evening, before Tor's own limit was
reached: [`benchmarks/trc1_carried_traffic_20261012.md`](benchmarks/trc1_carried_traffic_20261012.md),
interim result 1. That record's Amendment 1 runs the relay at 512 MB and
reports what the cap changed. Do not copy a torrc from this page into an exit
configuration. Wallet Tor stays a separate instance (PWD-E9); this page is
the daemon overlay posture.

## What you are trading

Stated here because they are the cost of the posture, not fine print:

- Cover is **statistical**, not structural. An observer can still ask whether
  a burst was relayed or originated. Volume is what makes that question lose.
- A **new** relay carries little for days while consensus weight builds. A
  fresh install is uncovered in the window it is most identifiable as new.
- A listed relay IP advertises "runs Tor," not "runs Shekyl." Publishing
  overlay inbound from that same process is how inbound mixes; it is a
  consequence of the topology, not a protocol requirement. If Shekyl
  operators adopt relaying disproportionately, that population correlation
  can strengthen over time. That is why this is a recommendation, never a
  requirement.
- The node cannot verify that cover is present. A low-weight relay at an idle
  hour may carry almost nothing.

## Reciprocity

Shekyl consumes Tor capacity (onion services, overlay P2P, archival fetches).
The project's commitment is to contribute more relay capacity than the
network consumes, and to make that contribution legible — Foundation-operated
non-exit relays in a named consensus family, plus operator relays such as
this one. Sizing of that offset is a Foundation measurement, not an operator
quota.

## See also

- The ruling: [`design/TOR_COVER_POSTURE.md`](design/TOR_COVER_POSTURE.md)
- Tor / I2P P2P usage: [`ANONYMITY_NETWORKS.md`](ANONYMITY_NETWORKS.md),
  [`USER_GUIDE.md`](USER_GUIDE.md) § Anonymity Networks — those pages are not
  the cover bind; copy the flags above, not a second-Tor example.
- The retained protocol carrier (encrypted zones other than Tor):
  [`design/COVER_TRAFFIC_RESTORATION.md`](design/COVER_TRAFFIC_RESTORATION.md)
