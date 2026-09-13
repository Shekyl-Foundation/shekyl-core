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
- **Same Tor process as the node's client.** Point the daemon's tor-zone
  SOCKS and overlay inbound at **this** instance. `--tx-proxy` and
  `--anonymous-inbound` create the tor zone, so the default ephemeral spawn
  **yields**; do not also leave a second client
  running. `--tx-proxy` to a SocksPort that is not this relay is still
  uncovered. Omit the outbound count (the default satisfies the floor of
  12; an explicit count below 12 is refused at start). Overlay inbound on
  this process is the mixing topology for inbound — inbound on a second Tor
  is uncovered inbound.

```bash
./shekyld --tx-proxy tor,127.0.0.1:9050 \
          --anonymous-inbound <your-onion>.onion:<virt>,127.0.0.1:<local>
```

SocksPort `9050` here is the **relay process's** SOCKS, not a second Tor.
Replace with that instance's actual SocksPort. `--anonymous-inbound` is the
HiddenService this same process publishes; taking it opts into a stable onion
address. Outbound-only mix (`--tx-proxy` without inbound) yields ephemeral
inbound and leaves this node without overlay inbound.

- **Not a Shekyl setting, flag, or consensus input.** Do not look for a
  daemon option that "enables cover." Path selection stays entirely Tor's.
  Never prefer Shekyl-operated relays for Shekyl circuits.

Follow the [Tor Project's relay documentation](https://community.torproject.org/relay/)
for the relay itself. Do not copy a torrc from this page into an exit
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
