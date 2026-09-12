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
`shekyld`, with a **separate lifecycle**.

- **Non-exit only.** No exit policy. "Run a relay" without that qualifier
  produces an exit and an abuse complaint. The project does not ask operators
  to handle exit abuse, and exit traffic is not what this posture needs for
  cover.
- **Separate process.** Relay throughput and uptime are remotely measurable
  (that is how Tor bandwidth authorities work). A relay inside the daemon
  process would turn the daemon's uptime into a probeable signal. You must be
  able to restart the node without restarting the relay, and the reverse.
- **Not a Shekyl setting, flag, or consensus input.** Do not look for a
  daemon option that "enables cover." Path selection stays entirely Tor's.
  Never prefer Shekyl-operated relays for Shekyl circuits.

Follow the [Tor Project's relay documentation](https://community.torproject.org/relay/)
for the relay itself. Set `ExitRelay 0` (or an equivalent reject-all exit
policy). Do not copy a torrc from this page into an exit configuration.

## What you are trading

Stated here because they are the cost of the posture, not fine print:

- Cover is **statistical**, not structural. An observer can still ask whether
  a burst was relayed or originated. Volume is what makes that question lose.
- A **new** relay carries little for days while consensus weight builds. A
  fresh install is uncovered in the window it is most identifiable as new.
- A listed relay IP advertises "runs Tor," not "runs Shekyl." If Shekyl
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
  [`USER_GUIDE.md`](USER_GUIDE.md) § Anonymity Networks
- The retained protocol carrier (encrypted zones other than Tor):
  [`design/COVER_TRAFFIC_RESTORATION.md`](design/COVER_TRAFFIC_RESTORATION.md)
