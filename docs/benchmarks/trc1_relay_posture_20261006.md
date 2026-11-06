# TRC-1 relay posture, step 1 — 2026-10-06

Falsifier step 1 of `docs/design/TOR_COVER_POSTURE.md` §8: the operator
topology is running. Step 2, carried traffic across hours and consensus
weights, has not started.

The subject is one operator non-exit relay at 1 MB/s average and 2 MB/s
burst, and the daemon's Tor client is that same process. The daemon is
`v3.1.0-alpha.9-release`. Managed ephemeral Tor is off. The relay's
lifecycle is separate from the daemon, so a daemon upgrade does not
restart it. Identity, the onion, and the port layout are in
`shekyl-dev`, `infrastructure/trc1/`.

## The running binary

The process is Tor Project `tor` 0.4.9.13. The directory authorities do
not call that version obsolete. The relay's first start, at 01:46Z, was
Ubuntu's `tor` 0.4.9.11, which they do. The identity keys were kept when
the binary was replaced at 03:23Z.

## Checks

On the 03:23Z start the process reached bootstrap 100%, Tor's self-test
reported the ORPort reachable, and the log carries no obsolete notice.

| Directory lookup | Result |
| --- | --- |
| 01:46Z | No relay. The process was Ubuntu's `tor` 0.4.9.11. That absence is not the weight of 0.4.9.13. |
| Published 2026-10-06 14:00Z | Listed and running. Version 0.4.9.13, recommended. Flags do not include Exit. Consensus weight 1, marked measured. Observed bandwidth 0. |

The directory first saw this relay at 02:00Z, during the 0.4.9.11
window. The 14:00Z row is the figure whose version field is 0.4.9.13.
Weight 1 and an observed bandwidth of 0 are that lookup. They are not a
measurement of carried traffic.
