# Upgrade Policy

Shekyl ships a change when the feature is ready, not on a calendar.
**There is no hard-fork mechanism** (RULED 2026-10-06, executed 2026-10-08,
`design/CXX_VERSION_GATES.md` §5). Block version is the constant 1.0 on
every network. A consensus change is a design document before any code,
and nothing in the tree votes one on or steps a table.

## Rationale

Much of Shekyl's roadmap depends on post-quantum cryptographic standards
(lattice-based membership proofs, PQ zero-knowledge proofs, threshold
schemes) that are still in active research and NIST standardization. Locking
to a fixed schedule (e.g. "every 6 months") would force one of two bad
outcomes:

1. **Empty releases** -- a software release with no meaningful change, adding
   coordination cost for node operators and wallet developers.
2. **Rushed features** -- shipping immature cryptographic primitives to meet
   an arbitrary deadline, risking security.

A feature-driven cadence avoids both.

## How a consensus change lands

| Aspect | Policy |
|---|---|
| **Trigger** | A consensus change is proposed when a concrete feature (or set of features) passes its readiness criteria. |
| **Readiness criteria** | Specification published, implementation reviewed, testnet validated, formal security audit completed (for cryptographic changes). |
| **Activation** | None is built. The design document comes first. There is no version-bit vote and no activation height. |
| **Communication** | Each upgrade is accompanied by a release announcement, operator migration guide, and updated documentation in `docs/`. |

## What genesis ships

| Era | Name | Description |
|---|---|---|
| Genesis | v3 | Fresh chain launch. Hybrid PQ spend authorization (Ed25519 + ML-DSA-65), TransactionV3, PQC multisig, Proof-of-Stake + mining hybrid consensus. Block version 1.0. |

## Planned work

| Era | Working Name | Status | Key Features |
|---|---|---|---|
| V4 | Lattice-only privacy | Research | Lattice-only privacy stack: a post-quantum membership-proof primitive succeeding FCMP++'s classical-curve component (the "lattice-based ring signature survey" is retired — FCMP++ is the anonymity primitive from genesis, see `POST_QUANTUM_CRYPTOGRAPHY.md`), PQ stealth address derivation, compact threshold signatures. Ships when underlying standards mature. Not a fork number. |

## Emergency consensus fixes

A critical consensus fix is a design document and a software release. There
is no fork version to hide it behind and no activation height. A post-mortem
is published in `docs/` within 30 days.

## Relationship to semantic versioning

Software releases use semantic versioning. There is no separate hard-fork
version. A release contains the consensus its design document specified, or
it does not.
