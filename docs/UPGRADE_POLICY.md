# Upgrade Policy

Shekyl uses a **feature-driven** hard fork cadence. Protocol upgrades ship
when a feature is ready -- not on a fixed calendar.

## Rationale

Much of Shekyl's roadmap depends on post-quantum cryptographic standards
(lattice-based ring signatures, PQ zero-knowledge proofs, threshold
schemes) that are still in active research and NIST standardization. Locking
to a fixed schedule (e.g. "every 6 months") would force one of two bad
outcomes:

1. **Empty forks** -- a hard fork with no meaningful changes, adding
   coordination cost for node operators and wallet developers.
2. **Rushed features** -- shipping immature cryptographic primitives to meet
   an arbitrary deadline, risking security.

A feature-driven cadence avoids both.

## How It Works

| Aspect | Policy |
|---|---|
| **Trigger** | A hard fork is proposed when a concrete feature (or set of features) passes its readiness criteria. |
| **Readiness criteria** | Specification published, implementation reviewed, testnet validated, formal security audit completed (for cryptographic changes). |
| **Signaling** | Nodes signal readiness via version bits. Activation occurs at a predetermined block height once a supermajority threshold is reached. |
| **Lead time** | Minimum 4 weeks between final release binary and activation height, giving operators time to upgrade. |
| **Communication** | Each upgrade is accompanied by a release announcement, operator migration guide, and updated documentation in `docs/`. |

## Hard Fork History

| Version | Name | Description |
|---|---|---|
| HF1 | Genesis | Fresh chain launch. Hybrid PQ spend authorization (Ed25519 + ML-DSA-65), TransactionV3, PQC multisig, Proof-of-Stake + mining hybrid consensus. |

## Planned Upgrades

| Version | Working Name | Status | Key Features |
|---|---|---|---|
| HF2 | V4 Privacy | Research | Lattice-based ring signatures, PQ stealth address derivation, compact threshold signatures. Ships when underlying standards mature. |

## Emergency Forks

If a critical vulnerability requires an immediate consensus change:

1. A patch release is published with the fix feature-gated behind a new hard
   fork version.
2. The activation height is set with the shortest safe lead time (minimum 72
   hours for critical fixes).
3. A post-mortem is published in `docs/` within 30 days.

## Relationship to Semantic Versioning

Hard fork versions (HF1, HF2, ...) are consensus versions -- they track
incompatible changes to the consensus rules. Software releases use semantic
versioning independently. A single software release may support multiple hard
fork versions during transition periods.
