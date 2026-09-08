# Shekyl documentation

This is the front door. Read it before grepping `docs/design/`.

## Who wins

When two documents disagree:

1. **Code on `dev`**
2. **Living contract** (protocol / wire / crypto spec)
3. **[IMPLEMENTATION_INDEX.md](design/IMPLEMENTATION_INDEX.md)** (identifier map, not design detail)
4. **Plan-doc status table**
5. **[FOLLOWUPS.md](FOLLOWUPS.md)** (one-line residue queue)

Fix the loser in a scoped change. Do not drive-by-update every surface that mentions the topic.

## Reading order

1. Mission: [`.cursor/rules/00-mission.mdc`](../.cursor/rules/00-mission.mdc)
2. This file, then the living contracts below
3. [IMPLEMENTATION_INDEX.md](design/IMPLEMENTATION_INDEX.md) — “what does this identifier mean, and has it landed?”
4. [FOLLOWUPS.md](FOLLOWUPS.md) — open residue only
5. [V3_WALLET_DECISION_LOG.md](V3_WALLET_DECISION_LOG.md) — binding *why*, append-only

Do **not** implement from `docs/completed/`. Those are closed plans, preflights, and retired records. Git history is the archive.

## Document classes

| Class | Lives in | Banner | Implement from? |
| --- | --- | --- | --- |
| Contract of record | `docs/` or `docs/design/` | `Status: LIVING CONTRACT` + last-verified date | Yes |
| Active plan | `docs/design/` | `Status: OPEN` + round | Yes, for the work it still owns |
| Closed plan / preflight / retired concept | `docs/completed/` | `Status: CLOSED-as-record` or `RETIRED` | No |
| Operator / user | `docs/` root | no round archaeology | Yes (product behaviour) |
| Ledger | one file each | not a queue | FOLLOWUPS (short), CHANGELOG (user-facing), decision log |
| Map | `IMPLEMENTATION_INDEX.md` | identifier + owning doc + one-line status | Map only |

Lifecycle rule: [`.cursor/rules/95-documentation-lifecycle.mdc`](../.cursor/rules/95-documentation-lifecycle.mdc). Completing a plan includes archive-or-contract in the same change. Structural gates live in [`.github/workflows/docs-gates.yml`](../.github/workflows/docs-gates.yml) (named `doc-links.yml` until P0b, 2026-09-05 — it had outgrown link checking).

## Work-item targets

There is no V3.1 / V3.2 / V3.x release train. Allowed FOLLOWUPS / plan `Target:` values:

- **pre-genesis** — default. If it should exist at launch, it lands before genesis.
- **post-genesis** — exceptional deferral with a named blocker. This list stays tiny.
- **V4** — lattice-only transition, 2–5 years, gated on NIST (or successor) actually approving primitives such as lattice threshold signatures.

`V3.1` in a protocol *title* (for example the equal-participants PQC multisig spec) is a historical name, not a target.

## Living contracts (start here)

| Topic | Doc |
| --- | --- |
| Post-quantum spend / ownership | [POST_QUANTUM_CRYPTOGRAPHY.md](POST_QUANTUM_CRYPTOGRAPHY.md) |
| FCMP++ membership | [FCMP_PLUS_PLUS.md](FCMP_PLUS_PLUS.md) |
| Economics / denomination | [DESIGN_CONCEPTS.md](DESIGN_CONCEPTS.md) |
| Genesis allocations | [GENESIS_TRANSPARENCY.md](GENESIS_TRANSPARENCY.md), [GENESIS_ALLOCATIONS.md](GENESIS_ALLOCATIONS.md) |
| Archival staking (mechanism) | [V3_STAKER_ARCHIVAL.md](V3_STAKER_ARCHIVAL.md) |
| Archival wallet FSM | [design/PHASE_2B_FSM_RETOOL.md](design/PHASE_2B_FSM_RETOOL.md) |
| Principal stake lifecycle | [design/PRINCIPAL_STAKE_LIFECYCLE.md](design/PRINCIPAL_STAKE_LIFECYCLE.md) |
| Reward emission | [design/REWARD_EMISSION_LEG.md](design/REWARD_EMISSION_LEG.md) |
| Address format (operator) | [USER_GUIDE.md](USER_GUIDE.md); message-signing / address v2: [design/WALLET_MESSAGE_SIGNING.md](design/WALLET_MESSAGE_SIGNING.md) |
| Staker operations | [STAKER_OPERATOR_GUIDE.md](STAKER_OPERATOR_GUIDE.md) |

Identifier collisions (Phase 2 vs Bond-PR 2, and the rest): [design/IMPLEMENTATION_INDEX.md](design/IMPLEMENTATION_INDEX.md).

## Operator and build

- [INSTALLATION_GUIDE.md](INSTALLATION_GUIDE.md)
- [USER_GUIDE.md](USER_GUIDE.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SIGNING.md](SIGNING.md), [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md)

Seeds / DNS / testnet ops live in the **shekyl-dev** sibling repository, not here.
