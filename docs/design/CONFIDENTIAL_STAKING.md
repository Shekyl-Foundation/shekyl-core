# ⛔ SUPERSEDED — not authoritative

> **STOP. Do not implement from this path. Do not treat grep hits on
> `CONFIDENTIAL_STAKING` as current staking design.**
>
> This filename is a **redirect stub** only. The confidential-claim / Decision
> **3C** / `txin_stake_claim_v2` / entitlement staking method is **retired for
> genesis**. Agents and humans that land here via search must read the
> authoritative docs below — not the historical body.

**Historical record (audit trail only):**
[`../completed/CONFIDENTIAL_STAKING.md`](../completed/CONFIDENTIAL_STAKING.md)

**Authoritative genesis staking / reward surfaces (read these):**

| Topic | Doc |
| --- | --- |
| Transfer-shaped admission (principal ↔ `P`) | [`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) |
| Principal stake lifecycle | [`PRINCIPAL_STAKE_LIFECYCLE.md`](PRINCIPAL_STAKE_LIFECYCLE.md) |
| Reward emission (membership-only backing) | [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md), [`REWARD_EMISSION_VIN_PLAN.md`](REWARD_EMISSION_VIN_PLAN.md) |
| Bond / `P`-scan / firewall | [`ARCHIVAL_BOND_CONSTRUCTION.md`](ARCHIVAL_BOND_CONSTRUCTION.md), [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) |
| Phase map | [`WALLET_REWRITE_PLAN.md`](WALLET_REWRITE_PLAN.md), [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) |

**Do not implement:** 3C staking subtree, `txin_stake_claim_v2`, entitlement /
`tier_num` claim wire, or any construction whose only home is the historical
record above.
