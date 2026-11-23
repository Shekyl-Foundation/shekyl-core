# Archival bond sizing: Round 0 note for investigation

**Status: PARKED (Rick, 2026-11-22).** Registered on Rick's direction so it is not lost. No change is proposed. It is taken up only after the economics sim finishes its current series: EUP-4 prep, EUP-4, and the stakers' emission share first look. The right bond depends on what stakers are paid. No brief, measurement or model starts from this note until Rick reopens it, and nothing here is built. Read against `dev` at `27a832cf81`. The economy figures are from #1476's derived table (`economies_table.csv`) at `920594b8e4`, its A-honest rows at N = 90 on the baseline; section 5 restates every figure it uses, so the note does not depend on that table.

**Identifier family:** `ABS-`, registered at birth (rule 94) in [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2. No `ABS-` identifier is minted yet.

## 1. Rick's question

The bond to hold an archival shard is small next to what a seat earns, and a slash is hard to incur. Should the bond be a base plus, or times, something tied to the shard's rarity, so a slash is more of a loss?

## 2. What the code does

| Fact | Where |
| --- | --- |
| The bond is 0.75 SKL per shard held, the same for every shard. A shard is 3 MB, so 250 SKL per GB. | `bond_floor.rs`; `archival_bond_floor_atomic` 750000000; `archival_shard_length_bytes` 3000000 |
| The bond must equal the floor exactly. Nobody can post more. | `bond_post.rs`, `bond_connect.rs` |
| A bond's holdings are fixed for its life. To change them an archivist posts a new persona and releases the old one. | `ARCHIVAL_BOND_GATE4.md` §4.4 |
| A clean release returns the whole bond after a 2-epoch cooldown. An archivist who is never slashed loses nothing but the use of the coins. | gate-4 §4.3; `release_cooldown_epochs` 2 |
| A slash removes one shard from the bond and burns that shard's 0.75 SKL. Rewards earned before the slash stay claimable. | gate-4 §4.2, §4.5 |
| An epoch is 10,000 blocks, about 14 days. Each epoch a pair gets 3 counted draws; 2 passes settle it Served, fewer settle it Missed. Fewer than 3 issued draws is not an observation. | `shekyl-types/src/archival/settlement.rs` |
| A slash needs 11 Missed in the last 13 observed epochs. The fastest slash is about five months, and serving 3 epochs in 13 avoids it for good. | `failure_window.rs`; `archival_failure_window_m` 11, `_n` 13 |
| The epoch's budget is the whole staker inflow: the stakers' emission plus their part of the burned fees. | `ARCHIVAL_BUDGET_SCHEDULE.md` §1 |
| A shard's work is `g(age) / r_market`: more for older shards, split by the number of holders. Rarity is already in the reward. | `reward_arithmetic.rs::scarcity_micro`; age weight 2000 milli |
| `r_market` counts only holders with serve credit. A bond that does not serve earns nothing and dilutes nobody. | `consensus_state.rs::as_of_e_served_work`; test `bonded_without_serve_credit_not_in_r_market` |
| The operator's selection list ranks shards by the bonded count and shows the served count beside it. | `shard_coverage.rs`; `ARCHIVAL_SHARD_SELECTION_LIST.md` SL-D4, SL-D5 |

## 3. The phantom, withdrawn

Claude first framed the exposure as a "phantom": someone who bonds a shard and serves nothing. Rick asked what the point of that would be. On reading the code, there is none.

- It earns nothing and takes nothing from honest holders, because payment is on served work.
- Its one effect is on the selection list's hint, and SL-D5 already ruled on that: bonding without serving degrades the hint and enriches anyone who reads the served column. The attack defeats itself as long as payment stays on the serve gate.

The phantom is not the adversary to size the bond against.

## 4. What the bond is for, in the design's words

`V3_STAKER_ARCHIVAL.md` calls the per-shard bond the keystone: it is the Sybil cost. One operator can run many personas, and personas cannot be linked, so the design makes capital the scarce input for a seat. Gate-4 §1.3 says the same: the bond makes each counted replica cost something, to protect `r_market`.

The seat that matters is therefore one that does serve. An operator with one physical copy of a shard can seat several personas on it. Each answers its draws, each counts in `r_market`, and each takes a share. The bond is the only price on the extra seats. The design's own text says the rate must be "high enough for Sybil-deterrence" and "not a knob set by eye".

## 5. The finding: the bond was never set against the real purse

The 0.75 comes from the staking sim's dimensionless `bond_rate* = 0.75`. `FOUNDATION_GENESIS_IDENTITY_SET.md` §9.3 maps it to coins by declaring one sim capital unit equal to 1 SKL, with a reference actor holding 20 units. Nothing ties that scale to what the chain pays stakers.

What a seat earns against its bond (Claude's arithmetic from the table, N = 90, baseline, as built; age weighting ignored; 100 holders a shard is an assumption for illustration):

| | Year 1 | Year 10 | Year 30 | Year 30, share held at 15 % |
| --- | --- | --- | --- | --- |
| Stakers' pay per shard, SKL a year | about 760 | 15.7 | 0.19 | about 4.2 |
| One seat of 100, SKL a year | about 7.6 | 0.16 | 0.002 | 0.04 |
| As a fraction of the 0.75 SKL bond | about 10 times | 21 % | 0.25 % | 6 % |
| Holders a shard at which a seat returns 10 % a year on its bond | about 10,000 | about 210 | 2 to 3 | about 56 |

Year 1 is derived from the emission and the archive's growth rate, not read from a table column.

Two readings follow.

1. **Early, capital does not bind.** A seat repays its bond in weeks. Extra seats are limited only by the cost of answering draws and posting the bond. This is Rick's "pretty good for a 1 SKL investment".
2. **Late, the same bond is heavy.** The number of holders a shard can support falls from thousands to two or three as built. A flat bond lets replication follow the purse down.

## 6. Candidate shapes

| # | Shape | First reading |
| --- | --- | --- |
| 1 | Flat, re-pinned against the real purse | Fixes the scale once. Keeps the swing in section 5. |
| 2 | Indexed to the shard's pay: `k` epochs of what the shard as a whole earned at the last closed epoch, fixed at posting | Follows emission down. Age comes with it. To first order the supportable holders per shard is then set by `k` alone, in every year and for every shard. Needs testing. |
| 3 | Base times an age multiplier (Rick's suggestion, with age as the rarity measure) | Covers age but not the purse's decline. |
| 4 | Floor plus index: the larger of a flat floor and shape 2 | Shape 2 with a bootstrap value for the first epochs, when nothing has yet been paid. This is the "base plus" form. |
| 5 | Leave the bond; add loss at slash (forfeit recent rewards, or a wait before a new seat) | Raises the cost of abandonment without more locked capital. Does nothing for the extra-seat question. |

## 7. Wargame notes

- **Index to the shard's total pay, not the seat's.** A bond that rises as holders fall would deter the first holders of a thin shard, which is the wrong direction.
- **Age, not holder count, as any explicit rarity term.** Holder counts can be moved by seating personas. Age cannot.
- **No per-persona base.** Personas are free and rotation is the designed path, so a base charge taxes small holders and rotation.
- **The reference must be consensus state.** The budget and `Σwork` of a closed epoch both are. A large holder can move `Σwork` a little; measure how much.
- **A larger bond scales the loss from a provider-level outage,** which slashes every shard an operator holds at once.
- **Capital-poor, storage-rich archivists.** Any rise in the bond excludes some of them. The design names this bind.
- **Bond amounts are public scalars.** An indexed amount is computable from the posting epoch and the shard, so it reveals nothing the holdings do not.

## 8. Open, not yet read

1. What bounds the number of bonded pairs when seats are cheap? The selection-list note says the challenge math is sized near 324,000 drawable pairs. At 0.42 GB a day the archive passes 50,000 shards in year 1.
2. What happens to pairs that cannot be issued 3 draws in an epoch because blocks are full of draws? They settle as not observed. Whether they are then paid needs reading.
3. The cost of serving one seat for one epoch, in bytes sent and fees. This is the real limit on extra seats today.
4. Whether `bond_duration(age)` is live in production or awaiting deletion (gate-4 §4.4 lists it as "delete-or-keep, not ruled").
5. Whether the staking sim's coupling half, on the economy's real purse, already reports a seat's return on its bond.

## 9. Proposed investigation, when unparked

Run the staking sim on the economy's real purse and report, by year: holders per shard, pairs in total, and the return on a seat's bond, for shapes 1, 2 and 4. Predictions first. Any change to the bond is consensus, so it comes to Rick before anything is cut.
