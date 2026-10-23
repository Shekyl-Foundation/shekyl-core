# CompleteTree support draws — Round 0

**Status: RULED 2026-10-22.** Rick ruled §12, all five as recommended.
Ground: `dev` at `11f8fd1f0`. §4 stays **TABLED** until after EUP-4:
whether a hole that 2-of-3 cannot see needs more. The row is in
`docs/FOLLOWUPS.md`.

A complete tree is a support role. It is challenged and slashable. Its
draws are not the economy's. This round names the stream, the schedule,
the bundle changes, and what stays. It does not cut code.

## 1. What the pin does

Read at `11f8fd1f0`.

`emit` (`rust/shekyl-chain-rules/src/archival/drawable.rs`, the
`Holdings::CompleteTree` arm) expands one complete-tree record into one
pair per shard `0..final_count`, and pushes the persona's receipt key
when that expansion added pairs. Both derivations of `D` call this
function. Pin 2 of `ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md` §7.4 is that
expansion, over the closed-and-final prefix at `h_open(E)`.

`draw_target` (`rust/shekyl-archival-retention/src/secret_draw.rs`)
sets the economy's block target from the set size `D`, the horizon `H`,
the shortfall `u`, and `SEB`. The cap is `9 · D · H`
(`COUNT_CAP_BASE_MULTIPLE`). Unanswered economy draws feed `u`, and `u`
feeds the next target. One complete tree therefore adds `final_count`
pairs to `D`, about `final_count / SEB` economy draws a block, and its
unanswered draws top the economy's count up, up to nine times the base.
`bond_floor_of` returns a single `ARCHIVAL_BOND_FLOOR_ATOMIC` for
`HoldingsKind::CompleteTree`.

`freeze_complete_trees` (`close.rs`) and `market_member_at_epoch`
(`consensus_state.rs`) keep a credited complete tree out of `R_market`
and `Σwork`. On rewards it is not a Sybil route. The drawable set is
the route.

A draw is an index `j` below `BlockDraws.count` at height `h`
(`shekyl-types` `settlement.rs`). The pass bitmap is exactly `count(h)`
bits (`bundle.rs` `PassBitmap`). The receipt signs
`nonce ‖ anchor_height ‖ anchor_hash ‖ shard_id ‖ delivery_digest`,
112 bytes (`pass_countersignature_message`,
`PASS_COUNTERSIGNATURE_MESSAGE_LEN`). The request header inside that is
72 bytes and has no stream tag.

## 2. Schedule — RULED 2026-10-22

**Recommended `c` = 10.** §3 derives it. It is the smallest count that
keeps the chance of fewer than three issued draws under `10^{-6}` when
one scheduled block in ten is never revealed. The PR does not retune
`FAILURE_WINDOW_M` / `N`, `COUNTED_DRAWS`, or `SERVE_THRESHOLD_PASSES`.

Constants at this pin: `SEB = 10_000`, `W₂ = 500`
(`CHALLENGE_RESPONSE_BLOCKS`). The usable span is `SEB − W₂ = 9_500`,
the late bound `draw_horizon` already uses. Block time is
`T_SECONDS = 120`.

**The schedule.** Persona `P` has a phase

```text
offset(P) = LE64(P_id[0..8]) mod (SEB − W₂)
```

Draw `i` of the `c` (`i` from 0) is issued at epoch-relative height

```text
r_i = (offset(P) + floor(i · (SEB − W₂) / c)) mod (SEB − W₂)
```

One draw per tree per chosen block. At `c = 10` the spacing is 950
blocks. Every `r_i` is in `0 .. 9_500`, so the response window ends at
or before block 9,999, inside the epoch. The phase is what keeps ten
trees from stacking their records on the same ten blocks: two personas
share a block only when their offsets land on it.

The heights are public. The shard a draw selects is not.

The cSHAKE input is `seed ‖ block_hash(h) ‖ persona ‖ j_le[4] ‖
attempt_le[4]`, customization `shekyl/archival-support-draw-v1`.
`persona` is required so two trees on one block do not share a shard.
The seed and the block hash are the economy draw's inputs; the label
and the persona are what separate the streams. Selection reuses
`select_draw`'s zone and the 256th-attempt cap. The set size is
`final_count`, not `|D|`. The first in-zone candidate is accepted.
The economy's 16 : 1 short weight is not applied: a shard index has no
economy shortfall.

**Unissued carry.** A support draw the producer did not issue moves to
the next block that can issue it. The counter for one tree is capped
at `c`: an epoch that opens while `c` are already unissued adds
nothing. The tree is never owed more than `c`, so a stall does not
stack epochs and there is no top-up multiple. While the producer is
keeping up, a skipped block is filled later in the same epoch and the
tree is issued `c`. An issued draw that goes unanswered does not
return to this counter. It is one observation in §3.

## 3. Settlement — what the PR builds

A complete tree uses the slash mechanics every pair already uses. No
epoch rule of its own. Read at this pin:
`settle_pair` (`settlement_select.rs`) and `SettlementRow::settle`
(`shekyl-types` `settlement.rs`).

1. The unit's issued draws in the epoch are taken in `(h, j)` order.
2. Fewer than `COUNTED_DRAWS` (3) issued: the outcome is
   NonObservation, which is not a miss. No draws issued: no row, and
   absence is not a miss.
3. Otherwise `select_counted` picks three of the issued draws,
   uniformly without replacement, from the beacon
   `shekyl/archival-settlement-select-v1`. A pass on a draw that was
   not selected does not count.
4. The outcome is Served at `SERVE_THRESHOLD_PASSES` (2) or more passes
   of those three, and Missed at 1 or 0.
5. `failure_window_slashable` slashes at 11 Missed observations in a
   window of 13. It passes over NonObservation and over an absent row.

A slash demotes through `SlashedHolding::CompleteTree`. `unslashed`
stays the undo.

**Each support draw selects its own shard**, uniformly from
`0..final_count` (Rick, 2026-10-22). The settlement row is **per tree
per epoch**, not per `(tree, shard)`. It gathers every support draw
issued to that tree in the epoch, whichever shards they hit, and
`select_counted` picks three of that list. With draws spread over
`final_count` shards, a row keyed `(tree, shard)` would almost never
reach three issued draws, every row would settle NonObservation, and
the tree could not be slashed. That key is rejected.

`select_counted`'s beacon preimage includes a shard. The support call
passes `ShardId::from_raw(u64::MAX)`, which is not a closed shard, so
the preimage does not alias an economy pair. The function is otherwise
unchanged. The three positions it returns are almost always three
different shards, because the list's members were drawn independently.

**Store layout.** Two new tables. `SCHEMA_VERSION` (30 at this pin)
bumps because both are stored bytes.

| Table | Key | Value |
| --- | --- | --- |
| `archival_support_issued` | `(epoch, persona, h, j)`: `BE64(epoch) ‖ P_id ‖ BE64(h) ‖ BE32(j)` | the selected shard, `BE64`, and the pass bit. Epoch-major so one tree's epoch is one range, in `(h, j)` order |
| `archival_support_settlement` | `(persona, epoch)`: `P_id ‖ BE64(epoch)` | a `SettlementRow`, the same 3 bytes (`outcome`, `passes`, `issued`) |

The economy's `archival_settlement` key stays `(persona, shard, epoch)`.
Support rows do not go in it.

**`c`.** Only three issued draws are counted. `c` exists so the epoch
still has three after some producers file nothing. Model, stated
because it is not a measurement: each scheduled block is revealed
independently, and the non-filing rate is `α = 0.10` (one block in ten
has no admitted bundle). Issued count is `Binomial(c, 0.9)`. The bound
is `P(issued < 3) ≤ 10^{-6}`.

| `c` | `P(issued < 3)` at `α = 0.10` |
| --- | --- |
| 8 | `2.3 × 10^{-5}` |
| 9 | `3.0 × 10^{-6}` |
| 10 | `3.7 × 10^{-7}` |

**`c` = 10** is the smallest integer under that bound. At `α = 0.20`
the same bound needs `c = 14`. The 0.10 rate is the one this round
recommends; the 0.20 row is what a worse filing rate would cost.

A draw the producer never revealed is not a miss (`SCS-P15`). It
returns to the unissued counter. An admitted bundle with the support
bit clear is a miss on that draw, and it counts only if `select_counted`
picks it.

The producer uses `CHALLENGE_READS = 3` inside `W₂`, the same retry as
an economy draw. A draw is unanswered when the admitted bundle has no
receipt after those reads.

A passed support draw writes no serve credit, adds nothing to
`Σwork`, and does not change `R_market`.

## 4. What the 2-of-3 cannot see — TABLED

**TABLED 2026-10-22.** Not built. The row is in `docs/FOLLOWUPS.md`,
owned by this document, triggered after EUP-4.

Each issued draw fails independently with probability `x` (a missing
fraction, or a hostile producer's share of the blocks). `settle_pair`
then misses the epoch with probability `3x² − 2x³`: zero or one pass
among the three the beacon selected. Eleven such epochs in a window of
13 are the slash.

| `x` | `P(epoch Missed)` | `P(slash in one 13-epoch window)` |
| --- | --- | --- |
| 0.01 | `3.0 × 10^{-4}` | `1.3 × 10^{-37}` |
| 0.25 | 0.156 | `7.8 × 10^{-8}` |
| 1/3 | 0.259 | `1.6 × 10^{-5}` |
| 0.60 | 0.648 | 0.11 |
| 0.80 | 0.896 | 0.85 |
| 1 (outage) | 1 | 1, at 11 epochs |

A hole small enough that the counted three usually pass is invisible.
At `x = 0.25`, `P(slash)` is about `10^{-7}`. A dead tree (`x = 1`)
and a grossly hollow one (`x = 0.80`) are what this window slashes.
Whether the support role needs to see a smaller hole is the question
after EUP-4. No new slash rule is in this round.

## 5. Bundle and verifier — consensus, named

A draw is `(stream, h, j)`. `stream` is economy or support. `j` is the
index within that stream at `h`.

The signed transcript gains one stream byte. Today it is
`nonce ‖ anchor_height ‖ anchor_hash ‖ shard_id ‖ delivery_digest`,
112 bytes (`pass_countersignature_message`). It becomes
`stream[1] ‖` those fields, 113 bytes.
`PASS_COUNTERSIGNATURE_MESSAGE_LEN` moves with it. Both scheme 1 and
scheme 3 sign that transcript. A signature over economy `(h, j)` does
not verify as support `(h, j)`: the byte differs, and the nonce was
derived under a different label. The red edit is dropping the stream
byte from the transcript. The request carries the byte because `P`
signs the bytes it sees. The role is identifiable as a full-archive
server; the byte does not add a second identity.

The selection label is `shekyl/archival-support-draw-v1`, registered in
`CRYPTO_DOMAIN_REGISTRY.tsv` in the implementation PR, next to the
`shekyl/archival-draw-v1` row.

**Kept bundle.** `PassBitmap` stays the economy bitmap: exactly
`BlockDraws.count` bits, bit `j` economy draw `j`. A second bitmap,
same bit order, has exactly the block's support count bits. Support
records follow the economy records, each still `BUNDLE_RECORD_LEN`
(1,397) wide. The verifier's step that derives `(P, s)` from economy
`D` runs only on the economy bitmap. A new step derives
`(persona, shard)` for support bit `j` from the support schedule and
`shekyl/archival-support-draw-v1` over `final_count`, and checks the
receipt under the support nonce. That step writes a support
observation for an admitted bundle. A missing bundle writes nothing
and returns the draw to the unissued counter. The step does not write
serve credit and it does not touch `issued_short`.

**Who files.** The challenger is the producer of block `h`, the same
party that draws and reads the economy's pairs (spec §1, steps 1–4).
Producing the block is the obligation. There is no separate fee for
dialling a complete tree. Any later miner includes the bundle, as for
the economy. A producer who files nothing leaves the support draws
unissued. That is not a miss, so an absent challenger cannot slash an
honest tree.

**Charge and the byte bound.** `bundle_charge` and `section_budget`
sum economy draws. Support draws are not in that sum, or the economy's
cap moves. Block weight does not count bundle bytes: the prunable body
is archival content in the shard domain (`SCS-P38`, spec §7.6), and
`block_weight.rs` does not read it.

Each passed support draw is one record, `BUNDLE_RECORD_LEN = 1,397`
bytes. The schedule puts at most one support draw per tree on a block,
so one bundle grows by at most `N · 1,397` bytes when `N` trees
pass a draw on that block. The phase in §2 is what keeps that from
being every tree on the same blocks. An unanswered draw sets no bit
and adds no record. At `c = 10`, a tree that passes every draw adds
`10 · 1,397 = 13,970` bytes to the epoch's shard domain.

| Trees | One bundle if every tree passes on it | Across the epoch, all draws passed |
| --- | --- | --- |
| 1 | 1,397 bytes | 14.0 KB |
| 10 | 13,970 bytes | 140 KB |
| 100 | 139,700 bytes | 1.40 MB |

That per-bundle term is the support stream's input to `SCS-P38`'s
maximum object, beside the economy bundle at the count cap. There is
no second numeric cap on `N`. The structural bound is one record per
tree per block.

**Store.** Economy `BlockDraws` (`archival_block_draws`, layout at
`SCHEMA_VERSION` 30) is unchanged: `count`, `carry`, `shortfall`,
`issued_short`, `revealed`. Support issuance is a new persisted row:
per tree, the unissued counter (capped at `c`), and per block the
support count issued. Unanswered support draws are not that counter
and are not `shortfall` or `issued_short`. The implementation PR bumps
`SCHEMA_VERSION` and regenerates `rust/shekyl-chain-store/schemas/`.
Rule 42: the snapshot gate is the red check.

## 6. What each site becomes

Nothing is cut in this round. The deletion list for the ruling is
empty: every flag below still has a job.

| Site | Class | Why |
| --- | --- | --- |
| `emit` complete-tree arm | support role, leaves `D` | The PR skips `Holdings::CompleteTree`: no pairs, no receipt key. Both derivations share `emit`, so the digest cross-check still compares them. Digest vectors are re-derived. |
| `freeze_complete_trees`, `archival_complete_trees[E]`, SI-31 `CompleteTreesNotFrozen` | still needed | SO-D12h freezes, at the slash pass, every credited persona whose record is a complete tree (`close.rs` `freeze_complete_trees`). That is the set `market_member_at_epoch` excludes. It is not the epoch-open membership the schedule needs. |
| `is_support_complete_tree` through `market_member_at_epoch`, `close.rs`, `tx_emission_against.rs` | still the §1.4 guard | Serve credit is written from passed draws. After complete trees leave `D`, an economy draw cannot select one. A support pass must not write credit. The exclusion is what still drops the persona from `R_market` and `Σwork` if a credit row is written anyway. The flag is reachable. Renamed from `is_foundation_complete_tree`; not deleted. |
| `SlashedHolding::CompleteTree`, `unslashed` | stays live | §3 demotes through it. |
| `ReportedSet::CompleteTreePrefix`, `ServingPosture::SupportCompleteTree`, `PinCompleteTreePrefix` | support role, stays | The node already serves the prefix. The producer of `h` dials, the same pull as an economy read (`read_from` / `read_from_nonce`), and files the support bitmap in the same bundle (§5). The serve posture does not need a second arm to answer a fetch of a prefix shard. Renamed from `FoundationCompleteTree`. |
| `HolderSource::holders_of` | design question, §7 | The scheduler's holders are the drawable holders. Leaving `D` removes complete trees from that urn. |

**SO-D12h and the schedule's membership are different facts.** The
schedule's set is pin 1 at `h_open(E)`: `join_settlement_epoch < E`
and the record is `CompleteTree`, the same walk `emit` already does.
SO-D12h's freeze is later, at the slash pass, and only over personas
that were credited. Re-using the freeze as the open membership would
ask the slash pass who was a complete tree before the epoch opened.
The open walk is the membership. The freeze stays the market exclusion.

## 7. Fetch — RULED 2026-10-22

`shekyl-p-fetch` `ServingEndpoint` is minted from the bond record's
endpoint column (`target.rs`, `EU-D4`). `HolderSource::holders_of`
(`shekyl-archival-fetch-sched` `facts.rs`) returns the drawable
holders of the shard. `drawable_epoch_walked_back` is the ruled
producer. Removing complete trees from `D` removes them from that
urn. The endpoint bytes remain on the record.

The proposal: the support membership from §6 is a second holder
source, read beside `D`, and the urn treats it as best-effort. Never
preferred over a drawn holder. Never the only holder tried while a
drawn holder of that shard exists. A refusal costs one timeout
(`NeedBudget` already moves on). `VerifiedShard` still checks the
body. This round does not patch it.

## 8. Who holds it, and what the wallet does today

Consensus accepts `HoldingsKind::CompleteTree` from any poster
(`verify_join_market_bond_post` allows the kind with an empty shard
list). The wallet's ordinary path is `ShardSetCompact`. The names
that said Foundation were the role's names and were wrong for ruling 2.
They are now `is_support_complete_tree` and
`ServingPosture::SupportCompleteTree`. The Foundation is one holder.

`verify_release_bond_post` does not refuse the kind. `Reinstate` does
(`ReinstateOnCompleteTree`). The proposal for the ruling: a voluntary
holder uses that existing `Release` and its cooldown, and the tree
stays slashable during the cooldown, the same exposure the economy's
cooldown already closes. A release that cleared a pending slash would
be the dodge that cooldown exists to stop. This round does not
redesign the path.

**Acquisition, checked at this pin. Not fixed here.** Reported to the
bond-post-delay round and the Tor lane.

- **One shard per circuit.** Yes for a single read. `PFetchClient::dial`
  presents `Isolation::Persona` from that read's header, and each read
  builds its own rendezvous circuit (`SF-D3`, `client.rs`).
- **Spread over time and across sources.** No such policy. `Urn::draw`
  is uniform over the need's holders, memoryless across needs
  (`draw.rs`). A burst of shard needs can draw the same complete tree
  repeatedly. Nothing delays the next shard.
- **Complete tree never the sole source.** No. `NeedBudget::DEFAULT`
  tries three holders. If the urn has only the complete tree, or the
  other holders fail, it is the source the need finishes on. While
  complete trees are in `D` they are holders of every shard, so they
  sit in every urn.

A complete-tree server that is asked for many shards of one new
holding sees that set. A later bond for exactly that set is the link
the bond-post delay's jitter is there to break. BD-Q4's window width
is still open.

## 9. Predictions

- `D` shrinks by `final_count` per complete-tree record. The economy's
  draws per block fall by `final_count / SEB` for each such record,
  and that record's unanswered draws leave `u`. The support stream
  adds `c` per tree per epoch, issued across the schedule in §2, with
  unissued carry capped at `c`.
- Neither sim draws complete trees. `shekyl-economics-sim`
  `secret_draw.rs` passes its own pair count to `draw_target`.
  `shekyl-staking-sim` does not call `draw_target` or `emit`.
  `proxy.rs` prices a complete tree as one floor at risk, not as
  members of `D`. No economy figure in either sim moves.
- At `c = 10` and non-filing rate `α = 0.10`, `P(issued < 3) =
  3.7 × 10^{-7}`. A draw that fails with probability `x = 0.01` then
  misses the epoch with probability `3.0 × 10^{-4}`, and the 11-of-13
  window slashes with probability `1.3 × 10^{-37}`. At `x = 1` the
  window slashes at 11 epochs. These are computed here, before any
  scenario test.

## 10. Tests the implementation PR owes

Each names the edit that turns it red.

- `emit` adds no complete-tree pair and no receipt key. Red: restore
  the expansion.
- The two derivations of `D` agree with a complete tree present.
- A support draw and an economy draw from the same seed and block hash
  differ, through the two customization strings. Red: one string for
  both.
- A signature over economy `(h, j)` is refused as support `(h, j)`,
  and the reverse. Red: derive both nonces with one customization
  string.
- A tree is issued `c` in an epoch when one scheduled block issues
  nothing; the unissued counter never exceeds `c`. Red: drop the carry.
- `SCHEMA_VERSION` moves with the new support row, and the
  chain-store schema snapshot fails until it is regenerated.
- Issued support draws for one tree over an epoch equal `c` at two
  values of `final_count`.
- An unanswered support draw leaves economy `u`, the cap, and
  `issued_short` unchanged. Red: add it to `u`.
- Slash: the tree's issued support draws settle through `settle_pair`.
  Fewer than three issued is NonObservation and does not enter the
  failure window. Two or more passes of the three selected draws is
  Served. Zero or one is Missed. Eleven Missed epochs demote through
  `SlashedHolding::CompleteTree`. Red: key the settlement row by
  `(tree, shard)`.
- A tree that passes every support draw has no serve credit, and
  `R_market` is unchanged.
- A complete-tree endpoint that refuses the body costs one timeout,
  and the fetch completes from a drawn holder, once §7 is ruled.

The tabled test, after EUP-4, is whatever finer hole detection §4's
question adopts. It is not a second interim rule.

## 11. What the implementation PR edits, after the ruling

- `ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md` §7.4 pin 2 becomes "complete
  trees are not in `D`". The support stream is its own section.
- `ARCHIVAL_SERVE_CREDIT_SPEC.md`: `D`, the support stream, the
  producer as the challenger, the two labels, and the per-bundle byte
  term in §7.6.
- `CONSENSUS_RULE_CENSUS.md`: the drawable-set rows and the support-draw
  rows. No new identifier family: this is `SO-D12`'s stream. A family
  minted later registers in the same PR (rule 94).
- `IMPLEMENTATION_INDEX.md` and `CHANGELOG`. The change is consensus,
  pre-genesis, so it is a regenesis, and the release note says so.
- The rename in §8, in that PR, not before.

## 12. Ruling — RULED 2026-10-22

Rick ruled all five as recommended. No new slash rule.

1. **`c` = 10**, at the stated non-filing rate of one block in ten
   (`P(issued < 3) ≤ 10^{-6}`).
2. **Schedule.** Spread across `SEB − W₂` with the per-tree
   `offset(P)`. Unissued carry capped at `c`. No top-up multiple.
3. **Deletion list empty.** The exclusion flag stays and is renamed
   for the support role.
4. **Fetch.** Support membership is a best-effort source beside `D`:
   never preferred over a drawn holder, and never the only holder
   tried while a drawn holder of that shard exists.
5. **Release.** A voluntary holder releases through the existing
   `Release` and its cooldown, and stays slashable during the cooldown.
