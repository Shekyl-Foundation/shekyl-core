# CompleteTree support draws — Round 0

**Status: OPEN — Round 0, amended 2026-10-22 on review of `7632f2e3f`.**
No code in this round. Ground: `dev` at `11f8fd1f0`. The PR builds §3.
What stays **TABLED** until after EUP-4 is §4: weighting a partial miss,
and the per-draw drop rate `q`.

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

## 2. Schedule — for ruling

**Recommended `c` = 413** support draws per complete-tree persona per
epoch. §3 is where that number is derived. The PR does not retune
`FAILURE_WINDOW_M` / `N`.

Constants at this pin: `SEB = 10_000`, `W₂ = 500`
(`CHALLENGE_RESPONSE_BLOCKS`). The usable span is `SEB − W₂ = 9_500`,
the same late bound `draw_horizon` uses after `0.7 · SEB`. Block time
is `T_SECONDS = 120`.

**The schedule.** For persona `P` in epoch `E`, draw `i` of the `c`
(`i` from 0) is issued at epoch-relative height

```text
r_i = floor(i · (SEB − W₂) / c) = floor(i · 9_500 / c)
```

One draw per tree per chosen block. At `c = 413` the spacing is
`9_500 / 413 = 23.00` blocks. The last height is
`floor(412 · 9_500 / 413) = 9_476`. Its response window ends at
`9_476 + 500 = 9_976`, inside the epoch. Records-was, the first draft:
all `c` draws sat in `r ∈ [0, 7_000)`, and the last window closed at
7,483, leaving about 2,517 blocks of every epoch with no support draw
that could land.

The heights are public. The shard a draw selects is not. Spreading
across `SEB − W₂` is what removes the gap a tree could step around.

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

## 3. Slash — what the PR builds

The predicate is the economy's. `failure_window_slashable` is unchanged:
at least `FAILURE_WINDOW_M = 11` misses in at most
`FAILURE_WINDOW_N = 13` observations. No new `m` or `n`.

The observation is the epoch, not the draw. The epoch is a pass when
every one of its `c` issued support draws passed. It is a miss when any
issued draw failed. A slash demotes through the existing
`SlashedHolding::CompleteTree` path. `drawable.rs` `unslashed` stays
the undo.

A draw the producer never revealed is not a miss. The economy's rule is
the same (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §1.6, `SCS-P15`): a block with
no bundle by `h + W₂` issues nothing, and nobody asserts a miss. Those
support draws return to the unissued counter in §2. The failure window
already passes over a NonObservation (`slash.rs`).

**Why the observation is the epoch.** A tree missing a fraction `f` of
the archive fails each draw with probability `f`. At `f = 0.01`, eleven
failures in thirteen consecutive draws has probability `7.7 × 10⁻²¹`.
A per-draw 11-of-13 never slashes that tree. It only slashes a total
outage measured in draw-spacings. Records-was, the first draft of this
section, which used that unit. The epoch observation is the existing
predicate applied where the economy already applies it.

**`c` = 413** is the smallest integer at which a tree missing at least
1% is slashed inside one window of 13 epoch-observations with
probability at least `0.999`. The table is §4. A live complete tree
(`f = 0`) fails no draw, so the false-slash rate on it is 0. A total
outage of `d` epochs is `d` misses and slashes at `d ≥ 11`, which is
the economy's threshold on epoch-observations.

**Retry, so a single draw's window is not the slash threshold.** The
producer uses the economy's `CHALLENGE_READS = 3` inside `W₂`
(`secret_draw.rs`). A draw is a miss only when the admitted bundle
carries no receipt for it after those reads. Covering one draw therefore
takes the outage across the reads the producer made inside that draw's
`W₂`, not across the spacing between draws. Under this section that
duration is not the slash line. Eleven epoch-observations are.

A passed support draw writes no serve credit, adds nothing to
`Σwork`, and does not change `R_market`.

## 4. What stays tabled

**TABLED 2026-10-22, narrowed on review.** §3 is the rule the PR
builds. Still unruled, and not built, until after EUP-4: weighting a
partial miss inside an epoch, and treating a per-draw drop rate `q` as
an outage. The row is in `docs/FOLLOWUPS.md`, owned by this document.
The rates below are the ones §3 is built from. They are not a second
rule.

A complete tree claims every shard, so a draw that fails while the
tree is answering is evidence it lacks that shard. The model used
here, stated so the rates can be checked:

- The tree is up, or it is in a total outage. A total outage of `d`
  epochs fails every support draw in those epochs and no others.
- While up, each draw fails independently with probability `f`, the
  fraction of the archive it does not hold. `f = 0` is a complete
  tree.
- "High probability" in the recommendation is `0.999`, on one window
  of 13 epoch-observations.
- The economy's false-slash comparison is the same 11-of-13 predicate
  on epoch-observations: a total outage slashes only when `d ≥ 11`.

**Option (a) — strict, epoch observation.** One epoch-observation is a
miss when any of the epoch's `c` draws fails, and a pass when all `c`
pass. The window is the existing 11-of-13 on those epoch-observations.
Demotion is `SlashedHolding::CompleteTree`.

`P(epoch miss | f) = 1 − (1 − f)^c`.
`P(slash in one window) = P(Binomial(13, p) ≥ 11)` with that `p`.

At `f = 0.01`:

| `c` | `P(epoch miss)` | `P(slash in the window)` |
| --- | --- | --- |
| 400 | 0.982 | 0.9986 |
| 412 | 0.984 | 0.99898 |
| 413 | 0.984 | 0.99901 |
| 459 | 0.990 | 0.99974 |

**Recommended `c` for this option: 413**, the smallest integer at
which a tree missing at least 1% is slashed inside one window with
probability at least `0.999`.

False slash under the outage model: the epoch is a miss only when its
draws fail. A total outage of `d` epochs is `d` misses. The window
slashes at `d ≥ 11` and not before. That is the economy's predicate
on epoch-observations. An honest tree (`f = 0`) that stays up fails
no draw, so this arm's false-slash rate on a live tree is 0.

A per-draw loss that is not a missing shard (a drop probability `q`
while the tree holds everything) is outside that model. At `q = 0.001`
and `c = 413`, `P(epoch miss) = 0.338` and `P(slash)` on one window is
`0.00025`. At `q = 0.001` and `c = 688` it rises to about `0.011`.
The recommendation does not treat that drop rate as the outage.

**Option (b) — tolerant miss rate.** Slash when the miss rate over the
window's `13 · c` raw draws exceeds a threshold `τ`.

A threshold that sees `f = 0.01` sits at or below `0.01`. A one-epoch
total outage is a miss rate of `1/13 ≈ 0.077`, which is already above
any such `τ`, so (b) slashes an outage the economy's 11-of-13 does
not. A threshold high enough to forgive a 10-epoch outage sits above
`10/13`, and a 1% hole never reaches it. (b) does not meet both bars
with one threshold on raw draws.

**(a) is §3.** What stays tabled is option (b), and the per-draw drop
rate `q` in the paragraph above. Weighting how many of the `c` draws
failed inside an epoch is the same deferral. Those are not a retune
of §3.

## 5. Bundle and verifier — consensus, named

A draw is `(stream, h, j)`. `stream` is economy or support. `j` is the
index within that stream at `h`.

The request `P` sees stays the 72-byte header. Spec §1.2: `P` cannot
tell a challenge from any other read, and a visible stream byte would
mark the support draws. The stream is covered because it is an input to
the nonce, and the nonce is inside the signed transcript
(`pass_countersignature_message`). A signature over economy `(h, j)`
was made under `CHALLENGE_NONCE_CUSTOMIZATION`. Checked as support
`(h, j)` it is checked under
`shekyl/archival-support-challenge-nonce-v1`, the nonce bytes differ,
and the signature fails. The red edit is one customization string for
both. The bundle's bitmap is what tells the verifier which string to
recompute.

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
so one bundle grows by at most `N · 1,397` bytes for `N` complete trees
that all pass. An unanswered draw sets no bit and adds no record. At
`c = 413`, a tree that passes every draw adds `413 · 1,397 = 576,961`
bytes (577 KB) to the epoch's shard domain.

| Trees | Added to one bundle, all passing | Added across the epoch |
| --- | --- | --- |
| 1 | 1,397 bytes | 577 KB |
| 10 | 13,970 bytes | 5.77 MB |
| 100 | 139,700 bytes | 57.7 MB |

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
| `is_foundation_complete_tree` through `market_member_at_epoch`, `close.rs`, `tx_emission_against.rs` | still the §1.4 guard | Serve credit is written from passed draws. After complete trees leave `D`, an economy draw cannot select one. A support pass must not write credit. The exclusion is what still drops the persona from `R_market` and `Σwork` if a credit row is written anyway. The flag is reachable. It is renamed, not deleted. |
| `SlashedHolding::CompleteTree`, `unslashed` | stays live | §3 demotes through it. |
| `ReportedSet::CompleteTreePrefix`, `ServingPosture::FoundationCompleteTree`, `PinCompleteTreePrefix` | support role, stays | The node already serves the prefix. The producer of `h` dials, the same pull as an economy read (`read_from` / `read_from_nonce`), and files the support bitmap in the same bundle (§5). The serve posture does not need a second arm to answer a fetch of a prefix shard. |
| `HolderSource::holders_of` | design question, §7 | The scheduler's holders are the drawable holders. Leaving `D` removes complete trees from that urn. |

**SO-D12h and the schedule's membership are different facts.** The
schedule's set is pin 1 at `h_open(E)`: `join_settlement_epoch < E`
and the record is `CompleteTree`, the same walk `emit` already does.
SO-D12h's freeze is later, at the slash pass, and only over personas
that were credited. Re-using the freeze as the open membership would
ask the slash pass who was a complete tree before the epoch opened.
The open walk is the membership. The freeze stays the market exclusion.

## 7. Fetch — proposed, for the ruling

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
that say Foundation are the role's names and are wrong for ruling 2:
`is_foundation_complete_tree`, `ServingPosture::FoundationCompleteTree`,
and the docs that define the kind as the Foundation's. The
implementation PR renames them to the support role. The Foundation
is one holder.

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
- For `c = 413` and `f = 0.01`, `P(slash in one 13-epoch window) =
  0.99901` under §3. False slash on a live complete tree is 0. A total
  outage slashes at `d ≥ 11` epochs and not before. These are computed
  here, before the scenario test. The scenario test is the
  implementation PR's.

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
- Slash: eleven epoch-observations that each contain a failed issued
  draw demote through `SlashedHolding::CompleteTree`. Ten do not. A
  block with no admitted bundle does not add a miss. A tree missing
  1% of the archive, at `c = 413`, is demoted inside one window at the
  rate in §3. Red: count one observation per draw instead of per epoch.
- A tree that passes every support draw has no serve credit, and
  `R_market` is unchanged.
- A complete-tree endpoint that refuses the body costs one timeout,
  and the fetch completes from a drawn holder, once §7 is ruled.

The tabled test, after EUP-4, is a partial-miss weight or a drop rate
`q`, against the figures in §4. It is not the 1% scenario above.

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

## 12. Ruling asked

Amended after review of `7632f2e3f`. The round's proposal on each:

1. **`c` = 413**, derived in §3 under the epoch observation. A per-draw
   11-of-13 does not derive it: at `f = 0.01` that window slashes with
   probability `7.7 × 10⁻²¹`.
2. **The schedule in §2.** Spread across `SEB − W₂`. Unissued carry
   capped at `c`. No top-up multiple.
3. **The deletion list.** Empty. The exclusion flag stays and is
   renamed.
4. **§7.** Support membership is a best-effort fetch source beside `D`.
5. **Release.** A voluntary holder uses the existing `Release` and its
   cooldown, and stays slashable during the cooldown (§8).

§4's partial-miss weight and the drop rate `q` are not on this list.
