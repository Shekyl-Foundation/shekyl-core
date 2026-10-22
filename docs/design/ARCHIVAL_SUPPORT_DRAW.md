# CompleteTree support draws — Round 0

**Status: OPEN — Round 0, 2026-10-22.** No code in this round.
Ground: `dev` at `11f8fd1f0`. Rule 26: Rick rules on `c`, the schedule,
and the deletion list before the implementation PR. The stricter miss
accounting in §4 is **TABLED** (Rick, 2026-10-22) until after EUP-4;
the PR builds the interim rule in §3.

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
epoch. §4 shows why that number, and that it is for the tabled
accounting. The interim PR uses whatever `c` is ruled here; it does not
retune `FAILURE_WINDOW_M` / `N`.

Constants at this pin: `SEB = 10_000`, `W₂ = 500`
(`CHALLENGE_RESPONSE_BLOCKS`), early window ends at
`floor(0.7 · SEB) = 7_000` (`draw_horizon`). Block time is
`T_SECONDS = 120`.

**The schedule.** For persona `P` in epoch `E`, draw `i` of the `c`
(`i` from 0) is issued at epoch-relative height

```text
r_i = floor(i · 7_000 / c)
```

One draw per tree per chosen block. At `c = 413` the last height is
`floor(412 · 7_000 / 413) = 6_983`. Its response window ends at
`6_983 + 500 = 7_483`, which is before the epoch ends (`10_000`) and
before `7_000 + W₂`. Every support draw of the epoch is inside the
early window, and the whole of `W₂` after it is still inside the epoch.
The late-window arm of `draw_horizon` is not used.

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

## 3. Interim slash — what the PR builds

`failure_window_slashable` as it stands: at least
`FAILURE_WINDOW_M = 11` misses in at most `FAILURE_WINDOW_N = 13`
observations (`failure_window.rs`). The observations are the persona's
support draws, most recent first, one draw one observation. A slash
demotes through the existing `SlashedHolding::CompleteTree` path.
`drawable.rs` `unslashed` stays the undo. No new `m` or `n`.

At `c = 413` those draws sit about 17 blocks apart (`7_000 / 413`).
Eleven missed draws are about `11 · 17 · 120` seconds, a little over
six hours. The economy's same 11-of-13 is eleven epoch-observations.
A pair observed once an epoch needs about eleven epochs, on the order
of `11 · 10_000 · 120` seconds. The interim window is the ruling's
slash ("there have to be draws so that a malfunctioning CompleteTree
could be slashed"). It is a shorter outage than the economy's window
at this `c`. That gap is what §4 is for. It is not tuned in this PR.

A passed support draw writes no serve credit, adds nothing to
`Σwork`, and does not change `R_market`.

## 4. Stricter miss accounting — TABLED

**TABLED 2026-10-22.** Not built. Not ruled. The numbers below are the
starting point for the discussion after EUP-4. The row is in
`docs/FOLLOWUPS.md`, owned by this document.

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

**(a) is the option the tabled discussion should start from.** A
support role that claims the whole archive is held to the epoch
observation above. Nothing in this paragraph is the interim rule.

## 5. Bundle and verifier — consensus, named

A draw is `(stream, h, j)`. `stream` is economy or support. `j` is the
index within that stream at `h`.

The receipt transcript gains one stream byte, in the request header
the server sees, so the signature covers it. Today the header is
`nonce[32] ‖ anchor_height_le[8] ‖ anchor_hash[32]` (72) and the
transcript is that plus `shard_id_le[8] ‖ delivery_digest[32]` (112).
The header becomes `stream[1]` followed by those fields (73 and 113).
`pass_request_header_bytes`, `pass_countersignature_message`,
`PASS_REQUEST_HEADER_LEN`, and `PASS_COUNTERSIGNATURE_MESSAGE_LEN`
change together. Both scheme 1 and scheme 3 sign that transcript
(`verify_pass_transcript`, `verify_receipt_transcript`). A signature
over economy `(h, j)` does not verify as support `(h, j)`, because the
byte and the nonce (its own customization, below) differ.

Nonce customization for a support challenge is a second label,
`shekyl/archival-support-challenge-nonce-v1`, beside
`CHALLENGE_NONCE_CUSTOMIZATION`. The selection label is
`shekyl/archival-support-draw-v1`, registered in
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
receipt under the support stream byte. That step writes a support
observation. It does not write serve credit and it does not touch
`issued_short`.

**Charge.** `bundle_charge` and `section_budget` sum economy draws.
Support draws are not in that sum, or the economy's section cap moves.
The length formula `3,193 + 1,397 ·` (set bits) gains the support
records. That is an input to the shard-size maximum (`SCS-P38`).

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
| `SlashedHolding::CompleteTree`, `unslashed` | stays live | The interim slash and the tabled slash both demote through it. |
| `ReportedSet::CompleteTreePrefix`, `ServingPosture::FoundationCompleteTree`, `PinCompleteTreePrefix` | support role, stays | The node already serves the prefix. A challenge is a pull: the challenger dials (`read_from` / `read_from_nonce`). What is missing is the challenger issuing a support draw and filing it on the support bitmap. The serve posture does not need a second arm to answer a fetch of a prefix shard. |
| `HolderSource::holders_of` | design question, §7 | The scheduler's holders are the drawable holders. Leaving `D` removes complete trees from that urn. |

**SO-D12h and the schedule's membership are different facts.** The
schedule's set is pin 1 at `h_open(E)`: `join_settlement_epoch < E`
and the record is `CompleteTree`, the same walk `emit` already does.
SO-D12h's freeze is later, at the slash pass, and only over personas
that were credited. Re-using the freeze as the open membership would
ask the slash pass who was a complete tree before the epoch opened.
The open walk is the membership. The freeze stays the market exclusion.

## 7. Fetch — question for Rick

`shekyl-p-fetch` `ServingEndpoint` is minted from the bond record's
endpoint column (`target.rs`, `EU-D4`). `HolderSource::holders_of`
(`shekyl-archival-fetch-sched` `facts.rs`) returns the drawable
holders of the shard. `drawable_epoch_walked_back` is the ruled
producer. Removing complete trees from `D` removes them from that
urn. The endpoint bytes remain on the record.

The question: the support membership from §6 has to be a second
holder source, read beside `D`, and the urn has to treat it as
best-effort. Never preferred over a drawn holder. Never the only
holder tried while a drawn holder of that shard exists. A refusal
costs one timeout (`NeedBudget` already moves on). `VerifiedShard`
still checks the body. This round does not patch it.

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
(`ReinstateOnCompleteTree`). Whether a voluntary support holder should
have a release path is for Rick. This round does not redesign it.

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
- For the tabled `c = 413` and `f = 0.01`, `P(slash in one 13-epoch
  window) = 0.99901` under §4 option (a). False slash on a live
  complete tree is 0. A total outage slashes at `d ≥ 11` epochs and
  not before. These are computed here, before any scenario test. The
  scenario test is the tabled row's, not the interim PR's.

## 10. Tests the implementation PR owes

Each names the edit that turns it red.

- `emit` adds no complete-tree pair and no receipt key. Red: restore
  the expansion.
- The two derivations of `D` agree with a complete tree present.
- A support draw and an economy draw from the same seed and block hash
  differ, through the two customization strings. Red: one string for
  both.
- A signature over economy `(h, j)` is refused as support `(h, j)`,
  and the reverse. Red: drop the stream byte from the transcript.
- A tree is issued `c` in an epoch when one scheduled block issues
  nothing; the unissued counter never exceeds `c`. Red: drop the carry.
- `SCHEMA_VERSION` moves with the new support row, and the
  chain-store schema snapshot fails until it is regenerated.
- Issued support draws for one tree over an epoch equal `c` at two
  values of `final_count`.
- An unanswered support draw leaves economy `u`, the cap, and
  `issued_short` unchanged. Red: add it to `u`.
- Interim slash: 11 misses in 13 support draws demotes through
  `SlashedHolding::CompleteTree`. Ten misses do not.
- A tree that passes every support draw has no serve credit, and
  `R_market` is unchanged.
- A complete-tree endpoint that refuses the body costs one timeout,
  and the fetch completes from a drawn holder. This waits on Rick's
  answer in §7.

The tabled option-(a) scenario (a tree missing a stated fraction,
against the §4 rates) is the FOLLOWUPS row's test, after EUP-4.

## 11. What the implementation PR edits, after the ruling

- `ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md` §7.4 pin 2 becomes "complete
  trees are not in `D`". The support stream is its own section.
- `ARCHIVAL_SERVE_CREDIT_SPEC.md`: `D`, the support stream, the stream
  byte, the two labels.
- `CONSENSUS_RULE_CENSUS.md`: the drawable-set rows and the support-draw
  rows. No new identifier family: this is `SO-D12`'s stream. A family
  minted later registers in the same PR (rule 94).
- `IMPLEMENTATION_INDEX.md` and `CHANGELOG`. The change is consensus,
  pre-genesis, so it is a regenesis, and the release note says so.
- The rename in §8, in that PR, not before.

## 12. Ruling asked

1. **`c`.** Recommended 413, from §4. The interim slash at that `c` is
   the six-hour reading in §3.
2. **The schedule in §2**, including the unissued cap at `c`.
3. **The deletion list.** Empty. The exclusion flag stays and is
   renamed. Say if that is wrong.
4. **§7**, the fetch source. Not patched here.
5. Whether a voluntary support holder should have a release path (§8).
   Not designed here.

§4 is not on this list.
