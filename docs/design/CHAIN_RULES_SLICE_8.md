# `shekyl-chain-rules` slice 8 — census 4.J, the archival admission rules, and the 4.B row that waited for the bond record (DRS-E6 increment 9)

**Status:** OPEN — **§5 rows 1–5 LANDED on PR-a (#953, 2026-10-04/05,
ruled as PR-a's scope under Q7 (a), §5); row 6 blocked on SO-D8's
`closed_and_final` sentence (§3.4, asked 2026-10-05); rows 7–10 proposed as
PR-b and row 6 as PR-c (§5, reorder); rows 11+ not begun.** Round 0 RULED
2026-10-04 (implementation opened with PR-a commit 1); pre-flight written
2026-10-03 against `dev` @ `01a4494f1a` (post-#939, the serve-credit
verifier's Round 0; post-#942, CEN-J2; post-#937, DRS-E4 archived).
*Records-was:* this banner read "No implementation has begun; rule 26 halts
implementation, not the pre-flight record" until 2026-10-05, five landed
rows after it stopped being true. Registered before
implementation (rule 94 §5): the DRS-E6 row in
[`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) and the doc row in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §7 name this file. No
identifier family is minted here: the slice's rows are the census's
`CEN-J*` and `CEN-B4`, its questions are `Q1…Q8` of §8 (Q9 struck by
ruling, kept as a numbered line so nothing re-uses it) scoped to this
document as the earlier slices' were, and the one disposition it makes
against a `CEN-` row is recorded on that row. Process per
`26-sub-pr-design-discipline.mdc`, cited as the pre-flight's shape:
substrate re-read at the pin, the expectation table written before the
second commit, artifact execution before a budget becomes a gate.

**UPDATE 2026-10-04 (Round 0, boundary ruling at `dev` @ `7003bd629`,
#946):** the serve-credit round closed and Slice C was authorized, and the
boundary it draws cuts this slice's row list — CEN-J1 is Slice C's
(`ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md` §8.0 `:2240`), the interim row
(`SCV-Q1`) is withdrawn, and `SCV-Q5` makes this slice pre-genesis critical
path. §1.2 items 1 and 2, §2, §4, §5, §6 and §8 carry the correction; the
figure moved for the third time, so §1.2 item 2 now derives it from the
row list and every other surface repeats the sum, not the total. Code
pins are unchanged (#946 touched documents only).

**UPDATE 2026-10-04 (Round 0 RULED — maintainer, eight rulings):** six
defaults taken (Q1 (a), Q2 yes, Q4 fail closed, Q5 build-here, Q7 three
PRs in sequence, Q8 J13 ahead of `judge_signatures`), **Q6 amended**
(`Option<WitnessSet>`; `None` is *not supplied*, `Some(empty)` is *none
exist*; B4 vacuous on `None` and recorded in the coverage gaps), **Q3
conditioned** (a byte-identity test between the driver's assembly and the
engine's, and a recorded trigger: a third re-made assembly makes
extraction the answer). Each ruling is on its question in §8 and on the
section it changes (§3.3–§3.5, §4, §5, §5.1, §6). The round log (§7)
carries the date.

**UPDATE 2026-10-04 (Q6's amendment — mechanism REFUTED at source, same
day; review on #947):** §3.5's premise that nothing carried a witness was
false at the pin (`Candidate::attestation_witness`, E4 commit 5), and the
amendment's mechanism cannot exist in this crate — a vacuous row is *in*
coverage, a gap is a row *absent* from it, and `ChainValid::mint` panics
on the absence (`verdict.rs:84–95`); `Some(empty)` is unrepresentable
(`AttestationWitness` is non-empty by construction). **Corrected
disposition — RULED 2026-10-04 (maintainer, verified at
`dev@638f4999f7`):** B4 judges the existing field, always; `None` is
judged as the empty preimage against the header's `attestation_root` —
passes on the empty root, refuses otherwise (fail closed); no new
parameter, no new type; the store's B4 gap-widening retires at row 10.
The ruling's intent is kept whole and lands consensus-bound rather than
transport-bound; §3.5 carries the refutation, the ruling and the
consequence for §5 row 10. **This ruling is PR-a's opening commit** (branch
`feat/chain-rules-slice-8-pr-a`, off `dev@638f4999f7`), so the ruling
rides the code it governs rather than a documents-only PR; §5 row 1's
census re-key follows it as the next commit. Still no code at this
update.

Branch commits are named by PR and subject, never by SHA (slice 6's rule at
its head, inherited). A `dev` SHA is an era; every line number in this file
is read at `01a4494f1a` unless its sentence says otherwise.

Parent: [`CHAIN_RULES_CRATE.md`](CHAIN_RULES_CRATE.md) §4.6 (`validate`),
[`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) §7.5 (the 4.J row, `:1785`,
and the DRS-E6 row, `:1336`). Census:
[`CONSENSUS_RULE_CENSUS.md`](CONSENSUS_RULE_CENSUS.md) §4.J (`:478–519`) and
CEN-B4 (`:338`). The state this slice judges over was delivered by DRS-E4
([`DRS_E4_ARCHIVAL_WRITER.md`](../completed/DRS_E4_ARCHIVAL_WRITER.md),
archived; §2.3 *What E6 slice 8 gets*). The serve-credit rows this slice
does **not** build had their own Round 0 —
[`SERVE_CREDIT_VERIFIER.md`](../completed/SERVE_CREDIT_VERIFIER.md), closed
as record 2026-10-04 — and now belong to SO-D8 Slice C (§1.2 below).

---

## 0. What this slice is

The **archival admission rules**: what the validator says about one
archival transaction — a bond post, an emission claim, the eligibility half
of a serve credit — *before* the transition folds it into the market's
state. In the C++ this is `check_archival_bond_post_input`
(`blockchain.cpp:4458–4707`), the emission arm of `check_tx_inputs`
(`:3888–4184`), and the first six gates of `check_archival_serve_credit_input`
(`:4756–`); every verdict is already Rust-side, reached through
`shekyl-archival-retention`'s verify functions, and the C++ marshals
operands off LMDB. The rows are 4.J's, and the census's own header says
what the slice is: *all verdicts Rust-side; C++ marshals*.

Three things make 4.J unlike 4.G and 4.I:

- **The judging half is missing and the folding half is landed.** DRS-E4
  built the archival *transition* (`archival/{inputs,slash,close}.rs`):
  `validate` already reads the record off `ChainView`, runs the retention
  crate's connect folds, and refuses the block at the offending input
  under **CEN-L7** when a fold cannot apply (`archival/inputs.rs:40–289`).
  So several 4.J rows are *partially* enforced today under L7's row — a
  serve credit from a persona with no record (J4's rule, `:49–53`; J4
  landed at §5 row 3 and that arm is its belt now), a
  second JoinMarket for a persona (J14's "must not already exist",
  `:97–99`), a Release whose debit is not the record's total (J16,
  `:158–170`), a Reinstate with no open interval (J18, `:210–223`) —
  J14, J16 and J18 landed at §5 row 5 and those three arms are belts now
  too — a claim for an epoch already claimed (J25's dedup, `:273–280`).
  What was **not** running at the pin is the admission verify the C++
  runs *before* applying: `verify_join_market_bond_post`,
  `verify_release_bond_post` with its cooldown anchors and
  `verify_reinstate_bond_post` (the three now called from
  `judge_bond_post`, row 5), `check_admission`,
  `emission_vin_verify_{claims,backing,auth}`, the bond-post statics
  (J11–J13, row 4), the emission statics (J19, J20, J22, J24). This slice lifts
  each row to its own `CenRow` with its own locus and falsifier, ordered
  before the transition; L7 keeps the fold refusal as the belt it is
  (one mechanism, one job — rule 05: the verify judges the *post against
  the rule*, the fold judges the *post against the record's arithmetic*,
  and the C++ runs both).
- **Its witnesses are made, not captured.** §1.2 item 2 prices this. The
  corpus carries the *accept* path for a JoinMarket and an emission claim
  and nothing else of this family; every refusal and every Release,
  Reinstate, B4 record, and bond-state (J4–J6) case is a scenario the
  driver has to be taught to produce.
- **Three of its rows and two of its clauses describe a mechanism that
  was retired by ruling.** J8–J10 encode the beacon-fire / sampled-leaf /
  leaf-path mechanism `PDM-Q12` retired (`ARW-13`, SCV §3); J17 and J13's
  drop arm name `HoldingsUpdate`, REJECTED 2026-09-20 (`ARW-14`) — re-keyed
  at §5 row 1 (PR-a commit 2, 2026-10-04; §3.2). A row
  that names a deleted type cannot be implemented as written, and a rule
  built to a retired mechanism is built to be deleted. §1.2 draws the
  seam; commit 1 does the re-key before any rule cuts.

In Rust the home is `tx_against` (`validate.rs:622`) for the per-transaction
view-bound rows — a `TxAgainstRule` after I7 and `judge_reference`, before
`judge_signatures`, in the C++'s order — and `tx_form` for the stateless
statics (J11, J12, J19, J20, J22, J24 are bytes-only, the `TxRule` shape J2
took in `rules/tx_inputs.rs:340`). CEN-B4 is a `BlockRule` in `validate`
after D1 (by construction the verify-behind-PoW order the C++ reorder row
wants — FOLLOWUPS `:190`).

---

## 1. Parents — landed? (§7.5.1 (a))

### 1.1 Landed

- **The archival reads** (`view.rs:406–487`): `bond_record`,
  `slash_log_after`, `last_served_epoch`, `served_shards`, `pass_count`,
  `r_market`, `sigma_work`, `budget`, `last_settled_slash_epoch`,
  `bond_records` — every operand the 4.J rows and B4 consume, each with
  `BatchView` and `MockChain` bodies and the store's conformance test
  (DRS-E4 commits 1–4, PR #914). `r_market` / `sigma_work` / `budget`
  return `Option` (`SAR-Q6`, [`DRS_E1_SARCH.md`](../completed/DRS_E1_SARCH.md)
  `:609`): the store stopped erasing absence so that this slice can ask
  what absence means (§3.3, Q4).
- **The transition and L7** (`archival/mod.rs`, `inputs.rs`, `slash.rs`,
  `close.rs`; DRS-E4 commit 5, PR #921): the folds run in `validate`
  (`validate.rs:475`) after the block rules and the paid reward; the
  verdict carries `ArchivalDelta` (`ARW-Q1`). The rows this slice lands
  run *before* it, at `tx_against`, and refuse with their own `CenRow`;
  a post that passes them and still fails a fold is L7's, as today.
- **`BondRecord` in `shekyl-types`** (`ARW-Q8`): the record the rows read
  is one type on both sides of the view.
- **The shard universe** (`closed_shards_before`, `rules/miner.rs:564`;
  `shard_close_height`, `archival/close.rs:51`; `SHT-Q2`, PR #910):
  `⌊C(h) / W⌋` off `cumulative_archival_len`. This is
  the "presence" operand J15 marshals as a freeze height in the C++
  (`blockchain.cpp:4650–4670`) and the operand of the closed-and-final
  predicate (§3.4).
- **The retention crate's verify surfaces**, all pure, all tested:
  `bond_post::{verify_join_market_bond_post, verify_release_bond_post,
  verify_reinstate_bond_post, release_vin_statics,
  bond_post_funding_floor_met}` (`:225`, `:381`, `:146`, `:328`, `:478`),
  `bond_ct_balance::verify_bond_post_ct_balance` (`:101`),
  `admission::{check_admission, parent_state_shards_from_gather}` (`:420`,
  `:327`), `release_cooldown::{release_cooldown_elapsed,
  slashes_settled_through, whole_record_last_served}`,
  `debit_auth::{debit_auth_pin, cold_authority_pin,
  requires_cold_authority}`, `serve_eligibility::serve_credit_epoch_ok`,
  `emission_verify::{emission_vin_verify_claims, emission_vin_verify_backing,
  emission_vin_verify_auth, emission_vin_verify}` (`:422`, `:659`, `:714`,
  `:772`), `claimed_epochs::*`, `p_canonical_id_from_hybrid_pubkey`. The
  crate already depends on `shekyl-archival-retention` (slice 5's H21/H22;
  the transition). These are the bodies the C++ calls through the FFI;
  the rows port as-is and the port is a *caller*, not a re-derivation.
- **The scenario driver's archival half** (`scenario_archival.rs`, DRS-E4
  commit 4): a persona with real keys, `Persona::join` / `release` /
  `post_by_hand` riding a real spend (`Spender::spend_coinbase_posting`),
  and `Persona::serve_credit(shard, epoch)` as a marker-signed credit. The
  driver can already make a JoinMarket, a Release and a serve credit that
  `validate` admits; it cannot yet make a Reinstate, an emission claim, or
  an attestation witness (§1.2 item 2).
- **The corpus's two archival shapes** (`shekyl-chain-ingest/tests/vectors/`):
  `bond-post` (109 blocks, one JoinMarket riding a spend, C++-built and
  C++-accepted) and `emission-claim` (1 026 blocks; a JoinMarket, a serve
  credit written by the regtest **injector** — `out_of_band_writes`, not a
  vin — and an emission claim). Both replay at digest parity today. They
  are the slice's two positive witnesses and the only ones.
- **CEN-J2** (`rules::tx_inputs::J2`, PR #942, `SHT-9`): the one 4.J row
  landed, stateless, in `tx_form`. 4.J reads `1 / 26` in the registry
  (`census.rs:485–510`).

### 1.2 Scoped out on arrival, and what the scoping costs

Three dispositions are made here, at the start, so the slice's record is
honest from its first commit rather than corrected at its fourth.

**1. CEN-J8, J9 and J10 are not this slice's; nor, with them, are J1, J3
and J7.** [`SERVE_CREDIT_VERIFIER.md`](../completed/SERVE_CREDIT_VERIFIER.md)
was their Round 0 — not this slice's. The seam is the one DRS-E4 drew when it scoped the
verifier out of itself (`DRS_E4_ARCHIVAL_WRITER.md` §2.2, RULED 2026-09-29:
*E4 owns the typed state and the transition, slice 8 owns the 4.J rule that
reads them*). This slice's rows are admission rules over state the view
already delivers: read the view, judge, record. J8–J10 are a different
object — they need `PDM-Q6` item 4's preimage re-derived against `SHT-Q2`'s
unit, they change what the wallet signs (`shekyl-archival-retention/src/wire.rs:345–360`),
and two of the three name a mechanism `PDM-Q12` retired. That is a design
round with a cross-crate cutover inside it; a 26-row slice that carries one
is how slice 6 reached seventeen commits.

SCV §3 (`:257–266`) then says the thing that moves two more rows: *the
validation surface is one (rule 19): J3, J7, J8, J9 and J10 change together
with J1/J2's wire*. J3's pair-epoch dedup and J7's `≤ H_close` / seal-on-chain
window are the beacon mechanism's rows as much as J8's fire height is
(superseded by `SO-D8b` and `SO-D8a` respectively — SCV §3's first two
rows). A rule built in this slice to the retired window would be built to
be deleted at Slice C. So they go with the surface.

*Ruled the next day, and the ruling draws the line one row further.* The
first draft of this item kept J1 — *the vin is an opaque blob; only the
Rust codec parses it* (census `:484`) — as an eligibility row. Slice C's
surface as ruled is **"the successors of CEN-J1–J3 and J7–J10"**
([`ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md`](ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md)
§8.0 `:2240`, AUTHORIZED 2026-10-04), and the census says why: J1 is the
vin's codec-parse row, and the codec parses the R-B record whose layout is
Slice C's Round 0 input 2 (`SCV-3`; §8.0 `:2253–2259`). A parse rule moves
with the bytes it parses. J2 is the one row of the J1–J3 run already
`implemented` (2026-10-03, `rules::tx_inputs::J2`); it stays landed and its
*successor* is Slice C's, which is what "successors of" says.

**What stays — and why the cut stops there.** J4 (*the named P must have a
bond record*), J5 (*claimed epoch ≥ E_first*), J6 (*P must be `good_through`
the claimed epoch*) — census `:487–489` — read bond state E4 already
delivers (`bond_record`, the join epoch, `good_through`) and touch neither
the preimage, nor the freeze, nor anything `SHT-Q2` re-keyed. `RC-114 ⇒
split across CEN-J4–J7` is the census recording that these were once one
check; Slice C took J7 (the close-height and seal-on-chain row, the beacon
window's) and left the three bond-state rows. They land here, and §5's
row 3 names them by what they check rather than by the transaction they
happen to sit on.

**Carrier** (rule 22): Slice C — SO-D8 §8 (`:2232`), authorized, with the
closed serve-credit round's §8 dispositions as its Round 0 (§8.0 `:2234`).
**Owner** of the six rows' census disposition is Slice C: `SCV-Q6`
transferred there, with a retired-by-ruling `RowStatus` arm owed with the
census change that lands Slice C's rows (§8.0 `:2271–2273`). The Rust
validator's *interim* behaviour on a serve-credit vin is no longer anyone's
question: `SCV-Q1` was **withdrawn as moot** and its three evidence facts
became Slice C's expectations (§8.0 item 3), so nothing in this slice
orders itself relative to an interim row — the earlier draft's preference
on that ordering is struck with it (was Q9). **Falsifier** that the
boundary moved without a ruling: any of the six — J1, J3, J7, J8, J9, J10
— reading `implemented` in `census.rs` under this slice's record.

**The genesis gate reaches this slice.** `SCV-Q5`, recorded on `DEL-008`
(§8.0 `:2245–2247`): *no genesis, and no `DEL-008` cutover, until Slice C's
admission rows are `implemented` in `census.rs` and J8–J10 are retired.*
Two consequences for this plan. Slice 8 and Slice C are both pre-genesis
critical path — this slice's `Target:` lines and its three PRs are
scheduled as such, not as a coverage sweep. And `DEL-008`'s trigger moved
from the cutover — the furthest date in the programme — to a near, owned,
checkable event (`check_chain_rules_coverage.py --describe` reading the
Slice C rows `implemented` and J8–J10 in the retired arm). The
serve-credit brief proposed that conversion from the other direction two
days earlier (`SCV-Q5`, posed 2026-10-02); it arrives here as a ruling.

This also re-points one inherited item. FOLLOWUPS `:197` (*Split
`archival_reorg_depth_blocks`*) names E6 slice 8 as the landing lane
because it is *the lane that lands the re-keyed serve-credit admission
rule*. That lane is now Slice C. The row's *Owed* and *Owner* lines were
re-pointed **in this PR** (`:186` at `7003bd629`), not deferred to commit
1: the index's method note makes the cleared-gate sweep the obligation of
the PR that moves the item, and a row naming a lane that has already given
the work away is the expensive direction (surfaced by review on #947). The
row's falsifier is unchanged.

**2. The two-number record, and what the numbers count.** The census
section this slice is named for has 26 rows. Of them J2 is landed, six
(J1, J3, J7, J8, J9, J10) are the successor's, and J17 — if Q1's default
holds (§3.2) — leaves the validator-enforced denominator as a REJECTED
mechanism, the way CEN-F12 did. What is left is **derived from the row
list, not restated** — this figure has moved three times in two days and
each time the per-row audit (§2) was right and the headline wrong:

| rows this slice implements | count |
| --- | --- |
| J4, J5, J6 | 3 |
| J11, J12, J13, J14, J15, J16 | 6 |
| J18, J19, J20, J21, J22, J23, J24, J25, J26 | 9 |
| **4.J rows in** | **18** |

Check: 26 = 1 landed (J2) + 6 Slice C + 1 J17 + **18**. Beside the
eighteen land rows that are not 4.J's at all:

- **CEN-B4** is a 4.B row. Slice 1 deferred it (*"until bond records are on
  `ChainView`"*, DRS-E6 row `:1336`); E4 §2.2 names this slice as where
  the deferral lifts. It lands here because its operand landed here, and
  the record says so from the start: the slice's coverage arithmetic will
  not match its census section's, and the `4.J n / 25` line and the
  `4.B 6 / 7` line are two lines, not one.
- **CEN-I13 and CEN-I15** are 4.I rows — slice 6's two named successors
  (FOLLOWUPS `:783`, `:787`). Both read **UNBLOCKED 2026-09-26** in their
  own rows and **`pending`** in `census.rs` (`:474`, `:476`) seven days
  later — a fired condition still filed as pending, the week's pattern,
  found by this slice's §1.3 check. They are in this slice's path because
  **J21** is I10–I13's reference context applied to the emission
  transaction and **J26** is I15 applied to its fee-input subset (*"exactly
  as CEN-I15"*): J26 cannot be judged without I15's body, and I15's body
  is one commit in `judge_reference` beside I12 with a witness the driver
  already produces (`scenario_spend.rs`). Q2 (§8) asks whether they land
  here; the default is yes, and the record counts them as 4.I rows landing
  in a 4.J slice, exactly as B4 is a 4.B row landing in one.

So the record this slice aims at, written before any measurement (§5.1):
`implemented 97 + 18 + 1 + 2 = 118 / validator-enforced 152 − 1 = 151` if
Q1 and Q2 hold (the table's 18, B4, I13 and I15 in; J17's denominator
out); `4.J 1 + 18 = 19 / 26 − 1 = 25`; `4.B 5 + 1 = 6 / 7`;
`4.I 18 + 2 = 20 / 20`. If Q2 goes the other way: `97 + 18 + 1 = 116 /
151`, with J21 and J26 landing their non-proof clauses and the proof
halves staying with I15's FOLLOWUPS row. Either way the six successor
rows stay `pending` until Slice C mints theirs (SCV-Q6, now Slice C's, leaves
`census.rs` unchanged for a row retired by ruling).

**3. No captured chain carries most of what this slice judges, and that is
the estimate's largest term.** Stated precisely, because the first version
of this sentence was wrong: the corpus *does* carry the accept path for a
C++-built JoinMarket (`bond-post`) and a C++-built emission claim
(`emission-claim`), and both replay at parity — so J11–J15 and J19–J26 have
one positive witness each, and the digest parity those two chains hold
today is a regression gate on every rule this slice adds (a new row that
refuses a corpus block is a finding, not a fixture). What the corpus does
**not** carry: any Release (J16), any Reinstate (J18), any serve credit as
a vin (the `emission-claim` credit is the injector's row — `ARW-13`; so
J4–J6 have no corpus witness at all — their witnesses are the driver's and
the store's, §5 row 3), any attestation witness (the RPC
edge drops the sidecar — FOLLOWUPS `:184`; B4 has none), and
**no refusal of any kind** — the C++ daemon captured only what it accepted.
Every negative fixture in this slice is scenario-driven. The driver can
produce these shapes — it has the persona, the real spend, the post
constructors — so this is **work, not risk**, and the work is: a Reinstate
constructor; an emission-claim constructor (the engine's assembly is split
between the pure module `engine/emission_claim.rs` and the `StakeEngine`
handler that adds the membership-only proof and the dual auth — the driver
needs the latter half, which no builder crate exposes today; Q3); a
witness-supplying path for B4; and the per-row perturbations.
[`CHAIN_RULES_SLICE_6.md`](CHAIN_RULES_SLICE_6.md) §5.3.3 and
[`CHAIN_RULES_SLICE_7.md`](../completed/CHAIN_RULES_SLICE_7.md) §5.1 row 2
both measured the first attempt at anything the driver has never done at
**one commit each**; slice 7's estimate missed
by 20 % (fifteen estimated, eighteen landed) *with* corpus witnesses for its
rows. This slice prices four driver capabilities as four commits (§5.1
rows 2, 7, 10) and carries a wider signal than slice 7's.

### 1.3 The inherited items — which blockers had already cleared

Run before this file was written, as the week's pattern demanded: three
times in E4 a parked condition had fired while its row still read pending.
Of this slice's inherited items:

| item | parked against | at `01a4494f1a` | disposition |
| --- | --- | --- | --- |
| **`SAR-Q6` forward action** (`DRS_E1_SARCH.md:609`; §7.5 `:1785`) | not a blocker — a decision handed to this slice: what J15 does when a held shard's epoch has no `r_market` row | **askable**: `ChainView::r_market` returns `Option` (`view.rs:452`); the C++ marshals `0` (`blockchain.cpp:4650–4670`) | decided here, **Q4** (§3.3) |
| **CEN-B4's deferral** (slice 1; DRS-E6 row `:1336`) | *bond records on `ChainView`* | **cleared** 2026-10-01 — `bond_record` (`view.rs:406`), `bond_records` (`:487`) landed in PR #914; the verify body `shekyl-archival-retention/src/attestation.rs` is landed Rust | **lands here**; the witness's entry into `validate` is **Q6** (§3.5) |
| **`ARW-14`'s re-key** (`DRS_E4_ARCHIVAL_WRITER.md:1167`) | `HoldingsUpdate` deleted | **cleared** 2026-10-02 — no `HoldingsUpdate` arm anywhere: `PostKind::from_u8` yields Release / Reinstate / JoinMarket, an unknown kind is L7's refusal (`archival/inputs.rs:66–72`); the appliers are no-ops; the journal table `archival_bond_holdings_update_log` remains in the LMDB X-macro and the redb catalogue, empty by construction, and dropping it is a layout bump (FOLLOWUPS catalogue row) — ARW-14 emptied that table rather than removing it | **commit 1's work** — a precondition of the rules, not a task among them; **Q1** (§3.2) fixes J17's class |
| **`SCV-6` — the closed-and-final shard predicate** (FOLLOWUPS `:205`) | *the A4 length rows (S-CHAIN-W) and S-PRUNE deriving `b_*`* | **both dissolved by ruling** (`PDM-Q6` item 5: *A4 is not owed*; `SHT-Q2`: `shard_of(cumulative_archival_len)`), and the operand is landed — `closed_shards_before` — as SCV-6 found 2026-10-02 | **lands here**, inside J15's commit, **Q5** (§3.4) names its row |
| **`archival_reorg_depth_blocks` split** (FOLLOWUPS `:197`) | owed to *the lane that lands the re-keyed serve-credit admission rule* | the lane moved (§1.2 item 1) | **re-pointed** to Slice C in this PR (`:186` at `7003bd629`) |
| **CEN-I13 / CEN-I15** (FOLLOWUPS `:783`, `:787`; slice 6's successors) | E3's `depth_at`; a driver that mines a real spend | **both cleared 2026-09-26** (`view.rs:328`; `scenario_spend.rs`), both still `pending` (`census.rs:474`, `:476`) | consumed by J21 / J26 — **Q2** (§1.2 item 2) |

Four of six had cleared — two of them (I13, I15) a week ago, with their
rows still reading pending in the registry the gate measures. The check
cost ten minutes.

---

## 2. Row-body audit (§7.5.1 (b)) — the 18 4.J rows in scope, J17's disposition, and B4; pins read at `01a4494f1a`

Site columns are the census's C++ line pins (which predate several
re-numberings; the C++ function names are the stable handle) and the Rust
body each row calls. *Partial under L7* marks a clause the transition
already refuses at the connect fold.

**Serve-credit eligibility** (per input; H20 is the shape; the vin parse is
`ArchivalKey::of`, `rules/body.rs`):

| row | rule (short) | Rust body today | class | witness today |
| --- | --- | --- | --- | --- |
| J1 — **Slice C's, ruled 2026-10-04** (§1.2 item 1); audited here because the finding is this slice's to hand over | the vin is opaque; the codec's parse must succeed | `ArchivalKey::of` (`rules/body.rs:226`) skips an unparseable vin in G7/G9/G10 and L7 refuses it (`inputs.rs:42–46`, *"CEN-J1 will refuse it earlier; this is the backstop"*) — the row named as the earlier refusal does not exist, and the codec it names parses the R-B record Slice C re-lays | not this slice's | none (corpus credit is injected) |
| J4 | the named P has a bond record | **`implemented` 2026-10-04 (§5 row 3): `rules::tx_bond::J4`, `judge_serve_credit_bond`.** *Was at the pin:* partial under L7 (`inputs.rs:49–53`) — L7 stays as the fold's belt | `TxAgainstRule` over `bond_record` | **Landed (row 3):** the mock has no bonds by policy (`harness.rs`, `archival_reads!(empty)`), so J4 is the one of the three the rules crate witnesses on its own fixture (`tx_bond_tests.rs`: the pool slot, the listed slot, the first failing vin named, vacuous off-class); on the store a `Bond`-stubbed session's credit (`archival_write_tests`, ARW-9); on the driver *posts for a persona with no record*. *Was at the pin:* none in the corpus. **Driver, 2026-10-04 (§5 row 2):** an unbonded persona's credit is **refused today — by L7 at `validate`**, not by a J row (`scenario_archival_tests.rs`, *posts for a persona with no record*, the credit at `input: 0`); J4 at `tx_against` runs before the fold, so that pin flips L7 → J4 at row 3 — **flipped** |
| J5 | `E ≥ E_join + 1` | **`implemented` 2026-10-04 (§5 row 3): `rules::tx_bond::J5` over `serve_credit_epoch_ok`.** *Was at the pin:* `serve_eligibility::serve_credit_epoch_ok` — called by nothing in the validator | `TxAgainstRule` | **Landed (row 3):** the driver's credit at `E_join` is refused J5 at `Input { Listed(0), 0 }`; its credit at `E_join + 1` connects (`archival_admission_tests`). *Was at the pin:* none in the corpus (the injected credit is at `E_join + 1`, J5's accept). **Driver pin, 2026-10-04:** a credit **at `E_join`**, the block after the join, **connects** while `serve_credit_epoch_ok(E_join, E_join)` is `false` (`archival_admission_tests`); flips at row 3 — **flipped** |
| J6 | P `good_through` the claimed epoch | **`implemented` 2026-10-04 (§5 row 3): `rules::tx_bond::J6` over the retention crate's `good_through` and the record's `bad_intervals`.** *Was at the pin:* the retention crate's `good_through` (FFI `shekyl_archival_good_through`); the validator reads `bad_intervals` in the folds only | `TxAgainstRule` | **Landed (row 3):** inside the open interval both credits — the kept shard's and the removed shard's — are refused J6; after the Reinstate closes it, at `E_reinstate + 1`, both **connect** — the removed shard's too, which is **J8's pin now** (the shard-held predicate is Slice C's; recorded in §5 row 3). *Was at the pin:* none in the corpus. **Driver pin, 2026-10-04:** inside an open bad interval, a credit for the kept shard **and one for the shard the slash removed** both **connect** — the fold reads *a record exists* and nothing of its state (`archival_admission_tests`); flips at row 3 — **flipped** |

**Bond post** (per tx; H21 the shape; the CT balance with terms is H21's):

| row | rule (short) | Rust body today | class | witness today |
| --- | --- | --- | --- | --- |
| J11 | hybrid pubkey length canonical; `p_canonical_id` recomputes | **IMPLEMENTED 2026-10-04 — `rules::tx_inputs::J11` (§5 row 4); the mismatched-hint pin flipped to a refusal at the transaction.** *Records-was (at the pre-flight):* `p_canonical_id_from_hybrid_pubkey` — the transition **trusted the vin's hint**: `post.p_canonical_id` is a decoded wire field (`shekyl-wire/src/transaction.rs:634`), never recomputed from the `hybrid_public_key` beside it (`:632`), and the folds key the record on it (`inputs.rs:95`, `:148`, `:194`). Contrast the emission vin, whose `p` *is* recomputed at parse (`body.rs:246`) | `TxRule`, `tx_form` | corpus accept (JoinMarket; both corpus posts' hints recompute — `archival_admission_tests`' table). **Driver pin, 2026-10-04:** a join whose hint names a **stranger connects** and inserts the stranger's record carrying the signer's key; flips at row 4 |
| J12 | `bond_spend_pk` ⇔ JoinMarket | **IMPLEMENTED 2026-10-04 — `rules::tx_inputs::J12`, the length belt (§5 row 4).** *Records-was:* the decoder's shape (`WireKind::JoinMarket { bond_spend_pk, .. }` vs `Other`) carried the kind⇔presence half and still does; the *length* belt was nowhere in the validator | `TxRule`, `tx_form` | corpus accept; fixtures: the three length edits (truncated, extended, cleared) |
| J13 | debit arm (Release) authorizes with the record's committed `bond_spend_pk`; credit arms (JoinMarket, Reinstate) with `P_pubkey` | **IMPLEMENTED 2026-10-04 — `rules::tx_bond::J13`, `judge_bond_post_key` in `tx_against` ahead of `judge_signatures` (§5 row 4, Q8; the sequence became `judge_bond_post` at row 5, J13 interleaved per kind with J14/J16/J18 in the C++'s arm order); the money-form pin flipped to a refusal at the post's vin, the record untouched.** *Records-was:* `debit_auth::{cold_authority_pin, debit_auth_pin}` existed; I18 verified the slot's signature but **which key** the slot must carry was not judged | `TxAgainstRule` over `bond_record` | corpus accept (credit arm only). **Driver pin, 2026-10-04 — the finding below in its money form:** another persona's Release of a bonded record — the record's own key and id in the post, the slot signed by the **poster's** identity key — **connects**, empties the record, and H21 balances the record's collateral onto the poster's outputs (`archival_admission_tests`); flips at row 4 |
| J14 | JoinMarket semantics: shape, no debit, `credit == bonded_total == bond_floor(holdings)`, record absent | **IMPLEMENTED 2026-10-04 — `rules::tx_bond::J14` in `judge_bond_post` (§5 row 5): `verify_join_market_bond_post(vin, record_exists)` over one `bond_record` read, ahead of J13 on the JoinMarket arm as the C++ orders it (`blockchain.cpp:4619`, the identity pin after).** *Records-was:* partial under L7 (record absent, empty set) — L7 stays as the fold's belt | `TxAgainstRule` over `bond_record` | **Landed (row 5):** the rules crate's negatives at the fixture (`tx_bond_tests.rs`: a two-shard post at one floor, the empty compact set, the zero endpoint, a debit, `total + 1`, each ahead of J13 on the same mis-keyed post); the driver's two-shard join passes J14 (`judged_by`) and the same post with one floor behind it refuses on `FloorMismatch` — the negative fixture the row below asked for, built at row 5 on the driver rather than at row 4 in the rules crate, where no record-less fixture can hold two floors against one. *Was at the pin:* corpus accept — **of the multiplier's degenerate case only (measured §5 row 2, 2026-10-04):** both corpus joins bond exactly one floor (`bond-post` a complete tree, `emission-claim` a one-shard compact set), so `bond_floor_of(kind, count)` is `floor × 1` on every corpus post and a J14 that compared against the floor alone would pass the corpus. The multiplier's witness is the driver's two-shard join (`archival_admission_tests`, the levered chain) and a driven under-bonded multi-shard post is J14's negative fixture — build it as such at row 4; a green on the corpus is not coverage of a multiplier that was never greater than one (the `DoubleSpend` distribution shape, slice 7) |
| J15 | admission viability (D3/R3) over per-shard `r_market` + presence at the parent | `admission::check_admission(holdings, parent_state)`; `parent_state_shards_from_gather`; **absent** in the validator; the C++ gather is `blockchain.cpp:4640–4680`. Presence under `SHT-Q2` is *closed before the parent*, not a freeze height | `TxAgainstRule` over `r_market`, `closed_shards_before` | corpus accept (shard set) |
| J16 | Unbond: full exit, cooldown elapsed from last-served anchors, slashes settled through the anchor | **IMPLEMENTED 2026-10-04 — `rules::tx_bond::J16` in `judge_bond_post` (§5 row 5): `verify_release_bond_post` over the record, the whole-record last-served maximum (`last_served_epoch` per held shard on a compact record, `served_shards` on a complete tree — the C++'s two gathers, `blockchain.cpp:4529–4538`), `last_settled_slash_epoch`, and the connecting height's settlement epoch off the rule set; after J13's pin on the Release arm, which the C++ gates on `have_record` (`:4509`) and J16 then refuses the missing record itself.** *Records-was:* partial under L7 (`release_connect`: debit is the total) — cooldown and settlement were unjudged; L7 stays as the fold's belt | `TxAgainstRule` over `bond_record`, `last_served_epoch` / `served_shards`, `last_settled_slash_epoch`, `tip` | **Landed (row 5):** the rules crate's no-record negative under both keys (the mock has no bonds by policy); the driver: a Release with no record (J16, *was* L7's), the wrong debit over a persisted record (`DebitNotFullBalance`, *was* L7's), a Release two epochs inside the cooldown on the levered chain (`CooldownNotElapsed`, new), and the `whole` persona's release of a persisted record connecting under J13 and J16 (`judged_by`). *Was at the pin:* none |
| J17 | HoldingsUpdate add / drop arms | **no such kind exists** (`ARW-14`) | **Q1**: REJECTED → bucket 3 — **re-keyed 2026-10-04** (§5 row 1) | n/a |
| J18 | Reinstate: single open interval, headroom, credit against identity key | **IMPLEMENTED 2026-10-04 — `rules::tx_bond::J18` in `judge_bond_post` (§5 row 5): `verify_reinstate_bond_post` over the record's total, holdings kind, held shards and intervals, ahead of J13 on the Reinstate arm as the C++ orders it (`blockchain.cpp:4581`, the identity pin after).** *Records-was:* partial under L7 (`reinstate_connect`'s preconditions) — L7 stays as the fold's belt | `TxAgainstRule` over `bond_record` | **Landed (row 5):** the rules crate's no-record negative under the identity key and a stranger's (J18 ahead of J13); the driver: the Reinstate over a slashed record still connects, its two belts (no open interval; holdings changed) **moved under J18** as row 2 pinned them, a Reinstate with no record and one over a released record (J18, both *were* L7's). *Was at the pin:* none in the corpus; *no driver constructor* until 2026-10-04 — **`Persona::reinstate` lands at §5 row 2** and its positive witness connects over a slashed record, the wallet-side verify and the fold agreeing on one vin; the two belts (no open interval; holdings changed) pinned as L7's, moving under J18 at row 5 (`archival_admission_tests`) |

**Reward emission** (per tx; H22 the shape):

| row | rule (short) | Rust body today | class | witness today |
| --- | --- | --- | --- | --- |
| J19 | the vin's blob parses: claimant P, ≥ 1 epoch | `ArchivalKey::of` (`Claims { p, epochs }`); L7 refuses the unparseable and the empty (`inputs.rs:75–79`, `:259–261`) | `TxRule`, `tx_form` | corpus accept |
| J20 | the emission slot's hybrid key derives the vin's `P_canonical_id` | `p_canonical_id_from_hybrid_pubkey`; not called on this path | `TxRule`, `tx_form` | corpus accept |
| J21 | reference context as I10–I13, required with zero fee inputs | I10–I12 landed (`tx_against::{I10,I11,I12}`), **I13 pending-though-unblocked**; whether `judge_reference` runs on the emission class is to read at commit | `TxAgainstRule` (shared with 4.I) | corpus accept |
| J22 | signable hash = prefix hash with the emission vin removed; Q1 auth message re-binds | not in `signing_preimage.rs` (no emission arm); the retention crate's `emission_wire.rs` owns the Q1 message — read at commit which body the slot's hash comes from | `TxRule` or `TxAgainstRule` — decided by what the body needs | corpus accept |
| J23 | every claimed epoch has a frozen budget row; as-of-E snapshots gathered | `ChainView::budget(E)` / `r_market(s, E)` / `sigma_work(E)` return `Option`; **no caller** | `TxAgainstRule` | corpus accept |
| J24 | commit set = loud vouts in order; checked sum | `emission_wire.rs` / the retention crate's reward-commit assembly; **no caller** in the validator | `TxRule`, `tx_form` | corpus accept |
| J25 | the coarse verify: claims 1–5, backing proof, auth gate; `vout_reward_sum` is the inflation-audit operand | `emission_vin_verify_claims` / `_backing` / `_auth` / `emission_vin_verify`; partial under L7 (`claimed_epochs_check_and_set`); **the arithmetic, the backing proof and the auth gate are unjudged** — this is the row that mints coins | `TxAgainstRule`; its `total_reward` is a consumer of `judge_emission`'s accounting (read at commit whether `coins_generated` includes claims) | corpus accept |
| J26 | fee-input FCMP++ proof: absent ⇔ no fee inputs; present ⇒ verifies as I15 over the `txin_to_key` subset | the absent⇔ clause is H22's shape; the verify is **I15's body, pending** | `TxAgainstRule` (with I15) | corpus accept (zero fee inputs — the present arm has no witness) |

**The 4.B row:**

| row | rule (short) | Rust body today | class | witness today |
| --- | --- | --- | --- | --- |
| B4 | `attestation_root` equals the recompute over the (possibly empty) witness; every record's P-countersignature verifies under `SF-D8` v2 | `shekyl-archival-retention/src/attestation.rs` (the FFI `shekyl_archival_verify_attestation`'s body); `census.rs:331` pending; `rules/header.rs:8` *"B4 is deferred (E4…)"* | `BlockRule` after D1; the witness is `Candidate::attestation_witness`, E4's field (`block.rs:116`), not a new input — **Q6**, as corrected | empty-root arm: every corpus block; record arm: none |

What the audit found that the census does not say: **J11's recompute is
not run anywhere in the validator** — the transition keys the record on
the vin's `p_canonical_id` hint. Under the C++ that hint is verified first
(`blockchain.cpp:4471–4480`); under the Rust it is trusted, so a post whose
hint names another persona's record would be folded into that record. J11
is the first bond row to land for that reason (§5 row 4), and its negative
fixture is the mismatched hint.

**Measured at §5 row 2 (2026-10-04), and it has a money form.** The
mismatched hint does what the paragraph above predicted: a JoinMarket
whose hint names a stranger inserts the stranger's record carrying the
signer's key. But the hint is only the *address*; the consequence that
moves coins is J13's, not J11's. A Release whose fields are a bonded
persona's — key and id consistent, so J11's recompute **passes** — with
the slot signed by another persona's identity key, connects today: the
release fold compares the post's debit to the record's total and nothing
about who signed (`inputs.rs:140–186`), I18 verifies the slot against the
key the slot carries, and H21 balances the debit as a source — so the
victim's collateral is paid to whoever built the transaction. The pin
that refuses it exists — `cold_authority_pin`
(`shekyl-archival-retention/src/debit_auth.rs`; the slot's key against
the record's committed `bond_spend_pk`, never the identity key; index row
*Principal stake/unstake/drain lifecycle* UB3) — and has two callers: the
C++ connect path over FFI (`blockchain.cpp`, `archival_cold_authority_pin`)
and the Rust submit verifier (`shekyl-daemon-rpc/src/submit/verifier.rs`).
`shekyl-chain-rules` calls it nowhere, so under the Rust stack the pool
refuses the relayed form and **a block carrying one connects**: a
pool-only refusal of a consensus-shaped predicate, which is a miner's
option, not a rule. J11 and J13
land together at row 4 for that reason: the hint row alone would leave the
drain open to any poster who copies the victim's fields verbatim. Both
pins were in `archival_admission_tests` (*the debit follows the hint*);
**both flipped at row 4 (2026-10-04)** — the join is refused on J11 at the
transaction, the Release on J13 at the post's vin before the fold writes
(`a_post_is_keyed_by_the_recompute_and_a_release_by_the_record_key`). The
no-record Release stays L7's, as the C++ gates the pin on `have_record`.

---

## 3. Findings from the code sweep

### 3.1 The row named as "the earlier refusal" does not exist

`archival/inputs.rs:41–46` refuses an unparseable serve-credit vin under L7
with the comment *"CEN-J1 will refuse it earlier; this is the backstop."*
J1 is `pending`. The same shape at `:75–79` for the emission vin (J19). Both
are the transition correctly declining to be the rule. J19 is the row this
slice makes exist; J1 is Slice C's (§1.2 item 1, ruled 2026-10-04), so the
`:41–46` comment stays a claim about a future rule until Slice C lands it —
handed over, not made true here. Not a defect; recorded because each
comment reads as a claim about the present and is a claim about a slice.

### 3.2 J17 names a type that was REJECTED, and the census registry still counts it

`ARW-14` deleted `HoldingsUpdate` in three places and named the census rows
as this slice's to re-key. Read at the pin: J17 is a row whose every clause
is about a post kind no decoder produces and no fold applies. Two readings:

- **(a) REJECTED → bucket 3 — default.** The mechanism was rejected by
  ruling (immutable bond, 2026-09-20). Rule 23: the name stays in the
  contract marked REJECTED; zero code symbols. So the census row keeps its
  id with its rule text replaced by the disposition and a pointer, and
  `census.rs` loses `J17` — the registry is the structured contract and a
  REJECTED row has no status to carry. `validator-enforced 152 → 151`, the
  CEN-F12 precedent (census `:389`: *Deleted (E6 slice 4 Q2, ruled (a)
  2026-09-21)*).
- **(b) by-construction.** The rule "a HoldingsUpdate post is judged thus"
  is vacuously satisfied because no such post can be spelled on the wire.
  `RowStatus::ByConstruction` with the decoder as the site. Rejected as the
  default because by-construction records a *property the code delivers*
  (G3/G4/G5 in slice 7), and here there is no property, only an absence
  the ruling created — filing it as delivered would make the gate count a
  refusal that was never written.

J13's drop arm and J15's *"drops deliberately ungated"* clause are
amendments to live rows, not dispositions: the arm is struck with a
line-local records-was (rule 23). **Q1 RULED 2026-10-04: (a), bucket 3.**
H24's precedent is exact — a row whose subject was deleted is residue, not
an unrepresentable state. (b) would have kept J17 in the denominator with a
falsifier watching a decoder property that belongs to a general
unknown-kind refusal, not to J17; a deleted subject does not inflate the
denominator, so `152 → 151`.

**Landed 2026-10-04 (PR-a commit 2, #953).** What the re-key touched, and
two things it found that §3.2 had not named:

- Census: J17 → bucket 3 in CEN-F12's shape (disposition, deleting commit
  `7909719f11`, sites as records-was); J15's *"drops deliberately ungated"*
  struck. **J13 named the type twice, not once** — the drop arm on the
  debit side *and* `HU-add` on the credit side (*"HU-add auth key must
  equal `P_pubkey`"*). Both struck line-local; the rule's two key-selection
  legs stand over the kinds that remain (Unbond; JoinMarket, Reinstate).
  Row 4 implements J13 as it now reads.
- `census.rs` loses `J17` with no placeholder, as F12 left — the census row
  and `census_tests.rs`'s count history are the record; `CenRow::ALL.len()`
  `154 → 153`; the gate's `validator-enforced` `152 → 151`.
- **The conformance register carried a verdict on the deleted arms.**
  `CONSENSUS_STORE_RECONCILIATION.md` §5.4.1 had J17 CHECKED-CONFORMANT, and
  its gate refuses a register row for a rule outside bucket 1/2 — so the row
  leaves with the rule (recorded in that file's log, 2026-10-04; tally
  `126 / 2 / 5 → 125 / 2 / 5`; the grader's fixture regenerated with
  `--out`). The FOLLOWUPS row that register row pointed at — *"CEN-J17's
  dropped-shard derivation lives in the C++ marshal"* — asked for a Rust
  drop-arm verify to derive a shard the C++ no longer derives; closed as
  mooted, no successor.
- Two doc comments that named the drop arm's grace tail as a consumer
  (`view.rs` A4, `serve.rs` `ServedShard`) re-worded as records-was; J16's
  cooldown is the read's remaining consumer.
- FOLLOWUPS' shard-predicate row carries its landing (§3.4; §5 row 6) and
  an `Owner:`.

Not touched: the broader `HoldingsUpdate` prose sweep (FOLLOWUPS,
*"Propagate the immutable-bond ruling through the `HoldingsUpdate`
documentation surface"*) is the archival bond lane's and stays theirs; this
commit took only the census family `ARW-14` assigned to slice 8 and the
rows that cited it.

### 3.3 `SAR-Q6`'s question, now askable: what is `None` to admission?

`ChainView::r_market(shard, epoch)` is `Option`; the C++ marshals `0` when
the row is absent. `ARW-Q4` ruled the close writes an `RMarket` for every
closed shard, zeros included, so under the Rust store `None` has exactly
one meaning: *this epoch did not close with this shard in it* — the shard
closed after that epoch's close (or no epoch has closed). For J15, which
reads the **last settled epoch's** row per held shard:

- **Default: `None` ⇒ the shard is not admissible yet.** A shard with no
  market row at the last settled epoch is one the market has never priced;
  under `PDM-Q6` item 3 the frontier shard is non-bondable
  ([`ARCHIVAL_PRUNED_DAEMON_MODE.md`](ARCHIVAL_PRUNED_DAEMON_MODE.md)
  `:706–707`), and a shard
  that closed *after* the last settled close is in the same position with
  respect to the operand admission reads. Refusing it is the fail-closed
  reading and it composes with §3.4's predicate (a shard admission can
  price is a closed one the market has seen). The C++'s `0` would have
  *admitted* it as a zero-co-holder shard — the most attractive shard in
  the market, unpriced. That is an inheritance finding (rule 16), not a
  parity target.
- **Alternative:** `None` ⇒ `r_market = 0`, parity with the C++.

**Q4 RULED 2026-10-04: fail closed, the default.** The ruling's ground is
precedent, and it names two: the `Option` exists because `SAR-Q6` refused to
let the store collapse *absent* into *zero* precisely so admission could
decide this on merit; and `None ⇒ 0` asserts a market value nobody computed
on a consensus admission decision, which is `SPL-14`'s shape one domain
over
([`RELAY_STATE_REFERENCE_SHAPES.md`](RELAY_STATE_REFERENCE_SHAPES.md) §4 —
a missing value resolving to the permissive answer). Third site for that
defect, second time ruled against. The view's `Option` is what let the
question be asked, which is what `SAR-Q6` said it was for.

### 3.4 The closed-and-final predicate has a landed operand and no row

`SCV-6`: both gates on FOLLOWUPS `:205` dissolved by ruling; the operand is
`closed_shards_before` (`rules/miner.rs:564`, the F17 read) with
`shard_close_height` (`archival/close.rs:51`). The predicate — *bond
admission accepts only valid, closed, final shards* (RULED 2026-09-19,
[`ARCHIVAL_BOND_ADD_ADMISSION.md`](ARCHIVAL_BOND_ADD_ADMISSION.md)) — has
no census id. The row leaves three questions open, and the substrate at the
pin answers each:

- **Its site** is J15's: admission already reads one parent-state fact per
  held shard (the C++ `has_segment` bit, `blockchain.cpp:4650–4670`); this
  is that fact, defined properly.
- **Its evaluation height** is the parent's, by construction: `validate`
  judges over a `ChainView` at the parent, so the `blockchain.cpp:1478–1492`
  read-point hazard the row names — the operand read after the connecting
  block advanced the chain — cannot arise here. *Closed* is
  `shard < closed_shards_before(view, connecting)`; *final* is
  `shard_close_height(shard) ≤ parent − D_max` with `D_max` the view's
  `RuleSet::reorg_cap` (`rule_set.rs:346`); *valid* is the `ShardSet`
  constructor's cardinality and duplicate-freeness, already enforced.
- **Who owns it:** a rule, not the constructor. `ShardSet` stays the one
  chain-free fallible constructor it is (`shekyl-types/src/archival/mod.rs:362`;
  the row's `bond_wire.rs:210–227` pin predates its move); the
  chain-context check is J15's body, which is where the C++ gathers it
  too. The row's trade — one fallible constructor against a pure one —
  resolves against giving `ShardSet` chain context, because the same
  `ShardSet` is built wallet-side where there is no chain to ask.

The fixture set the row demands, both directions: a valid closed final
shard **accepted**; a ghost `shard_id` (past the frontier), the open
frontier shard, and a closed-but-not-final shard (closed within `D_max` of
the parent) each **refused**, each as J15 and not as a fold failure.

*The boundary ruling names this predicate too.* Slice C's Round 0 lists it
as its **input 4** (`ARCHIVAL_SETTLEMENT_SO_D8_PROPOSAL.md` §8.0
`:2266–2269`: *"ruled and unbuilt … It carries the job of the freeze
clause J8 loses"*). That is a claim on the predicate's *existence*, not a
second site for it: Slice C's rows need bond admission to have already
refused a shard that is not closed and final, so that a persona's holdings
can mean something at the epoch's open. The site is still J15's — the
predicate judges a bond post, and Slice C judges credits. **Default,
posed to the reviewer rather than assumed (Q5, second half):** this slice
builds it in J15 (PR-b), Slice C consumes it, and Slice C's input 4 is
discharged by `CEN-J15` reading `implemented` with the predicate clause on
its row text. Falsifier: Slice C's Round 1 minting its own `CEN-` row for
the predicate — then two rows judge one fact and one must go.

*Confirmed 2026-10-04 (maintainer): one builder, two consumers — the I17
shape.* One thing is **owed from SO-D8, not inferred here**: the
predicate's *shape* serves both consumers and only one is in view while
this slice builds it. J15 asks about a shard at a bond post, at the
parent's height; Slice C needs it to carry the job J8's freeze clause
loses — a question about a shard at the height that replaces "the fire
height" (§8.0 input 3, `:2260–2264`), read strictly above a same-block
slash as `holds_shard_at` does
(`shekyl-archival-retention/src/held_at_height.rs:97`). If those are
different signatures, J15 lands a predicate Slice C cannot call, found at
Slice C's commit 3 rather than now. **Before PR-b's row 6 lands J15, SO-D8
names the signature Slice C will call** — a sentence in §8.0, nothing
more. The shape this slice proposes to offer: `fn closed_and_final(view:
&ChainView, shard: ShardId, at: BlockHeight) -> bool`, the height a
parameter and the two call sites passing their own — the parent for J15,
input 3's height for Slice C — so the predicate itself reads nothing that
only one caller has.

**Q5 RULED 2026-10-04: the default — one builder, two consumers — and the
paragraph above is what makes it safe.** The ruling adds to what is owed:
SO-D8's sentence names the height ***semantics*** as well as the
signature. "Input 3's height" is unambiguous to whoever wrote input 3 and
not to whoever implements J15, so the sentence says what `at` *is* for
Slice C's call — which block's view, and on which side of a same-block
slash it reads — in terms J15's implementer can test without reading
SO-D8 §8.0. PR-b's row 6 does not land until that sentence exists.

**Asked of SO-D8, 2026-10-05 (row 6 open and idle on it; carried by the
maintainer, as PDM's Q3 was).** One sentence in §8.0 input 4, confirming
or refusing: (1) the signature `fn closed_and_final(view: &ChainView,
shard: ShardId, at: BlockHeight) -> bool` — the height a parameter, the
predicate reading nothing only one caller has; (2) what `at` *is* for
Slice C's call, in J15's implementer's terms: **which block's view** (the
seal block, the height that replaces the fire height, the connecting
block) and **which side of a same-block slash** it reads — strictly above,
as `holds_shard_at` does (`held_at_height.rs:97`), or not. J15's own call
passes the parent's height and reads the pre-block view; if Slice C's
reads the same side, one body serves both and row 6's *operand retry* leg
stays at 0; if it reads the other, the predicate takes the side as a
second parameter and the leg is 1 (§5.1 row 6). This is the surface where
E4 landed three one-apart defects, so the answer is wanted as a sentence
J15's test can be written against, not as a pointer to input 3.

- **Default: amend CEN-J15's row text** to carry the predicate as its
  first clause, with the three answers above recorded on the row; no new
  `CEN-` id. The census is the registry of consensus rules, and a rule's
  text changing by ruling is recorded on the rule.
- **Alternative: mint `CEN-J27`** for it, so the predicate has its own
  coverage bit. Not a new family (rule 94 §1 is about prefixes); it is a
  new row in 4.J, which SO-D8 §8 also plans to add to at Slice C.

**Q5** rules it. Either way the FOLLOWUPS row closes with this slice.

### 3.5 CEN-B4's witness is a sidecar — and `validate` already has its door

**Premise refuted 2026-10-04 (review on #947, read at source).** The
paragraph below was written as *"`validate(block, …)` today takes the
block, the view, the rule set and the trust anchors; nothing carries a
witness"*, and that was false at the pin: `Candidate` has carried
`attestation_witness: Option<AttestationWitness>` since DRS-E4 commit 5
(`shekyl-chain-rules/src/block.rs:116`, `with_attestation_witness`
`:136`), `validate` receives the candidate through `StructurallyValid`,
the verdict carries the field into `ValidatedBlock`, and the store writes
it (`shekyl-chain-store/src/store/connect.rs:291`). The pre-flight read
`validate`'s signature and not its argument's type — rule 16's
*documentation is not verification*, applied to my own sentence. A second
witness argument would have made two independent values, one judged and
one persisted. **The door is the existing field; nothing is added to
`validate`.** The three shapes as posed are kept as records-was beneath
the correction, since the ruling fell on them.

The attestation witness is not block bytes (`block_complete_entry::
attestation_witness`, `KV_SERIALIZE_OPT`). The C++ passes
`connect.attestation_witness` into `verify_block_attestation`
(`blockchain.cpp:2243`, `:5304`). Three shapes, as posed (records-was):

- **Default: a `Witness` parameter on `validate`** — `Option<&[u8]>` or a
  typed wrapper, `None` meaning the empty set (the only valid value
  pre-population: `ARCHIVAL_CREDIT_WIRE.md:214–223`). The ingest passes
  what the sync wire delivered; the RPC-edge capture passes `None`, which
  is correct for every corpus block (FOLLOWUPS `:181`, second row). The
  recompute over `None` must equal the header's root on every corpus
  block, or B4 refuses the corpus — which is the empty-root arm's test.
- **(b)** carry the witness inside the block type the validator takes. Rule
  42 says no: the witness is not persisted block bytes and the hash
  excludes it.
- **(c)** land the empty-root arm only and leave the record arm with its
  producer. Rejected as the default: the verify body is landed Rust, the
  census row is ratified in full, E4 §2.2 already says the record arm is
  *"tested by a scenario that supplies a witness, since no corpus has
  one"*, and `SCV-Q4`'s default leaves B4's record arm as *B4's owner's to
  re-key* — a future re-key is not a reason to leave a landed verifier
  uncalled.

**Q6 RULED 2026-10-04: the default's door, with its value amended** — the
amendment as written: `Option<WitnessSet>`, `None` = *not supplied*,
`Some(empty)` = *none exist*, B4 **vacuous** on `None` and the
coverage-gaps component recording it, because `/get_blocks_by_height.bin`
never populates the sidecar (FOLLOWUPS `:184`) and the default's `None`
*as the empty set* conflated the two.

**The amendment's mechanism was refuted at source the same day** (review
on #947; three findings, each checked):

1. *Vacuous and a gap are exclusive in this crate.* A vacuous row is one
   `run_tx` **inserts into coverage** with its predicate trivially satisfied
   (`rules/mod.rs:328`, `validate.rs:507`); the store's gap is the set of
   enforced rows **absent** from coverage
   (`shekyl-chain-store/src/store/connect.rs:240–246`); and
   `ChainValid::mint` panics when an `Implemented` enforced row is absent
   (`verdict.rs:84–95`, G9). A B4 that is `implemented` and skipped on
   `None` would not reach the store to be recorded — it would panic at
   mint. The state the amendment named cannot exist.
2. *`Some(empty)` is unrepresentable.* `AttestationWitness` is non-empty by
   construction — *"an empty attestation set is no witness —
   `Option<AttestationWitness>::None` — never an empty one"*
   (`shekyl-types/src/archival/mod.rs:255–267`, `AttestationWitnessError::
   Empty`), matching the daemon store's rule that an empty witness is no
   row. The tri-state has no third value to hold.
3. *The header already arbitrates "not supplied" from "none exist".* B4's
   first clause is `attestation_root == recompute(witness)`. The empty-set
   root is a fixed value (`attestation_wire.rs:186`
   `empty_attestation_root`; the FFI's
   `empty_block_verifies_against_empty_root`,
   `attestation_verify_tests.rs:220`), and the C++ passes an absent witness
   as the empty one (`blockchain.cpp:5210`, `witness.empty() ? nullptr`).
   So on `None`: a header committing to the empty set **passes** — the
   set is empty whatever the carrier did, by the root's binding; a
   header committing to a non-empty set **refuses** — a block whose
   sidecar was not supplied cannot be judged and fails closed, which is the
   consensus answer (the sync wire carries the sidecar; a node without it
   has not seen the block). The conflation the ruling refused is real in
   the *carrier* and dissolved by the *rule*.

**Corrected disposition — RULED 2026-10-04 (maintainer, the mechanical
facts verified at `dev@638f4999f7`; the amendment's intent — never
conflate the two, never let an unjudged witness read as evidence — is
kept whole; its mechanism is replaced):** B4 judges
the one value, `Candidate::attestation_witness`, as E4 laid it; it is
**always evaluated** and always in coverage; `None` is judged as the
empty preimage against the header's `attestation_root`; `Some(w)` is the
recompute and every record's P-countersignature. Nothing is added to
`validate`'s signature and no type is minted. At row 10 every *"carried
unjudged / B4's coverage gap"* claim retires because the condition it
describes ends — seven sites, enumerated in §5 row 10 as a checklist
rather than described (a sweep at `638f4999f7` found seven where this
paragraph had first named three). The store's generic gap-widening
(`connect.rs:238–246`) is **not** among them: it records every unlanded
row, and after row 10 it simply stops containing B4.
Consequences for §5 row 10: the empty-root arm **is** tested by the
corpus (every corpus block is `None` with the empty root — a judged pass,
not a vacuous one); the record arm and the *non-empty root, nothing
supplied* refusal are the driver's; corpus parity on B4 is a parity of
verdicts, and a file whose witnesses were judged is evidence again. The
carrier question (`SCV-Q4`) is not this slice's.

Why the corrected mechanism is the stronger one, in the ruling's words:
the header's root is what distinguishes *none exist* from *not
supplied*, and it is **consensus-bound rather than transport-bound** — a
block claiming a non-empty root with no witness fails on a value the
block commits to, not on a parameter's shape, which is exactly the case
the dropped RPC sidecar was feared to smuggle through.

**The mechanism of the error, recorded once** (maintainer, 2026-10-04):
*"I read `validate`'s signature and not its argument's type, then
proposed a door for a value that was already inside the room."* The
amendment proposed a tri-state whose third state the type forbids in the
doc comment immediately above the struct (`archival/mod.rs:257–259`),
and combined two words — *vacuous*, *gap* — that `verdict.rs:87–95` with
`rules/mod.rs:328` make mechanically exclusive. Same shape as calling for
a `BlockHeight` newtype that `block_axis` had already built: a
recommendation derived from a negative result nobody had checked, where
the thing proposed existed and the comment beside it said so.

### 3.6 Two 4.I rows a week past their blocker, and the two 4.J rows that need them

§1.2 item 2 and §1.3 carry the finding. Added here only: FOLLOWUPS `:787`
already writes I15's commit — *one commit in `judge_reference` beside I12*
with the `shekyl-fcmp` dependency *as daemon-rpc's K12 takes it* — and
J25's membership-only backing proof and J26's fee-input proof take the same
dependency. Three consumers of one edge. If Q2's default holds, that edge
is cut once, in this slice's emission wave, and I15's `judge_reference`
site gets its consumer as its row foresaw. If not, the slice leaves two
emission rows with a proof clause pointing at a row three slices old.

### 3.7 The corpus is a regression gate here, not a parity oracle

Slice 7's G6 landed at parity because the C++ and the Rust computed the
same number over the same captured blocks. Nothing in this slice has that
shape: the rows are refusals, the corpus has no refused block, and the
C++ gate for serve credits checks a retired preimage (`ARW-13`). What the
two corpus shapes give is the other direction — every rule this slice lands
must *not* refuse `bond-post` or `emission-claim`, and the replay at digest
parity is the test that says so. A row that turns a corpus block red is the
slice's finding of the day, in one of two ways: the Rust rule is wrong, or
the C++ accepted something the census says it should not have (the slice-7
§3.11 shape). Both are findings; neither is a fixture to loosen.

---

## 4. Stage placement — ruled 2026-10-04 (Q2, Q6, Q8 as written below)

- **`tx_form`** (stateless, `TxRule`): J11, J12, J19, J20, J24, and
  J22 if its body reads only bytes. After the 4.H shape arms (a malformed
  bond post is H21's, not J11's — `tx_inputs.rs:9–13`'s rule), beside J2.
- **`tx_against`** (`TxAgainstRule`): J4, J5, J6 (bond state, read on the
  serve-credit vin); J13, J14,
  J15, J16, J18 (bond post); J21, J23, J25, J26 (emission). After I7 and
  `judge_reference`, before `judge_signatures` — the C++'s
  `check_tx_inputs` order (the archival arms sit between the key-image walk
  and the PQC verify). J13 runs ahead of `judge_signatures` by ruling
  (Q8): a wrong-key post refuses as J13, not as a bad signature — the
  reasoning that put G1 before the slot loop, and it forecloses the
  mis-keying `WrongReward` demonstrated. I13 and I15 in `judge_reference`
  (Q2, ruled yes).
- **`validate`** (`BlockRule`): B4 after D1, before the slot loop, over
  `Candidate::attestation_witness` (Q6 as corrected, §3.5); always
  evaluated — `None` is the empty preimage against the header root.
- **The transition** is untouched: L7 keeps every fold refusal it has.

---

## 5. Commit plan — Round 0, ruled 2026-10-04

The rows below are as posed, with each ruling written into the row it
changes (rows 1, 6, 7, 9, 10) rather than restated beneath the table.

| # | commit | gate |
| --- | --- | --- |
| 1 | **This file on review; the index rows; §5.1; the `ARW-14` census re-key** — J17 REJECTED → bucket 3 (Q1 (a), ruled), J13's drop arm and J15's ungated-drops clause struck line-local; `census.rs` loses `J17`; FOLLOWUPS `:205` noted as landing here (§3.4) — the `:197` re-point to Slice C already landed with the pre-flight PR (§1.2 item 1); the DRS-E6 row. **Lands before any rule**, so the completeness gate measures the rules against rows that describe something that exists. **LANDED 2026-10-04 — PR-a commit 2 (PR #953); §3.2 records what it touched, including two sites the row had not named (J13's `HU-add` leg; the register's J17 verdict and the FOLLOWUPS row it carried)** | docs gates; the coverage gate's denominator moves `152 → 151` — **measured: `validator-enforced 151`, `CenRow::ALL.len() == 153`, register `125 / 2 / 5`** |
| 2 | **Driver measurements, no rules.** (a) The two corpus shapes: what each block's archival inputs are, read off the replay, so the positive witnesses are enumerated rather than assumed; (b) `Persona::reinstate` and a Release that the driver *validates* (today it only constructs); (c) a serve credit from an unbonded persona and one at `E_join` through `mine_listing` — both connect today, pinned to flip at row 3; (d) the J11 mismatched-hint post — connects today (§2's finding), pinned to flip at row 4. **LANDED 2026-10-04 — PR-a commits 3–4 (PR #953); `archival_admission_tests.rs`, `Persona::{reinstate, reinstate_vin, release_post}`.** Two premises in the row were stale at the pin and are corrected here, the posed text kept above: (b) *"a Release that the driver validates (today it only constructs)"* — a Release has reached `validate` and connected since DRS-E4 commit 5 (`scenario_archival_tests.rs`, the `whole` persona's release); what the driver had never made was the Reinstate, which now connects over a slashed record on a levered chain (SEB 20, cap 10; the slash at height 319 as the schedule names it). (c) *"a serve credit from an unbonded persona … connects today"* — it is **refused** today, by L7 at `validate` (`scenario_archival_tests.rs:429`); the row-3 flip there is L7 → J4, not connect → refuse. The credit at `E_join` connects as the row said. Found beyond the row's text: (c) J6's pin — credits inside an open interval, one for a shard no longer held, connect; (d) **the money form of the hint finding** — another persona's Release of a bonded record, signed by its own key, connects and takes the collateral (§2, the paragraph after the tables; J11 and J13 land together at row 4 for it); (a) the corpus's two joins carry the same one-floor bond (a complete tree and a one-shard set), so the corpus cannot tell a per-shard floor from a flat one — J14's multiplier witness is the driver's two-shard join | the pins — **three tests, 27 s**: the corpus table (both directions, six chains); the levered reinstate chain (J5, J6, the Reinstate and its two L7 belts); the hint chain (J11, J13) |
| 3 | **J4, J5, J6** — the bond-state rows on the serve-credit vin: the named persona has a bond record (`bond_record`), the claimed epoch is `≥ E_first` (join epoch + 1), and the persona is `good_through` it. Three `TxAgainstRule`s over one view read, each with its negative fixture on a driven chain (an unbonded persona; a credit for the join epoch; a persona past its `good_through`). Named by what they check — they touch no credit, no preimage, no window; J1's parse and J7's window are Slice C's (§1.2 item 1). **LANDED 2026-10-04 — PR-a commits 6–7 (PR #953); `rules/tx_bond.rs`, `judge_serve_credit_bond` between `judge_reference` and `judge_signatures` in `validate::tx_against`, one `bond_record` read per serve-credit vin, J4 → J5 → J6 in the C++'s order (`blockchain.cpp`, the serve-credit arm of `check_tx_inputs`).** Found at the fixtures, before the rule: the C++ judges bond state against the DB **before the block**, and the Rust fold (L7's arm, `archival/inputs.rs:40–61`, whose `post` read sees the block's own joins) had been admitting a join and a credit for that persona **in the same block** — the rules crate's serve-credit fixtures, the store's `credited` chain and the driver's join scenario all leaned on that admission, and all three had to move before J4 could run (commit 6, fixtures; commit 7, the rule — the two-commit shape is the scope split, §5.1). Row 2's measurement did not see it: it enumerated what the driver *produces* and never asked what the validator *reads against* — rule 16's direction variant, the producer-ward heading, one slice after slice 6 failed it consumer-ward. Naming the variant had not prevented it: the rule's entry described slice 6's instance rather than the axis, so a measurement with the mirror case in hand had no question to fail. The entry is reshaped in this PR (the axis first — *every sweep states which way it ran and what the other heading would have enumerated* — each heading an instance under it). Two things recorded forward. **For Slice C (J7):** the C++ arm requires the credited epoch's seal to be on chain (`shekyl_archival_challenge_seal_on_chain(h_open, current_height)`, `blockchain.cpp:4846`) — the fixtures now credit `E_join + 1` on chains still inside `E_join`, which J4–J6 accept and J7 will refuse; when J7 lands every chain that carries a credit advances past the credited epoch's seal height first, and that is fixture work priced to Slice C, not a finding against these rows. **J8's pin:** after the Reinstate closes the interval, a credit for the shard the slash **removed** connects (`archival_admission_tests`) — J6 reads the record's intervals, not its shard set; the shard-held predicate is Slice C's by ruling. Harness: `TxShape::reads_bond_state` replaces `precedents()` — the sanity gate judges a bond-reading shape through `tx_form` and stops, since the mock has no bonds by policy; `valid_at` for the archival shapes is `Lone` and `Listed(0)` only | corpus parity holds — **held** (the six corpus chains connect under J4–J6: no corpus block carries a serve-credit vin, §1.2) |
| 4 | **J11, J12, J13** — the bond-post statics and the key-selection rule; J11's fixture is the mismatched hint, J13's a Release whose slot carries `P_pubkey`. **LANDED 2026-10-04 — PR-a commits 9–10 (PR #953); J11, J12 as `TxRule`s in `rules/tx_inputs.rs` beside J2 (`tx_form`'s last band); J13 as `judge_bond_post_key` in `rules/tx_bond.rs` (renamed `judge_bond_post` at row 5, when J14/J16/J18 joined it), called in `validate::tx_against` between `judge_serve_credit_bond` and `judge_signatures` (Q8) — the credit arms compare the slot's key to the post's identity key, the debit arm calls `cold_authority_pin` over the view's record. A Release with **no record** passes J13 — and that is not a hole: the C++ gates the pin on `have_record` (`blockchain.cpp:4508`) and the missing record refuses one row later — as L7 at this row, as **J16** since row 5 (`scenario_archival_tests`, the unbonded persona); J13 declines to judge a key against a record that isn't there rather than inventing a verdict for it. An unnamed kind is CEN-L7 in `judge_bond_post` since the row-5 review: the sequence and the fold share `BondArm`, and a kind no arm names is refused at the post's vin before any post row is recorded. The fold's arm stays the belt. The pin is the retention crate's one function, now called from the judge as well as from the C++ connect and the submit pool — a belt becoming a rule, not a second copy.** Found at the fixtures, before the rule (commit 9): every bond-post fixture in the rules crate carried an empty or arbitrary `hybrid_public_key` with a hint that recomputed from nothing — honest under a validator that trusted the hint, a J11 refusal under one that does not; `fixture::persona` gives the fixtures a derived identity, a bond-spend key and the recompute, and `signed()` selects the bond slot's seed by the key the slot carries, so the Release fixtures sign with the bond-spend key as a live persona would. Both driver pins flipped: the stranger's join refuses on J11 at `Locus::Tx`, the other persona's Release on J13 at the post's vin, and `bonded`'s record is untouched after it. Gate `implemented 100 → 103 / 151` | corpus parity (both corpus joins recompute and sign with their identity keys); the rules crate's negatives at both sites; the driver's two flipped pins |
| 5 | **J14, J16, J18** — the three kind verifies as callers of the retention crate's bodies; J16's cooldown operands off `last_served_epoch` / `last_settled_slash_epoch`; J18 over the driver's new Reinstate. **LANDED 2026-10-04 — PR-a commit 13 (PR #953); `judge_bond_post_key` becomes `judge_bond_post` in `rules/tx_bond.rs`, one sequence per bond-post vin in the C++'s per-kind order (`blockchain.cpp`, the bond arm of `check_tx_inputs`): JoinMarket J14 → J13 (`:4619`, the pin at `:4693`); Release J13 gated on the record → J16 (`:4509`, `:4542`); Reinstate J18 → J13 (`:4581`, the pin at `:4607`); an unnamed kind is CEN-L7 in this sequence, at the post's vin (the row-5 review: `BondArm` is the classifier the fold uses too, so the two cannot disagree; the fold's arm stays the belt). J16's operands: the whole-record last-served maximum over `last_served_epoch` (compact) or `served_shards` (complete tree), `last_settled_slash_epoch`, and the connecting height's epoch off `rule_set.settlement_schedule()` — the first transaction rule to read a parameter off the rule set (`tx_against` itself only compares it to the formed one). `retention_vin` (wire post → `ArchivalBondPostVin`) is the rules crate's; the submit verifier's `retention_vin` (`shekyl-daemon-rpc/src/submit/verifier.rs`) is a different function — it takes a caller-supplied kind and a separate `bond_spend_pk`, and does not classify the post — and it is the one that deletes when the pool adopts `tx_against` (`CHAIN_RULES_CRATE.md` §1's pool decorator), named there and here, and on a `FOLLOWUPS.md` row (added on review, 2026-10-05) whose falsifier is the duplicate's absence once the pool calls `tx_against` — a duplicate disclosed only in a doc comment survives the event meant to delete it unless something sweeps. Gate `implemented 103 → 106 / 151`.** Found at the pins, after the rule: the driver's join-and-release-in-one-block test and the mutation family's `DuplicateBondPost` both read *"G10 runs before the transition"* as *G10 refuses the pair*. It does run before the transition — and the slot loop runs before G10, so with J16 in it the release reads the view before the block, finds no record, and refuses `RecordMissing` a pass ahead of G10. The C++ has the same order (`check_tx_inputs` per body at `:5643`, the block's duplicate-post pass at `:5805`), so the pair never reached G10 there either: a sentence true of the design and false of both implementations (rule 16's corollary, in the test corpus). G10's witnesses are re-derived as two posts that each pass the slot loop alone — two joins for one `P` (`join_body` twinned in the mutation family; the driver's second block) — and the pair is pinned as J16's with the posed text kept as records-was. The two tests were green at row 4 because nothing then in the slot loop read the bond state of a Release | corpus parity for J16 and J18's shapes — **held, vacuously** (no corpus block carries a Release or a Reinstate, §1.2); **J14's corpus witness is misleading, not absent** (§2 J14 row): both corpus joins bond one floor, so a J14 comparing against the bare floor passes the corpus with the multiplier at 1 — the row's witness is the driver's two-shard join, a multi-floor post built deliberately, and the row does not land green over the corpus alone — **built:** the two-shard join passes J14 and its one-floor twin refuses (`scenario_archival_tests`) |
| 6 | **J15** with the closed-and-final predicate (Q5, ruled: built here, `closed_and_final(view, shard, at)` with the height a parameter) and `None` not admissible (Q4, ruled: fail closed); `parent_state_shards_from_gather` over `r_market` and `closed_shards_before`. **Does not land until SO-D8 §8.0 names the signature and the height semantics Slice C will call** (§3.4) | corpus parity; FOLLOWUPS `:205` closes; the SO-D8 sentence exists |
| 7 | **The driver's emission claim** (Q3, ruled with a condition): membership-only backing proof + dual auth over the Q1 message, as the engine handler does it; one claim `validate` admits, pinned; **and a test that the driver's assembly and the engine's emit identical bytes for one shape** — the I17 hazard is a driver whose claim differs from the engine's testing a transaction the wallet never produces. The trigger recorded in §6: a third re-made assembly makes extraction the answer | the pin; the byte-identity test |
| 8 | **J19, J20, J22, J24** — the emission statics | corpus parity |
| 9 | **J21, J23, J25, J26 + I13, I15** (Q2, ruled yes) — the reference context, the budget rows and the coarse verify, the backing and fee-input proofs; `shekyl-fcmp` into the crate; `vout_reward_sum` wired to its consumer | corpus parity; `4.I 18 + 2 = 20 / 20` |
| 10 | **B4** over `Candidate::attestation_witness` (Q6 as corrected and RULED, §3.5): `None` judged as the empty preimage against the header's `attestation_root`, `Some(w)` the recompute and every record's P-countersignature; always in coverage. **Retires, by site** (the checklist, enumerated by `rg 'unjudged|B4' --type rust` at `638f4999f7`; a site that survives is the defect): (1) `connect.rs:288–290`, the comment *written unjudged until CEN-B4 lands … records B4 as a coverage gap* — the `record_attestation_witness` call under it stays, it is the persist; (2) `block.rs:112–115`, `Candidate::attestation_witness`'s *until B4 lands … unjudged … under B4's coverage gap*; (3) `block.rs:388–393`, `ValidatedBlock`'s field doc, same claim; (4) `block.rs:468–469`, the accessor's *unjudged (the field's docs)*; (5) `archival/mod.rs:262–265`, `AttestationWitness`'s *until that row lands in `validate` … recorded under a coverage gap, not judged*; (6) `archival_write_tests.rs:324–325`, the phase-5 test's *written unjudged (CEN-B4's gap)* — the test's subject (written at height, popped with the block) stays; (7) `rules/header.rs:8`, *B4 is deferred (E4 S-ARCH)*. **Not retired:** `connect.rs:238–246`, the generic `CoverageGaps::of(enforced ∖ coverage)` widening — it is every unlanded row's record (Slice C's, each 4.J row until it lands), not B4's; after this row it simply no longer contains B4. The corpus is the empty-root arm (every block `None`, empty root — a judged pass); the driver supplies the record arm and the *non-empty root, nothing supplied* refusal. **Ruled at PR-a commit 1, implemented here in PR-c** — both PR bodies carry that line | corpus parity (B4 judged on every corpus block); the two driven fixtures; `rg 'unjudged' --type rust` over the three crates returns nothing B4's |
| 11 | **Docs** (rule 91): census 4.J and B4 re-pinned with `Rust (E6 slice 8 row n, date)` clauses; crate contract §4.6 (B4's reading of `None` — the empty preimage, arbitrated by the header root — and the Q3 extraction trigger, so both outlive this file); DRS-E6 row; index; FOLLOWUPS (`:205`, `:783`, `:787` removed); CHANGELOG (consensus-relevant: the validator now refuses what it admitted) | docs gates |

Eleven rows is past the ten-commit ceiling before the overrun; the slice
lands as **three PRs** in dependency order — **PR-a** rows 1–3 (docs,
driver, the bond-state rows), **PR-b** rows 4–6 (the bond post),
**PR-c** rows 7–11 (the emission, B4, docs) — the E4 PR-a / PR-b shape.
**Ruled 2026-10-04 (Q7): three, and the sequencing is the load-bearing
half.** Each lands on `dev` before the next opens — a *sequence*, not a
stack: no re-target, no base-branch diff, none of #877/#880's mechanics.
Twelve commits in a second PR is how slice 6 became unreviewable. Each
PR's record is stated in the row when it lands.

**Found 2026-10-05, at row 6's open: #953 (PR-a) carries rows 1–5, sixteen
commits, with its body's scope line still reading rows 1–3.** Rows 4 and 5
went onto PR-a's branch after row 3 landed, each reviewed and pushed under
the per-commit authorization, and the split above was neither re-ruled nor
named as deviated from — the reader who found it was the one row 6's
precondition sent back to Q7. The facts the ruling turned on are now the
other way round: the sequence was to keep any PR under the ceiling, and
the first PR is the one past it. **RULED 2026-10-05 (maintainer): (a) — #953 lands as rows 1–5.** The
split's purpose was reviewability; every commit was reviewed as it landed
and the tip clone-verified, so re-opening rows 4–5 as PR-b would
re-review sixteen commits to restore a shape whose whole point was
avoiding a sixteen-commit review — the remedy costs more than the drift
and buys a reviewer nothing they do not have. PR-b is now row 6 alone
(or the reorder below); PR-c unchanged. **Recorded as what it is, not as
"the plan changed": the ruling held for one PR and then stopped being
applied.** Q7 was a decision made for a stated reason; rows 4 and 5
went onto PR-a without anyone re-ruling it, and the body said rows 1–3
for two rows' worth of commits. The failure was not the scope — it was
that nothing checked the branch against the ruling, the same class as a
PR body lagging its branch, one level up. The check that was missing is
now rule 26 A4's: *a PR whose scope was ruled carries the ruling's row
range in its body, and a commit that lands outside that range updates
the line or re-rules the split.* #953's scope line reads rows 1–5 with
this ruling and its reason, so the next reader does not find a three-row
ruling and a five-row PR with nothing connecting them.

**Reorder, proposed 2026-10-05 for the maintainer's word (Q7's sequence
kept; the order inside it moves).** Row 6 waits on SO-D8's sentence
(§3.4) and nothing in rows 7–10 reads J15 or the predicate: the emission
rows judge coinbase outputs and the budget, B4 judges the header's
witness. So PR-b = rows 7–10 with their docs (estimate 2 + 1 + 3 + 2 + 1
= 9 commits, under the ceiling), and PR-c = row 6 with its docs
(FOLLOWUPS `:205` moves from row 11's list to row 6's), opening when
the sentence exists. Nothing is lost by waiting for the word: PR-b cannot
open until #953 is on `dev`. Falsifier for the independence claim: a
row-7–10 test that needs a persona's holdings to mean something — none is
in §5's text; one found at commit reopens this.

**A ruling that spans the split is named in both bodies.** Q6's ruling
lands at PR-a commit 1; its implementation is row 10, in PR-c. A reader
of PR-a finds a ruling about B4's witness arm and no B4 code; a reader of
PR-c finds the code with its ruling two PRs back. One line in each body —
*Q6 ruled at PR-a commit 1, implemented at PR-c row 10* — closes the gap,
the same reasoning as the body-matches-branch habit (2026-10-03).

### 5.1 The expectation, written at commit 1 (2026-10-03, before commit 2)

Commit counts and coverage are written now, before any measurement, so the
overrun signal has a subject. No per-connect budget is set here: the rows
are predicate evaluations over single reads, and the one fold with a cost —
J15's per-shard gather — is bounded by the shard set's cardinality cap and
priced by the admission crate already.

| row | lands | cost | why that number |
| --- | --- | --- | --- |
| 1 | this file; index; re-key; FOLLOWUPS re-points | 1 | — |
| 2 | four measurements, no rules | **2** | two of the four are driver capabilities the driver has never had (Reinstate; a Release that reaches `validate`), and the first attempt at each has cost a commit (slice 6 §5.3.3, slice 7 §5.1 row 2). **Measured 2026-10-04: 2, for a different reason.** One of the two capabilities already existed (the Release; §5 row 2's correction), and the Reinstate connected on its first run — the retention crate's own `ArchivalBondPostVin::reinstate` is the constructor, so there was no assembly to get wrong. The two commits are the driver's capability and the measurements that use it, a scope split; the retry the estimate priced did not happen |
| 3 | J4, J5, J6 | 1 | three callers of landed bodies over one read. **Measured 2026-10-04: 2, by scope split, not by retry.** The rule was the one commit the estimate priced; the other was the fixtures — three crates' serve-credit fixtures had been built on the fold's same-block admission the rule refutes (§5 row 3's finding), and moving them is its own commit so the rule's diff reads as the rule. The estimate priced the callers and not the fixtures that would have to stop lying to them; the next row with a view-read rule prices both |
| 4 | J11, J12, J13 | 1 | statics plus one record read. **Measured 2026-10-04: 2, by scope split — the same split as row 3.** The rules crate's bond-post fixtures were built on the hint the rule refutes (empty keys, hints recomputing from nothing), so they moved first and the rules landed second. Row 3's note priced this (*"the next row with a view-read rule prices both"*) and the estimate above was written before it; the row after this one that lands over a view read starts at 2 |
| 5 | J14, J16, J18 | **2** | J16's cooldown has three operands and the C++ gather is the slice's most-marshalled site (`blockchain.cpp:4520–4600`); the second commit is the one that finds the operand the first missed. **Re-priced 2026-10-04, before the row begins, with its legs named** (rows 3 and 4 both landed 2 on a fixture leg the estimate had not priced, so a third miss by the same cause would be a pattern unmeasured): *rule* 1 — the three callers; *operand retry* 1 — J16's; *fixtures* **0, assumed** — `fixture::persona` (row 4, commit 9) already gives every bond post a derived key and a floor-balanced credit, which is what J14 reads, and J18's Reinstate is the driver's levered chain (row 2), already connecting; *callers* 0 — the rows are leaves. If the row lands at 3, the fixture assumption is the finding and the note here is what it is measured against. **Measured 2026-10-04: 1 — against the legs:** *rule* 1 (the three callers landed as one sequence); *operand retry* 0 (J16's three operands were right first time — the two last-served gathers were read off the C++ before the rule, not after); *fixtures* 0 — the assumption **held**: `fixture::persona`'s floor-balanced posts carried J14, the driver's levered Reinstate carried J18, and the one new fixture (the under-bonded two-shard join) is a driver post, not a rules-crate shape. What the row found was in the *pins*, a leg the estimate did not name: two G10 witnesses that assumed a block-level row ran before the slot loop (§5 row 5), re-derived in the same commit; the pin leg is priced at 0 here because it cost no commit, and the next row with a block-level neighbour (B4, G10 itself) prices it |
| 6 | J15 + predicate | **2** | a new rule (the predicate) plus an unimplemented old one (admission), on a question (Q4) with a non-parity default — the fixture set must fail in both directions. **Legs named 2026-10-05, before the row begins and before SO-D8's sentence exists** (row 5 measured 1 against named legs and found its miss in a leg nobody priced, so every row from here carries four): *rule* 1 — the predicate and its J15 caller; *operand retry* 0, assumed — `r_market` and `closed_shards_before` are landed view arms (`view.rs:454`, `rules/miner.rs`) read by `scan_slashes` already, so the gather is a second caller of two reads, not a first; *fixtures* 1 — Q4's non-parity default means the rules crate's `MockView` grows `r_market` arms it has never carried (`archival_reads!(empty)` today) and the set must red in both directions; *pins* **0, assumed** — J15's block-level neighbour is none (it judges a vin in the slot loop) and the driver's row-2 pin (a join onto an unclosed shard connects today) is the one this row flips. The leg SO-D8's sentence can move is *operand retry*: a height semantics other than the parent's for Slice C's call does not change J15's cost; a signature that reads something only Slice C has does, by one |
| 7 | the driver's emission claim | **2** | a membership-only prover call and a dual auth the driver has never made; the engine's half lives in a handler, not a crate. Q3's byte-identity test is inside this estimate, not added to it: it is the first thing the second commit runs, and a mismatch is the finding the second commit exists for |
| 8 | J19, J20, J22, J24 | 1 | statics; J22's body located at commit |
| 9 | J21, J23, J25, J26 (+ I13, I15) | **3** | the `shekyl-fcmp` edge, I15 in `judge_reference`, then the emission rows over it; J25 is the row that mints coins and gets the fixture set a minting row deserves |
| 10 | B4 | **2** | the estimate stands with its reason replaced (Q6 as corrected, §3.5): no new parameter — the rule reads a field `validate` already receives — but the seven-site retirement in §5 row 10 touches three crates, and the first commit is that retirement with the rule; the second is the driven fixtures, the record arm and the *non-empty root, nothing supplied* refusal, which no corpus block exercises |
| 11 | docs | 1 | — |

**Expectation: eighteen commits**, across three PRs (the sixteen-commit
branch closed when Q2 ruled yes). Registry, as the sum §1.2 item 2 derives
from its row table and not as a figure of its own:
`implemented 97 + 18 + 1 + 2 = 118`, `validator-enforced 152 − 1 = 151`
(Q1 (a), ruled); `4.J 1 + 18 = 19 / 25`; `4.B 5 + 1 = 6 / 7`;
`4.I 18 + 2 = 20 / 20` (Q2, ruled). **The signal:** more than **twenty-two** means the substrate was not
what this document claims. Slice 7 missed by 20 % with corpus witnesses for
its rows; this slice has none for its refusals, so the signal is set at the
slice-7 ratio over a larger base, not tighter. The most likely causes, in
order: row 7 (the emission claim's construction is the one object here no
Rust test has built end to end), row 9 (I15's first consumer), row 10 (the
store's gap retirement). The estimate and the signal are recorded separately
at close, as slice 7 did.

---

## 6. What this slice does not build

- **J1, J3, J7, J8, J9, J10** — Slice C's, authorized 2026-10-04 with the
  closed serve-credit round as its Round 0 (§1.2 item 1).
- **Any interim serve-credit row.** `SCV-Q1` was withdrawn as moot; there
  is no interim, and this slice orders nothing relative to one.
- **`DEL-008`'s trigger** — ruled (`SCV-Q5`): Slice C's rows `implemented`
  and J8–J10 retired. This slice is on that gate's critical path and does
  not move it.
- **The `archival_reorg_depth_blocks` split** — re-pointed to Slice C
  (FOLLOWUPS `:186`, this PR).
- **The attestation-record producer** (the block-template writer's,
  FOLLOWUPS `:181`) and the witness crossing the RPC edge (its second row,
  `SCV-Q4`). B4 judges whatever reached `Candidate::attestation_witness`
  — `None` as the empty preimage — and the header root decides (Q6 as
  corrected, §3.5); the corpus is the empty-root arm, the driver the
  record arm and the refusal. How the sidecar reaches the candidate on
  sync is the carrier's question, not this slice's.
- **A builder crate for the emission claim** — the handler's assembly is
  re-made in the driver (Q3), the second re-made assembly after the bond
  post's. **Trigger, recorded before the evidence exists: a third re-made
  assembly makes extraction the answer**, not a fourth re-making. Row 11
  carries the trigger into the crate contract so it outlives this file's
  archive.
- **The settlement writer** (Slice C's, landing as one unit with its
  admission rows — SO-D8 §8.0 item 3) and anything in
  `archival/{inputs,slash,close}.rs` — the transition is E4's, landed, and
  this slice adds rules in front of it, not arithmetic inside it.
- **Any C++ change.** The C++ gates stay as `DEL-008`'s cutover-day list has
  them; this slice's rows are the Rust side of the same verdicts. Where the
  Rust rule and the C++ disagree by design — the J15 `None` ruling (Q4),
  the `ARW-27` slash-log off-by-one E4 already recorded — the Rust is the
  spec's and the C++ is a finding, not a parity target.

---

## 7. Round log

| round | date | state |
| --- | --- | --- |
| 0 | 2026-10-03 | pre-flight written at `01a4494f1a`; §1.3's blocker check run first; nine questions posed with defaults (§8); no code |
| 0 (boundary) | 2026-10-04 | #946 read at `7003bd629`: Slice C authorized, its surface *"the successors of CEN-J1–J3 and J7–J10"* — J1 leaves this slice (one row, not four: J4–J6 are bond-state rows and stay); `SCV-Q1` withdrawn, Q9 struck; `SCV-Q5`'s genesis gate read into the plan; Slice C's input 4 (the shard predicate) and this slice's Q5 reconciled as build-here / consume-there, posed; figure re-derived from the row list (18 4.J rows; `118 / 151`); still no code |
| 0 (ruled) | 2026-10-04 | eight rulings from the maintainer: six defaults (Q1, Q2, Q4, Q5, Q7, Q8), one amendment (Q6 — `Option<WitnessSet>`, `None` = not supplied, B4 vacuous and recorded as a gap), one condition (Q3 — the byte-identity test; the third-assembly trigger); Q5's owed sentence widened to height semantics; Q9's struck number kept. Written into §3.2–§3.5, §4, §5, §5.1, §6. Implementation opens with PR-a commit 1; still no code |
| 0 (refuted) | 2026-10-04 | review on #947, verified at source: §3.5's premise *"nothing carries a witness"* false at the pin (`Candidate::attestation_witness`, E4 commit 5); Q6's amendment mechanically impossible — a vacuous row is in coverage, a gap is absent from it, `ChainValid::mint` panics on the absence (`verdict.rs:84–95`); `Some(empty)` unrepresentable (`AttestationWitness` non-empty by construction). Corrected disposition written (§3.5; ruled in the next row): B4 over the existing field, always evaluated, `None` the empty preimage against the header root, fail closed on a non-empty root; the store's B4 gap retires at row 10. FOLLOWUPS `:186` re-pointed in this PR rather than commit 1 (§1.2). Ruling's intent kept; still no code |
| 0 (Q6 re-ruled) | 2026-10-04 | the maintainer verified both mechanical facts at `dev@638f4999f7` (`archival/mod.rs:257–259`; `verdict.rs:87–95` with `rules/mod.rs:328`) and **ruled the corrected mechanism** — stronger than the amendment because the header's root, consensus-bound, is what tells *none exist* from *not supplied*; the error's mechanism recorded once in §3.5. "Posed" struck everywhere; Q6 is RULED. **This commit opens PR-a** (`feat/chain-rules-slice-8-pr-a` off `dev@638f4999f7`) so the ruling rides the implemented code; §5 row 1's census re-key is the next commit; still no code in this one |
| 1 | 2026-10-04 | **§5 row 1 — the `ARW-14` census re-key (PR-a commit 2).** CEN-J17 → bucket 3 (Q1 (a)); J13's two `HoldingsUpdate` legs and J15's ungated-drops clause struck line-local; `census.rs` loses `J17` (`CenRow::ALL.len()` 154 → 153, `validator-enforced` 152 → 151); the conformance register's J17 verdict leaves with the rule (125 / 2 / 5, fixture regenerated) and its FOLLOWUPS row closes as mooted; two doc comments naming the drop arm's grace tail re-worded; the shard-predicate FOLLOWUPS row carries its landing and an owner. Found beyond the row's text: J13's `HU-add` leg; the register row. §3.2 holds the list. The completeness gate now measures against rows whose subjects exist |
| 2 | 2026-10-04 | **§5 row 2 — the driver measurements, no rules (PR-a commits 3–4).** `Persona::reinstate` (the retention crate's constructor under the identity key; `release_post` beside it for the by-hand Release); `archival_admission_tests.rs` with the corpus's archival inputs pinned both directions and seven driver pins, each naming the row that flips it (J5, J6 → row 3; J11, J13 → row 4; J18's two belts → row 5). Two row premises stale at the pin, corrected in the row with the posed text kept: the Release already reached `validate`; the unbonded credit is L7's refusal today, not a connect. **Found:** the hint finding's money form — a Release of another persona's record under the poster's own key connects and takes the collateral; `cold_authority_pin` is called by the C++ connect and the submit verifier and by nothing in `shekyl-chain-rules` (§2). The corpus's two joins are indistinguishable on J14's multiplier (recorded in J14's row before the rule, so its witness is driven). **Review note (the maintainer, on the row):** the §2 paragraph's first draft reached for `CEN-B4` as a name for the pool-refuses / validator-connects split — B4 is the attestation root; the split was the subject at hand and B4 the nearest id in view — the fourth borrowed identifier of the week (the `connect.rs:238–246` cite and the `BlockHeight` recommendation, both §3.5, among the earlier three), an identifier taken from proximity rather than from its definition. All four were caught by re-reading, none by a gate: identifiers in prose are the one citation class nothing checks (`check_doc_code_citations.py` resolves `file:line`; a `CEN-xx` in a sentence resolves to nothing). Still no rule |
| 4 | 2026-10-04 | **§5 row 4 — J11, J12, J13 (PR-a commits 9–10).** J11 and J12 in `tx_form`'s last band; J13 in `tx_against` ahead of the signatures (Q8), the debit arm through `cold_authority_pin` — the pin that had two callers and none in the rules crate (§2) now has three; `implemented 100 → 103 / 151`. Both §2 pins flipped as row 2 named them: the stranger's join on J11, the money form on J13 at the post's vin with the record untouched. **Found at the fixtures, before the rule** (the second rule row running, after row 3): the rules crate's bond posts carried hints that recomputed from nothing, so `fixture::persona` landed first (commit 9) and the rules second — §5.1 row 4 measured 2 by split, as row 3's note said the next view-read row would; the estimate had been written before the note. Left as the C++ has it: a Release with no record is L7's, not J13's — the `have_record` gate (`blockchain.cpp:4508`) is a guard on *where* the refusal lands, not on whether it does (rule 16's guard variant, read the right way round this time) |
| 3 | 2026-10-04 | **§5 row 3 — J4, J5, J6 (PR-a commits 6–7).** The first rules of the slice: `rules/tx_bond.rs`, `judge_serve_credit_bond` in `validate::tx_against` after `judge_reference`, one `bond_record` read per serve-credit vin, the C++ arm's order; `implemented 97 → 100 / 151` (gate). The seven driver pins shed three: L7 → J4, J5 at `E_join`, J6 inside the interval — all three flipped as row 2 named them. **Found before the rule, at the fixtures:** the fold's L7 arm admits a same-block join + credit because its `post` read sees the block's own joins; the C++ reads the DB before the block, and the fixtures in three crates (the rules crate's serve-credit shapes, the store's `credited` chain, the driver's join scenario) all carried a credit in the join's block or epoch — commit 6 moved them, commit 7 landed the rule (§5.1: 2 by split, not retry). Row 2's measurement ran one direction — what the driver produces — and missed what the validator reads against; rule 16's direction variant, producer-ward, one slice after slice 6 failed it consumer-ward. The rule's entry is reshaped to name the axis rather than the instance, so the next sweep has a question to fail. **Recorded forward:** J7 (Slice C) requires the credited epoch's seal on chain, so the fixtures that now credit `E_join + 1` inside `E_join` will need their chains advanced when J7 lands — Slice C's fixture work, named here so it is not read as a J4–J6 red; and a new pin for J8 — a credit for a shard the slash removed connects once the interval is closed. Harness: `TxShape::reads_bond_state` (the sanity gate stops at `tx_form` for bond-reading shapes; the mock has no bonds by policy); the I17/I18 vacuity tests call `judge_signatures` directly, since the whole pass now refuses J4 on a record-less view. L7's J4 arm and the writer's SI-15 arm (`ARW-9`) are belts beneath a rule now; both stay, each saying so |
| 5 | 2026-10-04 | **§5 row 5 — J14, J16, J18 (PR-a commit 13).** The three kind verifies as callers of the retention crate's bodies, in one sequence per bond-post vin — `judge_bond_post_key` renamed `judge_bond_post`, J13 interleaved per kind in the C++ arm's order (JoinMarket J14 → J13; Release J13 over the record → J16; Reinstate J18 → J13); `implemented 103 → 106 / 151`. J16's operands read first time: the two last-served gathers (per held shard on a compact record, every served shard on a complete tree), the slash watermark, the connecting height's epoch off the rule set — the first transaction rule to read a parameter off it. Seven driver pins flipped L7 → J14/J16/J18 as rows 2 and 4 named them; two driver negatives added that no rules-crate fixture can shape (J14's under-bonded two-shard join; J16's Release inside the cooldown), and on review (2026-10-05) J16's **accept over a served anchor** — the operand `release_terms_hold` gathers, not the vacuous `None` of a never-served persona, which was the only driven accept at the row's landing: the two serving operands lift at one height (the fold settles the anchor in its deadline block, the next block opens the cooldown's boundary epoch), so the witness is a one-block pair — refused J16 at the deadline, the record's `Update` to zero one block later, and no re-slash of the persona in the ~40 blocks between. **Found at the pins, after the rule:** two G10 witnesses (the driver's join-and-release block; the mutation family's `DuplicateBondPost`, a twinned Release) read *"G10 runs before the transition"* as *G10 refuses the pair*; the slot loop runs before G10, and with J16 in it the release refuses on the missing record first — the C++'s order too (`check_tx_inputs` at `:5643`, the duplicate pass at `:5805`), so the pair never reached G10 in either implementation. Re-derived as two joins for one `P`; the pair pinned as J16's, the posed text kept. §5.1 row 5 measured **1** against the legs the re-pricing named: the fixture assumption held, the operand retry was not needed, and the leg the row did find — the pins — was not among them. `retention_vin` has a second copy in the submit verifier, named as the one that deletes when the pool adopts `tx_against` |
| 5 (review) | 2026-10-05 | **§5 row 5 on review (PR-a commits 15–16).** J16's accept over a served anchor driven as a one-block pair at the cooldown's boundary (the fold settles the anchor in its deadline block; the next opens epoch `E + RELEASE_COOLDOWN_EPOCHS`), the only driven accept before it being the vacuous `None` of a never-served persona; the G10 pair premise swept to the retention crate's `bond_post_block_unique` doc and `ARCHIVAL_BOND_GATE4.md`; `retention_vin`'s second copy filed with a grep falsifier. **Row 6 opened and did not begin:** SO-D8 §8.0 input 4 on `dev` (`cd51261ab2`) still reads *ruled and unbuilt* with no signature and no height semantics — the precondition §3.4 names is unmet, and the sentence is SO-D8's to write, not this slice's. Found at the open: PR-a carries rows 1–5 against Q7's rows 1–3 (§5, the disclosure paragraph); row 6's four legs priced in §5.1 |
| 6 (open) | 2026-10-05 | **Q7 re-ruled (a): #953 lands as rows 1–5**, recorded as *the ruling held for one PR and then stopped being applied* — the missing check (the body carries the ruled range; a commit outside it updates the line or re-rules) is now rule 26 A4's; #953 is its precedent, recorded here (the rules carry checks, not incident logs — #959). **SO-D8 asked for its sentence** (§3.4): the signature to confirm or refuse, and what `at` is for Slice C's call — which block's view, which side of a same-block slash. **Reorder proposed** (§5): PR-b = rows 7–10, PR-c = row 6 when the sentence exists; Q7's sequence kept. #953 marked ready for review at the commit carrying this row (docs-only over the clone-verified `512e4c3cf5`); the merge word is the maintainer's |
| 5 (review, arm) | 2026-10-05 | **The bond-post classifier is one type.** `BondArm::of` (`archival/arm.rs`) is what `judge_bond_post` and the fold's `apply_input` both call, so they cannot disagree about the arm. An unnamed kind is CEN-L7 inside `tx_against`, at the post's vin, and the four post rows are not recorded for it; the fold's L7 arm stays the belt for a transition that skipped the sequence. A missing `pqc_auths` slot refuses on J13 at the point that arm reads the slot — after the arm's non-slot check, in the C++ order — instead of falling through as a covered pass. The rules `retention_vin` takes the classified arm; the pool's `retention_vin` takes a caller-supplied kind and is not the same function (FOLLOWUPS). The driver's admission file split into the corpus table, the levered slash chain (one chain, a phase a failure can name), and the hint chain; the shared height and refusal shape live in `archival_driver`. |

---

## 8. Questions for the reviewer — Round 0 — RULED 2026-10-04

Each had a default; the ruling is on its question, the date once here.

- **Q1 — CEN-J17's class** (§3.2). *Default (a):* REJECTED → bucket 3; the
  census row keeps its id marked REJECTED with a pointer to `ARW-14`;
  `census.rs` loses `J17`; `validator-enforced 152 → 151`. *Alternative
  (b):* by-construction, the decoder as site. **RULED: (a), bucket 3.**
  H24's precedent is exact — a deleted subject is residue, not an
  unrepresentable state; (b)'s falsifier would watch a decoder property
  that belongs to a general unknown-kind refusal, not to J17.
- **Q2 — CEN-I13 and CEN-I15 land here** (§1.2 item 2, §3.6). *Default:*
  yes, in row 9, as 4.I rows recorded in a 4.J slice; their FOLLOWUPS rows
  close with this slice. *Alternative:* no — J21 and J26 land their
  non-proof clauses and the proof halves stay with `:787`. **RULED: yes.**
  Both blockers cleared (`depth_at` at `view.rs:328` — the ruling cited
  `:293`, which is `tip`; read at source; the scenario spend
  judged against a real tree), and §1.3 found both rows marked UNBLOCKED a
  week before `census.rs` stopped reading `pending`. The alternative
  splits J21 and J26 across slices into a half-implemented state the
  coverage gate cannot express; B4 already forces the two-line coverage
  record, and these use it.
- **Q3 — how the driver builds an emission claim** (§1.2 item 3, row 7).
  *Default:* in `shekyl-chain-ingest`, from the retention crate's wire
  builder, `shekyl-fcmp`'s membership-only prover over the wallet-side
  tree the driver already holds (`scenario_spend.rs`), and the dual auth
  over `emission_wire.rs`'s Q1 message — the engine handler's steps,
  re-made in the driver as the bond post's were. *Alternative:* extract
  the handler's assembly into a builder crate first (the
  `shekyl-archival-bond-builder` shape). Rejected as the default on
  scope: a crate extraction is a wallet-lane refactor, and the driver
  needs one caller. **RULED: the default, with one pin.** This is the
  second re-made assembly after the bond post, and the hazard is I17's —
  a driver whose claim differs from the engine's tests a transaction the
  wallet does not produce. So row 7 also lands **a test that the driver's
  assembly and the engine's emit identical bytes for one shape**, and §6
  records the trigger before the evidence exists: **a third re-made
  assembly makes extraction the answer.**
- **Q4 — `None` to admission** (§3.3). *Default:* a held shard whose last
  settled epoch has no `r_market` row is not admissible (fail closed; the
  C++'s `0` recorded as an inheritance finding). *Alternative:* `None ⇒
  0`, parity. **RULED: fail closed**, on two precedents — `SAR-Q6` kept
  the `Option` so this could be decided on merit, and `None ⇒ 0` is
  `SPL-14`'s shape one domain over (a missing value resolving to the
  permissive answer, here on a consensus admission decision). Third site
  for that defect, second time ruled against.
- **Q5 — the closed-and-final predicate's row, and who builds it** (§3.4).
  *Default:* amend CEN-J15's text; no new id; this slice builds it in J15
  and Slice C's Round 0 input 4 is discharged by that row reading
  `implemented`. *Alternatives:* mint `CEN-J27`; or Slice C builds it,
  which puts a bond-admission rule in a serve-credit slice and leaves J15
  reading a fact nothing enforces until Slice C lands. **RULED: the
  default** — one builder, two consumers; §3.4's owed-from-SO-D8 paragraph
  is what makes it safe, and the ruling widens what is owed: SO-D8's
  sentence names the **height semantics** as well as the signature, since
  "input 3's height" is unambiguous to input 3's author and not to J15's
  implementer. Row 6 waits on that sentence.
- **Q6 — the witness door for B4** (§3.5). *Default:* a parameter on
  `validate`, `None` the empty set. *Alternatives:* (b) inside the block
  type (rule 42 refuses); (c) the empty arm only. **RULED: the door, with
  the default's value AMENDED.** `None` as the empty set conflates *not
  supplied* with *none exist*, and `/get_blocks_by_height.bin` never
  populates the sidecar, so every captured chain's `None` is the former.
  The parameter is `Option<WitnessSet>`: `None` = not supplied,
  `Some(empty)` = none exist; **B4 vacuous on `None`**, recorded by the
  coverage-gaps component — the mechanism E4 commit 5 chose when
  `Fact`/`Origin` were deleted. **AMENDMENT'S MECHANISM REFUTED
  2026-10-04 at source** (§3.5): the question's own premise was wrong —
  `validate` already receives the witness through
  `Candidate::attestation_witness` — and the amended value cannot be
  built: vacuous-and-a-gap is a contradiction `ChainValid::mint` turns
  into a panic, and `Some(empty)` has no type to live in. **CORRECTED
  MECHANISM RULED 2026-10-04** (maintainer, verified at
  `dev@638f4999f7`): B4 over the existing field, always evaluated;
  `None` is the empty preimage against the header root — the root, not a
  tri-state, tells *none exist* from *not supplied*, and the latter fails
  closed. §3.5 carries the refutation and the consequences for row 10.
- **Q7 — the three-PR split** (§5). *Default:* PR-a rows 1–3, PR-b rows
  4–6, PR-c rows 7–11, each landing on `dev` before the next opens.
  *Alternative:* two PRs (a: 1–6, b: 7–11), which puts twelve commits in
  the second. **RULED: three, and the sequencing is the load-bearing
  half** — a sequence, not a stack: no re-target, no base-branch diff,
  none of #877/#880's mechanics. Twelve commits in a second PR is how
  slice 6 became unreviewable.
- **Q8 — J13 under I18.** I18 verifies the slot's signature; J13 says which
  key the slot must carry. *Default:* J13 is its own `TxAgainstRule`
  reading `bond_record().bond_spend_pk` for a Release and
  `hybrid_public_key` otherwise, run before `judge_signatures` so a
  wrong-key post is refused as J13 and not as a bad signature.
  *Alternative:* fold the key selection into I18's archival arm. **RULED:
  the default.** The reasoning that put G1 before the slot loop, and it
  forecloses the mis-keying `WrongReward` demonstrated.
- **Q9 — STRUCK 2026-10-04.** *Was:* the interim row's position relative to
  J1/J4–J6, a preference posed for `SCV-Q1`'s Round 1 to read. `SCV-Q1` was
  withdrawn as moot at #946 (§1.2 item 1); there is no interim row to order
  against, and J1 is no longer this slice's. The number is kept so nothing
  re-uses it (confirmed at the ruling: kept, not reused).

---

## 9. Documentation owed (rule 91)

Row 11 of §5. In addition, at this file's commit 1: the DRS-E6 row and the
§7.5 4.J row in `DAEMON_REDB_STORE.md` (the slice opened; the six
successor rows named; the `SAR-Q6` forward action pointed at Q4), the index
doc row, and the two FOLLOWUPS re-points named in §1.2. This document
archives to `docs/completed/` when PR-c lands (archive-or-contract, rule
95); its living residue, if any, goes to FOLLOWUPS with an owner that
resolves.
