# `shekyl-chain-rules` slice 8 — census 4.J, the archival admission rules, and the 4.B row that waited for the bond record (DRS-E6 increment 9)

**Status:** OPEN — **Round 0 RULED 2026-10-04 (implementation opens with
PR-a commit 1); pre-flight written 2026-10-03 against `dev` @
`01a4494f1a`** (post-#939, the serve-credit verifier's Round 0; post-#942,
CEN-J2; post-#937, DRS-E4 archived). No implementation has begun; rule 26
halts implementation, not the pre-flight record. Registered before
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
carries the date. Implementation opens with PR-a commit 1; still no code
at this update.

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
  serve credit from a persona with no record (J4's rule, `:49–53`), a
  second JoinMarket for a persona (J14's "must not already exist",
  `:97–99`), a Release whose debit is not the record's total (J16,
  `:158–170`), a Reinstate with no open interval (J18, `:210–223`), a
  claim for an epoch already claimed (J25's dedup, `:273–280`). What is
  **not** running is the admission verify the C++ runs *before* applying:
  `verify_join_market_bond_post`, `verify_release_bond_post` with its
  cooldown anchors, `verify_reinstate_bond_post`, `check_admission`,
  `emission_vin_verify_{claims,backing,auth}`, the bond-post statics
  (J11–J13), the emission statics (J19, J20, J22, J24). This slice lifts
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
  drop arm name `HoldingsUpdate`, REJECTED 2026-09-20 (`ARW-14`). A row
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
rule*. That lane is now Slice C; commit 1 edits the row's *Owed* and
*Owner* lines to say so (disclosure here, rule 22). The row's falsifier is
unchanged.

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
J4–J6 have no corpus witness at all), any attestation witness (the RPC
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
| **`ARW-14`'s re-key** (`DRS_E4_ARCHIVAL_WRITER.md:1167`) | `HoldingsUpdate` deleted | **cleared** 2026-10-02 — no `HoldingsUpdate` arm anywhere: `PostKind::from_u8` yields Release / Reinstate / JoinMarket, an unknown kind is L7's refusal (`archival/inputs.rs:66–72`); the appliers and the journal table are gone (ARW-14's three places) | **commit 1's work** — a precondition of the rules, not a task among them; **Q1** (§3.2) fixes J17's class |
| **`SCV-6` — the closed-and-final shard predicate** (FOLLOWUPS `:205`) | *the A4 length rows (S-CHAIN-W) and S-PRUNE deriving `b_*`* | **both dissolved by ruling** (`PDM-Q6` item 5: *A4 is not owed*; `SHT-Q2`: `shard_of(cumulative_archival_len)`), and the operand is landed — `closed_shards_before` — as SCV-6 found 2026-10-02 | **lands here**, inside J15's commit, **Q5** (§3.4) names its row |
| **`archival_reorg_depth_blocks` split** (FOLLOWUPS `:197`) | owed to *the lane that lands the re-keyed serve-credit admission rule* | the lane moved (§1.2 item 1) | **re-pointed** to Slice C in commit 1 |
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
| J4 | the named P has a bond record | partial under L7 (`inputs.rs:49–53`) | `TxAgainstRule` over `bond_record` | none |
| J5 | `E ≥ E_join + 1` | `serve_eligibility::serve_credit_epoch_ok` — called by nothing in the validator | `TxAgainstRule` | none |
| J6 | P `good_through` the claimed epoch | the retention crate's `good_through` (FFI `shekyl_archival_good_through`); the validator reads `bad_intervals` in the folds only | `TxAgainstRule` | none |

**Bond post** (per tx; H21 the shape; the CT balance with terms is H21's):

| row | rule (short) | Rust body today | class | witness today |
| --- | --- | --- | --- | --- |
| J11 | hybrid pubkey length canonical; `p_canonical_id` recomputes | `p_canonical_id_from_hybrid_pubkey` — the transition **trusts the vin's hint**: `post.p_canonical_id` is a decoded wire field (`shekyl-wire/src/transaction.rs:634`), never recomputed from the `hybrid_public_key` beside it (`:632`), and the folds key the record on it (`inputs.rs:95`, `:148`, `:194`). Contrast the emission vin, whose `p` *is* recomputed at parse (`body.rs:246`) | `TxRule`, `tx_form` | corpus accept (JoinMarket) |
| J12 | `bond_spend_pk` ⇔ JoinMarket | the decoder's shape (`WireKind::JoinMarket { bond_spend_pk, .. }` vs `Other`); the *length* belt is nowhere in the validator | `TxRule`, `tx_form` | corpus accept |
| J13 | debit arm (Release) authorizes with the record's committed `bond_spend_pk`; credit arms (JoinMarket, Reinstate) with `P_pubkey` | `debit_auth::{cold_authority_pin, debit_auth_pin}`; I18 verifies the slot's signature but **which key** the slot must carry is not judged | `TxAgainstRule` over `bond_record` | corpus accept (credit arm only) |
| J14 | JoinMarket semantics: shape, no debit, `credit == bonded_total == bond_floor(holdings)`, record absent | `verify_join_market_bond_post(vin, record_exists)`; partial under L7 (record absent, empty set) | `TxAgainstRule` | corpus accept |
| J15 | admission viability (D3/R3) over per-shard `r_market` + presence at the parent | `admission::check_admission(holdings, parent_state)`; `parent_state_shards_from_gather`; **absent** in the validator; the C++ gather is `blockchain.cpp:4640–4680`. Presence under `SHT-Q2` is *closed before the parent*, not a freeze height | `TxAgainstRule` over `r_market`, `closed_shards_before` | corpus accept (shard set) |
| J16 | Unbond: full exit, cooldown elapsed from last-served anchors, slashes settled through the anchor | `verify_release_bond_post(vin, total, intervals, last_served, last_settled, epoch)` with `release_cooldown::*`; partial under L7 (`release_connect`: debit is the total) — **cooldown and settlement are unjudged today** | `TxAgainstRule` over `bond_record`, `last_served_epoch`, `last_settled_slash_epoch` | none |
| J17 | HoldingsUpdate add / drop arms | **no such kind exists** (`ARW-14`) | **Q1**: REJECTED → bucket 3 | n/a |
| J18 | Reinstate: single open interval, headroom, credit against identity key | `verify_reinstate_bond_post`; partial under L7 (`reinstate_connect`'s preconditions) | `TxAgainstRule` | none (no driver constructor) |

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
| B4 | `attestation_root` equals the recompute over the (possibly empty) witness; every record's P-countersignature verifies under `SF-D8` v2 | `shekyl-archival-retention/src/attestation.rs` (the FFI `shekyl_archival_verify_attestation`'s body); `census.rs:331` pending; `rules/header.rs:8` *"B4 is deferred (E4…)"* | `BlockRule` after D1; the witness is a `validate` input — **Q6** | empty-root arm: every corpus block; record arm: none |

What the audit found that the census does not say: **J11's recompute is
not run anywhere in the validator** — the transition keys the record on
the vin's `p_canonical_id` hint. Under the C++ that hint is verified first
(`blockchain.cpp:4471–4480`); under the Rust it is trusted, so a post whose
hint names another persona's record would be folded into that record. J11
is the first bond row to land for that reason (§5 row 4), and its negative
fixture is the mismatched hint.

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

- **Default: amend CEN-J15's row text** to carry the predicate as its
  first clause, with the three answers above recorded on the row; no new
  `CEN-` id. The census is the registry of consensus rules, and a rule's
  text changing by ruling is recorded on the rule.
- **Alternative: mint `CEN-J27`** for it, so the predicate has its own
  coverage bit. Not a new family (rule 94 §1 is about prefixes); it is a
  new row in 4.J, which SO-D8 §8 also plans to add to at Slice C.

**Q5** rules it. Either way the FOLLOWUPS row closes with this slice.

### 3.5 CEN-B4's witness is a sidecar, and `validate` has no door for it

The attestation witness is not block bytes (`block_complete_entry::
attestation_witness`, `KV_SERIALIZE_OPT`). The C++ passes
`connect.attestation_witness` into `verify_block_attestation`
(`blockchain.cpp:2243`, `:5304`). `validate(block, …)` today takes the
block, the view, the rule set and the trust anchors; nothing carries a
witness. Three shapes:

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

**Q6 RULED 2026-10-04: the default's door, with its value amended.** The
default's `None` as *the empty set* conflates **not supplied** with **none
exist**, and `/get_blocks_by_height.bin` never populates the sidecar
(FOLLOWUPS `:184`), so every captured chain's `None` means the former. The
parameter is `Option<WitnessSet>`: `None` = not supplied, `Some(empty)` =
none exist. **B4 is vacuous on `None`**, and the verdict's coverage-gaps
component records it — `Provenance::rule_coverage_gaps`
(`shekyl-chain-store/src/provenance.rs:25`), the mechanism E4 commit 5
chose when `Fact`/`Origin` were deleted
([`DRS_E4_ARCHIVAL_WRITER.md`](../completed/DRS_E4_ARCHIVAL_WRITER.md)
`:531`): the gap's meaning narrows from *B4 not evaluated* to *B4 not
evaluated because nothing was supplied*, and a file whose witnesses were
written unjudged is still not parity evidence. Two consequences for §5
row 10: the empty-root arm is no longer tested by the corpus (every corpus
block is `None`, vacuous) — it is tested by a driver-supplied `Some(empty)`
against the header's empty root, beside the record arm's driver-supplied
witness; and corpus parity on B4 is a parity of *gaps* (B4 recorded as a
gap on every corpus block), not of verdicts. The carrier question
(`SCV-Q4`) is not this slice's.

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
  the `Option<WitnessSet>` parameter (Q6 as amended); vacuous on `None`.
- **The transition** is untouched: L7 keeps every fold refusal it has.

---

## 5. Commit plan — Round 0, ruled 2026-10-04

The rows below are as posed, with each ruling written into the row it
changes (rows 1, 6, 7, 9, 10) rather than restated beneath the table.

| # | commit | gate |
| --- | --- | --- |
| 1 | **This file on review; the index rows; §5.1; the `ARW-14` census re-key** — J17 REJECTED → bucket 3 (Q1 (a), ruled), J13's drop arm and J15's ungated-drops clause struck line-local; `census.rs` loses `J17`; FOLLOWUPS `:197` re-pointed to Slice C (§1.2 item 1), `:205` noted as landing here (§3.4); the DRS-E6 row. **Lands before any rule**, so the completeness gate measures the rules against rows that describe something that exists | docs gates; the coverage gate's denominator moves `152 → 151` |
| 2 | **Driver measurements, no rules.** (a) The two corpus shapes: what each block's archival inputs are, read off the replay, so the positive witnesses are enumerated rather than assumed; (b) `Persona::reinstate` and a Release that the driver *validates* (today it only constructs); (c) a serve credit from an unbonded persona and one at `E_join` through `mine_listing` — both connect today, pinned to flip at row 3; (d) the J11 mismatched-hint post — connects today (§2's finding), pinned to flip at row 4 | the pins |
| 3 | **J4, J5, J6** — the bond-state rows on the serve-credit vin: the named persona has a bond record (`bond_record`), the claimed epoch is `≥ E_first` (join epoch + 1), and the persona is `good_through` it. Three `TxAgainstRule`s over one view read, each with its negative fixture on a driven chain (an unbonded persona; a credit for the join epoch; a persona past its `good_through`). Named by what they check — they touch no credit, no preimage, no window; J1's parse and J7's window are Slice C's (§1.2 item 1) | corpus parity holds |
| 4 | **J11, J12, J13** — the bond-post statics and the key-selection rule; J11's fixture is the mismatched hint, J13's a Release whose slot carries `P_pubkey` | corpus parity |
| 5 | **J14, J16, J18** — the three kind verifies as callers of the retention crate's bodies; J16's cooldown operands off `last_served_epoch` / `last_settled_slash_epoch`; J18 over the driver's new Reinstate | corpus parity |
| 6 | **J15** with the closed-and-final predicate (Q5, ruled: built here, `closed_and_final(view, shard, at)` with the height a parameter) and `None` not admissible (Q4, ruled: fail closed); `parent_state_shards_from_gather` over `r_market` and `closed_shards_before`. **Does not land until SO-D8 §8.0 names the signature and the height semantics Slice C will call** (§3.4) | corpus parity; FOLLOWUPS `:205` closes; the SO-D8 sentence exists |
| 7 | **The driver's emission claim** (Q3, ruled with a condition): membership-only backing proof + dual auth over the Q1 message, as the engine handler does it; one claim `validate` admits, pinned; **and a test that the driver's assembly and the engine's emit identical bytes for one shape** — the I17 hazard is a driver whose claim differs from the engine's testing a transaction the wallet never produces. The trigger recorded in §6: a third re-made assembly makes extraction the answer | the pin; the byte-identity test |
| 8 | **J19, J20, J22, J24** — the emission statics | corpus parity |
| 9 | **J21, J23, J25, J26 + I13, I15** (Q2, ruled yes) — the reference context, the budget rows and the coarse verify, the backing and fee-input proofs; `shekyl-fcmp` into the crate; `vout_reward_sum` wired to its consumer | corpus parity; `4.I 18 + 2 = 20 / 20` |
| 10 | **B4** — the witness door as amended (Q6: `Option<WitnessSet>`, `None` = not supplied → B4 vacuous, recorded in the coverage gaps; `Some(empty)` = none exist), the recompute, both arms; the scenario supplies `Some(empty)` for the empty-root arm and a witness for the record arm — neither arm has a corpus witness, since every corpus block is `None` | corpus parity as a parity of gaps (B4 a gap on every corpus block); both arms on the driver |
| 11 | **Docs** (rule 91): census 4.J and B4 re-pinned with `Rust (E6 slice 8 row n, date)` clauses; crate contract §4.6 (the `validate` parameter and its two `None`/`Some(empty)` meanings; the Q3 extraction trigger, so it outlives this file); DRS-E6 row; index; FOLLOWUPS (`:205`, `:783`, `:787` removed); CHANGELOG (consensus-relevant: the validator now refuses what it admitted) | docs gates |

Eleven rows is past the ten-commit ceiling before the overrun; the slice
lands as **three PRs** in dependency order — **PR-a** rows 1–3 (docs,
driver, the bond-state rows), **PR-b** rows 4–6 (the bond post),
**PR-c** rows 7–11 (the emission, B4, docs) — the E4 PR-a / PR-b shape.
**Ruled 2026-10-04 (Q7): three, and the sequencing is the load-bearing
half.** Each lands on `dev` before the next opens — a *sequence*, not a
stack: no re-target, no base-branch diff, none of #877/#880's mechanics.
Twelve commits in a second PR is how slice 6 became unreviewable. Each
PR's record is stated in the row when it lands.

### 5.1 The expectation, written at commit 1 (2026-10-03, before commit 2)

Commit counts and coverage are written now, before any measurement, so the
overrun signal has a subject. No per-connect budget is set here: the rows
are predicate evaluations over single reads, and the one fold with a cost —
J15's per-shard gather — is bounded by the shard set's cardinality cap and
priced by the admission crate already.

| row | lands | cost | why that number |
| --- | --- | --- | --- |
| 1 | this file; index; re-key; FOLLOWUPS re-points | 1 | — |
| 2 | four measurements, no rules | **2** | two of the four are driver capabilities the driver has never had (Reinstate; a Release that reaches `validate`), and the first attempt at each has cost a commit (slice 6 §5.3.3, slice 7 §5.1 row 2) |
| 3 | J4, J5, J6 | 1 | three callers of landed bodies over one read |
| 4 | J11, J12, J13 | 1 | statics plus one record read |
| 5 | J14, J16, J18 | **2** | J16's cooldown has three operands and the C++ gather is the slice's most-marshalled site (`blockchain.cpp:4520–4600`); the second commit is the one that finds the operand the first missed |
| 6 | J15 + predicate | **2** | a new rule (the predicate) plus an unimplemented old one (admission), on a question (Q4) with a non-parity default — the fixture set must fail in both directions |
| 7 | the driver's emission claim | **2** | a membership-only prover call and a dual auth the driver has never made; the engine's half lives in a handler, not a crate. Q3's byte-identity test is inside this estimate, not added to it: it is the first thing the second commit runs, and a mismatch is the finding the second commit exists for |
| 8 | J19, J20, J22, J24 | 1 | statics; J22's body located at commit |
| 9 | J21, J23, J25, J26 (+ I13, I15) | **3** | the `shekyl-fcmp` edge, I15 in `judge_reference`, then the emission rows over it; J25 is the row that mints coins and gets the fixture set a minting row deserves |
| 10 | B4 | **2** | a new `validate` parameter touches the store's connect path and every caller in two crates' tests — wider than slice 7 row 9's new *view read* (`total_burned`), which already cost one over estimate; then both arms over driven witnesses — Q6's amendment moved the empty-root arm off the corpus and onto the driver (`Some(empty)`), inside the same two commits: the parameter is the first, the arms are the second |
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
`validate` signature). The estimate and the signal are recorded separately
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
- **The `archival_reorg_depth_blocks` split** — re-pointed to Slice C.
- **The attestation-record producer** (the block-template writer's,
  FOLLOWUPS `:181`) and the witness crossing the RPC edge (its second row).
  Both of B4's arms are tested with driver-supplied witnesses
  (`Some(empty)`, a record set); the corpus stays at `None` — *not
  supplied* — and B4 records as a coverage gap on every corpus block (Q6
  as amended).
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
  `Fact`/`Origin` were deleted. §3.5 carries the consequences for row 10.
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
