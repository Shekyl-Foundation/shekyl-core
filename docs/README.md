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

**Claim audit.** A document can declare the invariants it means to hold, and
[`.github/workflows/doc-claims.yml`](../.github/workflows/doc-claims.yml) holds
it to them — put any of these near the top of the file:

```text
<!-- claim-audit: series DRS-W -->   register rows contiguous, no duplicates
<!-- claim-audit: range DRS-W -->    "DRS-W1…DRS-Wn" restated elsewhere must match
<!-- claim-audit: sections -->       every §N names a section this document has
<!-- claim-audit: numbered -->       numbered lists number themselves 1, 2, 3 …
<!-- claim-audit: counts -->         "**N rows**" matches the table beneath it
<!-- claim-audit: citations -->      path:line cites resolve (see scope below)
```

The citation leg is **scoped, not universal**: it resolves tokens rooted at
`src/`, `rust/`, `scripts/`, `tests/`, `external/` or a `shekyl-*` crate
(resolved under `rust/`), ending in `.cpp`, `.h`, `.rs`, `.py`, `.sh` or
`.inl`. An unrooted filename or another extension is not checked — so a green
run says the cites it recognises resolve, not that every path-like token in the
document does. Range citations (`file.rs:81-127`) are checked at **both**
endpoints, since a range is a claim about its whole span and a file truncated
inside one still resolves at its start.

Two ratchets keep the opt-in honest, and both are enforced against the **base
revision**, not just the tree in hand:

- the count of dead citations in live documents is a baseline in
  [`docs/ci/doc-claims-baseline.txt`](ci/doc-claims-baseline.txt) that may only
  move **down**. The figure travels in the same commit as the change it
  constrains, so a single edit could otherwise add rot and lift the bar to
  match; the gate reads the base branch's copy and rejects a raise. Whether it
  compared, and against what, is printed on **every** run — a check that
  quietly did not run must not look like one that ran and passed.
- a document that has declared a leg cannot silently un-declare it, and the
  registry records the **full declaration** (`series:DRS-W`, not `series`) —
  a document holding two declarations of one kind could otherwise drop either
  and still satisfy a kind-keyed record. The registry is complete: declaring a
  new leg costs one line in the baseline, and the gate prints the line to add.
  The registry **line** is base-checked too, because it is a reference value
  the change under test could otherwise edit: dropping a declaration and
  deleting the token that recorded it in one change satisfies every check that
  reads only the tree in hand. Deleting the document releases its line.

A base ref that **does not resolve** is fatal, not skipped: it would disable
both base-backed ratchets while the run still exited zero, and a ratchet with
no base is an absent ratchet rather than a lenient one. The one allowed gap is
narrow and self-identifying — the ref resolves but carries no baseline yet,
which is true exactly once, for the change that introduces the file.

Because that count is a ratchet, it has to mean the same thing everywhere. A
citation into a submodule this tree cannot vouch for therefore stops the run
rather than being counted as rot. Three states qualify, and they do not share a
remedy:

| State | Why it is not measurable | Fix |
| --- | --- | --- |
| Not checked out | a missing file is first evidence the *subject* is absent, not that the claim went stale | `git submodule update --init <path>` |
| At another commit | the file is present, so its line numbers are somebody else's | `git submodule update --init <path>` |
| Worktree dirty | at the recorded commit, but the content is not what the superproject records | commit, stash or restore inside the submodule — **`update --init` will not do this, by design** |

The dirty case is the one that surprises: the checkout is at the right commit
and still fails, and nothing here will discard local work to make a gate pass.

Declaring is opt-in because inferring these corpus-wide produced 991 findings
against a clean tree — `§17` usually cites another document, registers
legitimately skip a retired number, and the CHANGELOG cites files that existed
when it was written. Run it before pushing (`python3
scripts/ci/check_doc_claims.py`); that is where it earns its keep. It checks
numeric and structural claims against source, and **does not check
rationales** — a document can pass it green and still be wrong about the
world.

The matrix that falsifies this gate also measures its own completeness: every
discrepancy, non-coverage and refusal the gate can emit must be executed by
some case, or the matrix fails and names the unreached ones. That check exists
because the review of this gate kept finding holes the matrix could not — the
first sweep found seven, one of them a branch no case reached at all.

Where a leg declines a subject it cannot judge, it says so on a `Not checked:`
line rather than staying quiet — `§N.M` references, for instance, are treated
as pointing at *another* document's section and are reported as unchecked
rather than failed, since a document without dotted headings of its own cannot
tell a cross-reference from a typo.

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
| Archival serving route (request) | [design/ARCHIVAL_SERVING_ROUTE.md](design/ARCHIVAL_SERVING_ROUTE.md) |
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
