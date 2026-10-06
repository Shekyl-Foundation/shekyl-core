# The C++ version gates — the sweep and its inventory

**Status:** OPEN — the sweep was executed 2026-10-05 at `b998f484a1`
(approved by Rick, 2026-10-05, as work item (a) of
[`ECONOMY_UMBRELLA_PLAN.md`](ECONOMY_UMBRELLA_PLAN.md) §3.2). It closes when
the inventory is empty or the C++ is gone, whichever comes first; the gate
and the inventory are deleted then.

The inventory is [`docs/ci/cxx-version-gates.tsv`](../ci/cxx-version-gates.tsv).
`scripts/ci/check_cxx_version_gates.py` holds the tree to it in both
directions on every pull request. This document says what the rows mean. It
does not repeat them: a second copy of the table would drift from the one
the gate reads.

Not a new identifier family. A row is addressed by its path and its code
text.

---

## 1. Why a sweep

Monero gates behaviour on its hard-fork numbers. Shekyl restarted the block
version at 1, so a branch behind `version >= N` with `N ≥ 2` never runs and
its `else` arm is what ships. The reward-aware template fill sat dead behind
`version >= 5` from the reboot until 2026-10-04, by which time the economics
sim had modelled it as production
([`ECONOMY_UMBRELLA_PLAN.md`](ECONOMY_UMBRELLA_PLAN.md) §3.1). Nothing had
classified the other comparisons. This sweep does, and the gate keeps a new
one from arriving unclassified.

## 2. The operands, and what pins each

"Dead" means dead at Shekyl's value of the operand a comparison reads, not
"`N` is greater than 1". There are several operands and they are not the
same thing.

| Operand | Shekyl's value | What pins it |
| --- | --- | --- |
| Block major version | 1 | Every network's hard-fork table holds version 1 alone (`src/hardforks/hardforks.cpp`). `HardFork::check` requires a block's major version to **equal** the table's, so an accepted block's is 1; the template takes its own from the table |
| Block minor version (the vote) | 0 or more | Inert: a vote is counted against a table with one entry |
| Transaction version | 3, once admitted | `ver_non_input_consensus` and `check_tx_inputs` both bound it at 3 exactly. **The parser does not**: `transaction_prefix` refuses 0 and anything above 3, and still reads a version-1 or version-2 blob |
| A hard-fork table lookup | 1, or the height the table gives | The same single-entry table |
| Other things named `version` | their own | The LMDB schema version, the SOCKS protocol version, the PQC `auth_version`, a CLI argument, a peer-list format. Not chain versions; extracted and rowed so nothing named `version` is unclassified |

The transaction row is the one that needs care. A comparison such as
`tx.version >= 2` is always true for a transaction the daemon has admitted.
The version-1 serialisation arms are *not* dead in the same way: a peer can
send a version-1 blob, the parser takes that arm, and the transaction is
refused only afterwards. Deleting those arms changes what the parser does
with such a blob, so they wait for the parser to refuse it first (§4).

## 3. The dispositions

One per row, and no row is left as it is because it is harmless.

| Disposition | Meaning |
| --- | --- |
| Move to Rust | A dead arm that is the design. The owner moves to Rust and the C++ and its gate are deleted with it |
| Delete | A dead arm that is not the design: pre-fork Monero behaviour nobody wants |
| Collapse | A live arm. The gate is noise; it collapses to the one arm |
| With the mechanism | Not a gate on a number. Part of the hard-fork machinery itself, correct for any table, and decided with it (§5) |
| None | A row for another operand |

## 4. Where each row lands

| Landing | Rows, 2026-10-05 | What it is |
| --- | --- | --- |
| **This PR** | none left; see below | The block-version gates that could be executed alone |
| **The template fill's move to Rust** | 2 | `tx_pool.cpp`'s `version >= 5`. RULED 2026-10-05; sequenced after the coinbase reserve ([`ECONOMY_UMBRELLA_PLAN.md`](ECONOMY_UMBRELLA_PLAN.md) §3.2 c, d) |
| **The transaction-version PR** | 26 | The parser refuses every version but 3. Then 17 comparisons collapse to their one arm and 8 are deleted as dead, the version-1 serialisation arms among them. Its validation surface is the transaction wire format: `core_tests`, the wire parity vectors and the Rust parser's own refusals |
| **CEN-F21's epoch** | 4 | `get_earliest_ideal_height_for_version(HF_VERSION_SHEKYL_NG)`. Live and consensus: it resolves the height the staker emission share decays from. It collapses to the Rust owner's `EMISSION_SPLIT_EPOCH`, with the `core_tests` fork tables that still disagree with the daemon about it (`docs/FOLLOWUPS.md`) |
| **The hard-fork mechanism's decision** | 27 | §5 |
| **None** | 7 | Other operands |

**Executed in this PR.** These comparisons are gone, so they have no row:

- `db_lmdb.cpp` `blk.major_version >= 4` — dead, not the design. With it
  goes everything that read the field it guarded (§6).
- `cryptonote_protocol_handler.inl` `version >= 6` — dead, not the design: a
  Monero check that a peer's advertised top block version is the ideal one.
  It has never run here. Whether Shekyl wants such a check is a peer-to-peer
  design question, and it is not answered by enabling a Monero branch.
- `blockchain_db.cpp` `blk.major_version >= HF_VERSION_FCMP_PLUS_PLUS_PQC`,
  twice — live. The curve-tree append and its undo now run unconditionally,
  which is what they did.
- `cryptonote_tx_utils.cpp`'s assertion that the fork version is at least
  `HF_VERSION_FCMP_PLUS_PLUS_PQC` — always true.
- `HF_VERSION_DYNAMIC_FEE` and `HF_VERSION_FCMP_PLUS_PLUS_PQC` — deleted
  with their last readers. `HF_VERSION_SHEKYL_NG` is the operand of the
  epoch lookup. `HF_VERSION_EXACT_COINBASE`, `HF_VERSION_VIEW_TAGS` and
  `HF_VERSION_2021_SCALING` are read only by tests.

## 5. The hard-fork mechanism is one decision

These rows are the machinery, not gates on a number: `HardFork`
itself, the wrappers that expose it, the version it hands the template, the
`hf_version` read from it and threaded as a parameter that no callee
compares any more, and the start-up loop that pops blocks made under an
older fork (`ideal_hf_version <= 1`, which is correct for any table and
simply has nothing to do with one entry).

Collapsing them one at a time would be deciding, row by row, that Shekyl has
no fork mechanism. That is one decision, and it is Rick's: keep a fork table
for a future transition (the V4 lattice-only transition is the named one),
or delete `HardFork` and carry the version as the constant it is. Asked
2026-10-05. Until it is answered these rows stay as rows, which is not the
same as leaving them: each names this decision as its landing, and none can
gain a sibling without a row of its own.

## 6. What the output-count gate was guarding

`bi_cum_rct` was not a counter stuck at zero. `add_block` stores each
block's own output count unconditionally; only the step that added the
previous block's total sat behind `major_version >= 4`. So the field held a
per-block count where its one reader expected a running total.

That reader was `get_output_distribution`, the decoy-selection distribution.
Nothing calls it: the Rust RPC server asserts the route is not served, and
its last C++ caller was its own unit test. FCMP++ has no decoys. So the
disposition was to delete the surface, not to repair the counter:
`RpcHandler` (the whole class; nothing derived from it), the
`output_distribution` message struct and its JSON functions, the function
through `core`, `Blockchain`, `BlockchainDB` and LMDB, the test, and the
gated step.

One piece stays. `bi_cum_rct` is a field of the persisted block-info row, so
removing it is a schema change, and LMDB's replacement is already in flight.
It is written and never read (`docs/FOLLOWUPS.md`).

## 7. Two things the sweep found beside the gates

- **An existing gate could not see what it named.** `grep-gates.yml` has
  carried "C++ residue: no v1/v2 tx version branches", a grep for
  `tx.version == 1`. It passes, and five version-1 arms exist, spelled
  `version == 1`, `t.version == 1` and `x.version == 1`. The new extractor
  reads the operand's name, not one spelling of it; the transaction-version
  PR deletes the arms and the old grep with them.
- **`hf_version` is threaded and unread.** `get_current_version()` is read
  into a local in four places and passed down as a parameter; after the
  earlier rule-60 deletions no callee compares it. The parameter goes with
  the mechanism's decision (§5).

## 8. Changing the inventory

Run `python3 scripts/ci/check_cxx_version_gates.py --dump` for the tree's
hits. A new comparison needs a row with its operand, what it evaluates to at
Shekyl's value, one of §3's dispositions, and a landing. A row whose site is
deleted is deleted. The better change is not to add the comparison: nothing
in this tree should branch on a fork number.

The gate compares sets, not counts, so adding one gate while removing
another fails. It refuses an empty source tree and an empty inventory, so it
cannot go quietly green when the C++ is gone; it is deleted then, with this
document.
