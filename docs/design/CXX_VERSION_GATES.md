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
| Transaction version | 3, once admitted | `ver_non_input_consensus` and `check_tx_inputs` both bound it at 3 exactly, including where the bound is a local (`min_tx_version`, `max_tx_version`) rather than the literal 3. **The parser does not**: `transaction_prefix` refuses 0 and anything above 3, and still reads a version-1 or version-2 blob |
| A hard-fork table lookup, and the table's own comparisons | 1, or the height the table gives | The same single-entry table. A lookup is a row, and so is a comparison inside `HardFork` (a block must equal the current fork, a vote is clamped to the newest entry, the index walks) and a comparison of the `hf_version` that lookup returns (the pool revalidated on connect and on pop, the non-input-consensus cache) |
| Other things named `version` | their own | The LMDB schema version, a persisted row's `kVersion`, the bootstrap file version, the SOCKS protocol version, the PQC `auth_version`, a CLI argument. Not chain versions; extracted and rowed so nothing named `version` is unclassified |

The transaction row is the one that needs care. A comparison such as
`tx.version >= 2` is always true for a transaction the daemon has admitted.
The version-1 serialisation arms are *not* dead in the same way: a peer can
send a version-1 blob, the parser takes that arm, and the transaction is
refused only afterwards. Deleting those arms changes what the parser does
with such a blob, so they wait for the parser to refuse it first (§4).

## 3. The dispositions

One token per row. The gate rejects any other word, so a sentence in the cell cannot pretend to be a classification. The per-site nuance lives in `evaluates`.

| Token | Meaning |
| --- | --- |
| `move-to-rust` | A dead arm that is the design. The owner moves to Rust and the C++ and its gate are deleted with it |
| `delete` | A dead arm that is not the design: pre-fork Monero behaviour nobody wants, deleted once its blocker is gone |
| `collapse` | A live arm. The gate is noise; it collapses to the one arm |
| `none` | A row for another operand |

## 4. Where each row lands

`landing` is a token too: `template-fill`, `tx-version`, `cen-f21`, `hardfork`, `none`. Counted 2026-10-06, when the extractor was widened to a comparison on any version name (a named bound, `HardFork`'s own comparisons, a persisted row's `kVersion`, the bootstrap file version) and to `.cc`. The 2026-10-05 sweep had 66 rows; it required one side to be an integer or an uppercase `VERSION` token, and these were the rows that requirement hid.

| Token | Rows, 2026-10-06 | What it is |
| --- | --- | --- |
| `template-fill` | 2 | `tx_pool.cpp`'s `version >= 5`. RULED 2026-10-05; sequenced after the coinbase reserve ([`ECONOMY_UMBRELLA_PLAN.md`](ECONOMY_UMBRELLA_PLAN.md) §3.2 c, d) |
| `tx-version` | 28 | The parser refuses every version but 3. Then 19 comparisons collapse to their one arm and 9 are deleted as dead, the version-1 serialisation arms among them. The admission bound in `ver_non_input_consensus` is one of the 19: both locals are 3. The two checks in `check_tx_inputs` are a second statement of it, and they are two of the 10. Its validation surface is the transaction wire format: `core_tests`, the wire parity vectors and the Rust parser's own refusals |
| `cen-f21` | 4 | `get_earliest_ideal_height_for_version(HF_VERSION_SHEKYL_NG)`. Live and consensus: it resolves the height the staker emission share decays from. It collapses to the Rust owner's `EMISSION_SPLIT_EPOCH`, with the `core_tests` fork tables that still disagree with the daemon about it (`docs/FOLLOWUPS.md`) |
| `hardfork` | 41 | §5 |
| `none` | 14 | Other operands: the LMDB schema version, a persisted row's `kVersion`, the bootstrap file version, SOCKS, the PQC `auth_version`, a CLI argument |

**Executed in the 2026-10-05 sweep.** These comparisons are gone, so they have no row:

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

## 5. The hard-fork mechanism is deleted

**RULED 2026-10-06 (Rick):** "delete the fork table - when we need one, we
will write a fresh one, not try to recycle Monero's."

The rows landing at `hardfork` are the machinery, not gates on a number:
`HardFork` itself, the comparisons inside it, the wrappers that expose it,
the version it hands the template, the `hf_version` read from it and
compared where the pool is revalidated (on connect and on pop) and where
non-input consensus is skipped because the transaction already passed at
that fork, and the start-up loop that pops blocks made under an older fork.
The handshake's `top_version` is written and read by nobody. All of them are
`delete`.

They go in one PR, because collapsing them a row at a time would leave a
fork mechanism with pieces missing. What that PR has to carry, beyond
removing the class:

- **The block-version rule stays, stated directly.** `HardFork::check` is
  what requires a block's major version to equal 1 today. The rule moves to
  where blocks are validated, as a comparison against the constant, and its
  CEN row is updated to say so.
- **CEN-F21's epoch stops being a table lookup.** The four `cen-f21` rows
  resolve the staker-emission epoch through
  `get_earliest_ideal_height_for_version`. They take the Rust owner's
  `EMISSION_SPLIT_EPOCH`, and the `core_tests` fork tables that disagree
  with the daemon about that height (`docs/FOLLOWUPS.md`) are settled in the
  same change, since the tables are what is being deleted.
- **The persisted fork tables and the RPC that reports them go too**: LMDB's
  `hf_versions`, the `hard_fork_info` surface, and the handshake field. The
  first is a schema change and follows the serialization policy.
- **Tests that fork to version 2.** `core_tests` builds fakechain tables at
  `HF_VERSION_VIEW_TAGS + 1`. Those tests are of a mechanism that will not
  exist; each is kept for the rule it really exercises, on a chain at
  version 1, or deleted.

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
  `version == 1`, `t.version == 1` and `x.version == 1`. The extractor reads
  the operand's name, not one spelling of it; the transaction-version PR
  deletes the arms and the old grep with them.
- **The first form of this extractor had the same blind spot.** It classified
  a comparison only when one side was an integer or an uppercase `VERSION`
  token, so `tx.version < min_tx_version`, `HardFork`'s
  `heights[i].version` comparisons and `p[0] != kVersion` were not rows.
  Widened 2026-10-06: a version operand is an identifier that ends in
  lowercase `version`, or the persisted-row spelling `kVersion`, and `.cc`
  is scanned with the other translation units. `hf_version` is compared.
  Those comparisons are rows, and they are deleted with the mechanism (§5).

**What the extractor reads, and what it leaves alone.** A comparison counts
with a version on either side: `version >= 5`, `5 < version`,
`(version) >= 5`. A lone `<` or `>` is a template bracket as often as a
comparison, so it counts only with a version on its left and a value on its
right, or a constant on its left and a version on its right, and never where
the `>` closes a bracket the line opened. The contents of string and
character literals are blanked before a line is judged: an error message that
says "tx version < 3" is prose, and two such rows left the inventory on
2026-10-06 when that was made so.

## 8. Changing the inventory

Run `python3 scripts/ci/check_cxx_version_gates.py --dump` for the tree's
hits. A new comparison needs a row: its operand, what it evaluates to at
Shekyl's value, one §3 token, and one §4 token. Anything else is not a row.
A row whose site is deleted is deleted. The better change is not to add the
comparison: nothing in this tree should branch on a fork number.

The gate compares sets, not counts, so adding one gate while removing
another fails. It refuses an empty source tree and an empty inventory, so it
cannot go quietly green when the C++ is gone; it is deleted then, with this
document.
