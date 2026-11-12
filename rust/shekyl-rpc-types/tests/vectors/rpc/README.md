# RPC wire vectors

## The 3.x corpus is retired

The 3.x oracle corpus (`<method>_<case>_v<N>.json` and `.bin`, epee's
captures of the C++ handlers) and its two parity suites, `rpc_parity.rs` and
`rpc_bin_parity.rs`, are deleted (Rick, 2026-11-12). Their purpose, RK-1's
parity with the C++ handlers at the cutover
(`docs/completed/DAEMON_RPC_KV_CUTOVER.md` §3.5), is discharged: the C++ is
gone and 4.0 renames the wire. The last commit that holds them is
`f993270e85`.

One 3.x reply is kept: `get_version_synced_v47.json`, a 3.70 daemon's
`get_version` result. `tests/skew.rs` reads it to show that this build's
version-first read refuses a 3.x daemon on the wire axis before it decodes
anything else (RK-Q11, RK-D25).

## The 4.0 wire vectors (`4.0/`)

One request and one reply for every row of the method table
(`shekyl_rpc_types::wire::TABLE`, 42 methods, 84 files), ruled by Rick on
2026-11-12. They were written by hand on 2026-11-12 at `f993270e85`, from
`docs/design/INPUT_GRAMMAR.md`:

- Part C: §17 (the method census), §18 (the field census) and §19 (the
  glossary);
- Part F: §25 and §26, IG-Q73…IG-Q94 (slots, selectors, keywords, the
  verdict, the writer);
- `RPC_CHANNEL.md` §6.1 and §6.4, for the grant keywords and the option
  row's two forms.

They were not generated from the types, and no Rust fixture was copied.

The files are the 4.1 wire, edited by hand from the grammar as IG-Q102 amends
it: a header's `section_root` in place of `attestation_root`, each block's
`section` and `section_body` (empty here: no block in these files admits a
bundle), no `complete_tree` on an `archival_claim_show` bond, and `version`
262145. The directory keeps its name.

### Layout

`4.0/<method>.request.json` is the call's `params` object, and
`4.0/<method>.reply.json` is its `result`. Neither carries the JSON-RPC
envelope: the envelope is the same for every method and is held by the
daemon's own envelope tests (`shekyl-daemon-rpc`, `handlers/rpc_tests.rs`).
A method with no parameters has the request `{}`; an omitted `params` is the
same request (`NoParams::from_params`). A reply that says only that the call
succeeded is `{}` (`Done`).

The values are plausible and consistent with each other: a tip at height
1199, hashes of 64 hex characters, padded base64, amounts in decimal atomic
units, `HexU128` as `0x` hex, durations in seconds and ratios in micro.

`daemon_status` is the host's full-disclosure reply, with every part shown.
Where a value has several forms, each file shows one or two:

- `block_header_list`, `block_list`, `txpool_flush` and `tx_relay` show an
  item and `{"missing": null}`. `tx_list` shows all four slot states: an
  item, `missing`, `archived` and `null`.
- `chain_height` and `daemon_status` show `writer` as `{"live": null}`.
- `tx_submit` shows `already-in-pool` with publication `public`. The other
  verdicts and causes are pinned in `tests/wire_contract.rs` and
  `tests/skew.rs`.
- `mine_status` shows the idle miner, with no job, a `null` address and a
  diagnostic `cause`.
- `option_show` shows a value row and a secret row.
- `relay_stats` shows a tally whose connector is `null`.
- `block_show` and `block_list` are asked with `prune`, so their
  transactions carry the txid operands. The unpruned form is not pinned
  here.

### What the test checks

`tests/wire_vectors.rs` walks the table:

1. Every row has both files, and every file in `4.0/` names a row's request
   or reply.
2. Each vector conforms to its row's shape (`schema::conforms`).
3. Each vector reads as the method's type and writes back as the same JSON
   value.
4. That written form reads again as an equal value.

A failure names the file. The dispatch is a `match` over `wire::Id` with no
wildcard arm, so a new row does not compile there until it is added.

### Adding a row

A new method needs both files, and they are written first, by hand, from the
grammar row that rules the method: §17's parameters, and §18's fields under
§19's terms. Then add its arm to `row_faults`. If a file the grammar admits
does not read through the type, either the grammar or the type is wrong.
Settle that in the PR that adds the row, and never by editing the vector to
match the type.
