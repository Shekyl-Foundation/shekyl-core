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

## The wire vectors (`wire/`)

One request and one reply for every shape of every row of the method table
(`shekyl_rpc_types::wire::TABLE`, 42 methods, 100 files), ruled by Rick on
2026-11-12. They were written by hand from `docs/design/INPUT_GRAMMAR.md`
and never generated from the types or copied from a Rust fixture:

- Part C: §17 (the method census), §18 (the field census) and §19 (the
  glossary);
- Part F: §25 and §26, IG-Q73…IG-Q94 (slots, selectors, keywords, the
  verdict, the writer), with IG-Q55 and IG-Q56 as 4.1 reads them;
- `RPC_CHANNEL.md` §6.1 and §6.4, for the grant keywords and the option
  row's two forms.

The set was first written on 2026-11-12 at `f993270e85` for 4.0. At 4.1 the
same day the switched methods were split into one pair per shape, each
field a request did not select taken out of its reply (`RPC_WIRE.md`
RW-Q4 as amended).

### Layout

A method whose reply has fields a request switch selects has one pair per
set of switches turned on, named by them: `<method>.plain.*`,
`<method>.pow.*`, `<method>.prune.*` and `<method>.pow-prune.*`. Those are
`block_header_show` and `block_header_list` (`pow`), `block_list`,
`tx_show` and `tx_list` (`prune`), and `block_show` (both, four shapes).
`block_list` takes no `pow`, so its headers never carry one. Every other
method has `<method>.request.json` and `<method>.reply.json`.

A request file is the call's `params` object and a reply file is its
`result`; neither carries the JSON-RPC envelope, which is the same for
every method and is held by the daemon's envelope tests
(`shekyl-daemon-rpc`, `handlers/rpc_tests.rs`). A method with no parameters
has the request `{}`; an omitted `params` is the same request. A reply that
says only that the call succeeded is `{}`.

The values are plausible and consistent with each other: a tip at height
1199, hashes of 64 hex characters, padded base64, amounts in decimal atomic
units, `HexU128` as `0x` hex, durations in seconds and ratios in micro. A
`prune` reply carries the pruned body, and a plain one the whole body.

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

### What the tests check

`tests/wire_vectors.rs` walks the table:

1. Every shape of every row has both files, and every file in `wire/` names
   one. A shape's request turns on exactly the switches its name says.
2. Each vector conforms to its row's shape (`schema::conforms`), a reply
   read against the switches its request turned on
   (`schema::conforms_asked`).
3. Each vector reads as the method's type and writes back as the same JSON
   value.
4. That written form reads again as an equal value.
5. Every field a switch selects, in every shape, is edited: removed from a
   reply whose request asked for it, added to one whose request did not.
   Each edit must make the reply fail to conform. This is every shape's red
   edit.

A failure names the file. The dispatch is a `match` over `wire::Id` with no
wildcard arm, so a new row does not compile there until it is added.

### Adding a row

A new method needs its files, and they are written first, by hand, from the
grammar row that rules the method: §17's parameters, and §18's fields under
§19's terms, one pair per shape if its request takes a switch that selects
reply fields. Then add its arm to `row_faults`. If a file the grammar admits
does not read through the type, either the grammar or the type is wrong.
Settle that in the PR that adds the row, and never by editing the vector to
match the type.
