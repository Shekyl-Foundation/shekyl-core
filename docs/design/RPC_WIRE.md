# RPC wire — the daemon RPC's contract (RW)

**Status:** LIVING CONTRACT — the daemon RPC wire's contract of record, last verified 2026-10-18 at `2470176c1`. RW-Q2…RW-Q7 ruled 2026-10-17; RW-Q1, RW-Q8, RW-Q9 and RW-Q10 ruled 2026-10-18 (Rick); each question carries its ruling in its own line. It carries the KV cutover's decisions still in force, with their IDs (*Carried decisions*). The name census (RW-Q1, RW-Q6, RW-Q10) is `INPUT_GRAMMAR.md` Part C, ruled 2026-10-19. `get_info`'s wire stays in [`DAEMON_RPC_KV_GET_INFO.md`](DAEMON_RPC_KV_GET_INFO.md) until this document absorbs it. Family `RW-` (`RW-Q`, `RW-F`), registered in `IMPLEMENTATION_INDEX.md`.
**Origin:** the daemon RPC KV lane's retirement, ruled by Rick 2026-10-17:
1. Retire the KV lane as a migration program; restructure what nobody else owns.
2. RPC method names join the input-grammar glossary (`INPUT_GRAMMAR.md` §1 "brought in by ruling").
3. One call form; epee leaves the RPC wire with the rest of the C++.
4. Bans and `stop_daemon` fold into DRS-X PR 3b, so the flip deletes the C++ RPC server whole.
5. The console moves to `shekyl-cli` as an RPC-lane slice (R8).

**Ground of the findings:** `dev` `0be5ead54` (RW-F1…RW-F3); the contract is verified at the Status line's commit.

## RW-Q1 — What a method name is — RULED 2026-10-18

- **Problem.** Today's names are Monero's:
  - a `get_` verb on every read;
  - C++ handler names leaked onto the wire (`on_get_block_hash`);
  - 13 alias spellings: nine on JSON-RPC (`getblock`, `submitblock`, …) and four REST paths (`/getinfo`, `/getblocks_by_height.bin`, …), RW-F2;
  - four methods for one fact (block headers by height, by hash, last, range).

  The console word and the method behind it are two vocabularies (`chain height` vs `get_block_count`).
- **Ruling.** A method name is a command path under IG-3 as ruled (`INPUT_GRAMMAR.md`), `_`-joined on the wire (RW-Q9).
  - `get` is never a term. A state change ends in a verb.
  - A read ends in a view noun, which takes no selector, or in one of two read verbs: `show` (one item, by a typed selector) or `list` (a bounded list).
  - One method per reply type: `block header show`, with the selector `{"height": n}`, `{"hash": h}` or `"tip"`; `block header list`; `block show`; `block list` (bounded heights, replacing `get_blocks_by_height.bin` and its REST alias, RW-Q5).
  - Where a console word exists (`INPUT_GRAMMAR.md` §13), the method takes its path.

## RW-Q2 — The envelope — RULED 2026-10-17

- **Problem.**
  - The parser tolerates a missing `jsonrpc`, and decodes a missing `id` as `null` (`types.rs`, `JsonRpcRequest`).
  - Two methods take positional arrays (`on_get_block_hash`, `submit_block`).
  - REST paths answer with their own envelope and their own HTTP status.
  - Batches are already refused by the parse.
- **Ruling.** The envelope is strict JSON-RPC 2.0:
  - `"jsonrpc": "2.0"` required.
  - A non-null `id` required: no notifications, so every call is answered.
  - `params` is a named object only.
  - One request per message, on one path.
  - HTTP status describes the transport only.

  Every tolerance is a second way to say the same thing (IG-5, applied to the wire), and a notification is a call whose failure nobody hears.

## RW-Q3 — Errors — RULED 2026-10-17

- **Problem.** A failure reaches a client three ways:
  - a `status` string inside a successful reply. 20 reply fields carry one (RW-F3), and `shekyl-cli` matches free text such as `"Already mining"` (`rust/shekyl-cli/src/daemon.rs`);
  - JSON-RPC codes inherited from Monero (`-1` … `-25`);
  - REST error envelopes.

  Only `option_set`'s `-26` carries typed diagnostics (#1088).
- **Ruling.** A failure is only ever the JSON-RPC error object:
  - `status` leaves every reply.
  - A closed code registry lives in `shekyl-rpc-types`.
  - The numeric code is a class a client branches on: bad params, refused by the method, outside the grant, over a resource bound, not ready, store fault, internal.
  - `data` carries IG-11's typed diagnostic: a stable dotted code, its parameters, and one English renderer.

  A state a reply legitimately describes stays data (`offline` on `get_info`, 3.56); a method that cannot answer refuses. Grant refusal (RT-W10) and resource refusal (`RPC_CHANNEL.md` §6.3) are two classes in this registry, so §6.2's second refusal shape ("HTTP 403 on REST") retires.

## RW-Q4 — One encoding per value kind — RULED 2026-10-17

- **Problem.**
  - An amount is a JSON number in block headers (`reward`) but a decimal string on `get_info` (FOLLOWUPS row).
  - 61 `skip_serializing_if` sites inherit epee's omissions (RW-F3), including an empty list dropped from the document (RK-3b).
  - `#[serde(default)]` lets an omitted field read as zero (FOLLOWUPS row).
  - Whether a field is a count or a height still differs by field (`HEIGHT_SEMANTICS.md`).
- **Ruling.** Every wire value takes exactly one encoding per kind. Where a wire kind is also a grammar kind (`hash`, `bytes`), the syntax is IG-6's. The wire amount is its own kind: atomic units, where IG-6's `amount` is the decimal SKL an operator types.
  - amount → decimal atomic units (`AtomicUnitsString`);
  - 128-bit quantity → `HexU128`;
  - hash → `HashHex`;
  - height vs count named in the field, per `HEIGHT_SEMANTICS.md`;
  - RK-D23's three states everywhere: absent means withheld by grant, `null` means no answer, `0` is a value;
  - an empty list is `[]`;
  - no `serde(default)` on any reply field.
- **Bodies — RULED 2026-10-18.** IG-6 gains `bytes` (base64, RFC 4648 §4, padded) for block and transaction bodies; hex remains the hash kind only. Bodies are what a wallet scanning a remote daemon over Tor pulls in bulk: hex doubles them, base64 costs 4/3. The glossary term `hex` is replaced by `body` ("a block's or transaction's serialized bytes, kind `bytes`"); `INPUT_GRAMMAR.md` §12.3 is `tx show <id> --body` and `tx decode <body>`, and §13's `print_tx` row follows.

## RW-Q5 — The two `.bin` methods — RULED 2026-10-17

- **Problem.** Epee leaves the RPC wire (ruled). Two methods still use it.
  - **`get_o_indexes.bin`.**
    - Its one consumer asks once per block, for the coinbase, to learn the block's first global output index (`block_fetch.rs:28–34`, `:494–519`).
    - The wallet avoids per-output asks because they leak which outputs it owns.
    - So a by-txid output-index method leaks by construction, and is kept alive to answer a fact every block carries.
  - **`get_blocks_by_height.bin`.** It has two consumers: the engine's timing rig (`daemon_observability.rs:21`, `:80`), and `shekyl-chain-ingest`'s fetch (`fetch.rs:45`), the corpus builder behind `shekyl-chain-replay` and the chain-ingest file source that `INPUT_GRAMMAR.md` IG-Q26 names as offline bootstrap's successor (RW-F1). It also answers a second REST spelling, `/getblocks_by_height.bin` (`server.rs:267`, RW-F2). The FOLLOWUPS attestation-witness sidecar row concerns this method.
- **Ruling.**
  - The first output index becomes a field of the block reply, and the by-txid method is deleted. The field is the same for every caller, so it says nothing about who is asking.
  - The block view takes a bounded list of heights (`block list`, RW-Q1; resource policy §6.3), replacing `get_blocks_by_height.bin` and its REST alias, with the sidecar row re-homed to the block reply's shape, and both consumers moved to it in the same PR.

  The safest query is the one that does not exist.

## RW-Q6 — The version read — RULED 2026-10-17

- **Problem.**
  - RK-D25 freezes `get_version`'s `version` field (the key, a JSON integer, `(major << 16) | minor`) so that a client can always report "this daemon is newer".
  - It freezes the field, not the method's name.
  - If the method is renamed at 4.0, an older client gets "method not found", which is exactly the undiagnosable skew RK-D25 exists to prevent.
- **Ruling.** The version read is named once, `version` (already a glossary subject), and the freeze extends to the method's name and its empty params from the ruling on. Every release before genesis wipes, so freezing from now costs one rename. Part C states that `version` is callable at every grant and that only its `version` field is frozen in the reply (RW-Q8).

## RW-Q7 — One method table — RULED 2026-10-17

- **Problem.** A method's facts live in several places:
  - the dispatch match (`native_method_for`, `json_rpc.rs:207`);
  - `RESTRICTED_METHODS` (`:49`) and its spec test;
  - `RPC_CHANNEL.md` §6.1's grant table, as prose;
  - the route list in `server.rs`;
  - each client's own constants. `shekyl-cli` even runs its own HTTP client (ureq) with its own reply types (`rust/shekyl-cli/src/daemon.rs`), against RK-D1.

  RK-D6 asked for one list, and the FOLLOWUPS dual-list row is still open.
- **Ruling.** There is one method table in `shekyl-rpc-types`.
  - Each row: the grammar path (the method name is the path joined with `_`, RW-Q9; the console word, if the method has one, is the same path), request type, reply type, grant (or host-only, or armed lever), resource bound.
  - `INPUT_GRAMMAR.md` §13's method rows are generated from the table, so each name has one home (IG-15); words with no method (`help`) stay in `shekyl-cli`'s own table (IG-9). The IG-3 walk covers method names; a new term is a glossary row ruled like any other.
  - Dispatch, the grant check, the generated docs and every client's call are built from it.
  - A gate checks that every served method is a row and every row is served (the IG-9 pattern).

  It carries RK-D6 (restricted-mode policy single-sourced in Rust: the table's grant column is the policy), closes the FOLLOWUPS dual-list row, gives RT-W10 its grant table as data, and makes the rename a one-table edit.

## RW-Q8 — Sequencing — RULED 2026-10-18

- **Problem.**
  - PR 3b writes about 15 new request and reply types soon.
  - RT-P5 has not run, and it derives RT-O6's padding classes from per-method HTTP message sizes (`RPC_CHANNEL.md:1670`).
  - RT-W10's grant table is keyed by method name.
- **Ruling.** The round lands in two halves.
  - **Conventions** (Q2–Q5, Q7), ruled 2026-10-17; PR 3b is built to them.
  - **The name table** (Q1, Q6, Q10) is drafted with a census of every served method, its parameters and its reply fields, as `INPUT_GRAMMAR.md` Part C: the glossary rows and the walk are the grammar's, and it is ruled before the rename. Part C also states that `version` is callable at every grant and that only its `version` field is frozen in the reply. It lands in one rename PR after the flip, at `CORE_RPC_VERSION` 4.0, with every in-tree client changed in the same PR and the GUI repository's change paired with it.
  - RT-P5 measures after the rename, and its registration names the wire it measured.

  Renaming after the flip keeps DX-Q8's two-binary comparison free of a name map; ruling conventions before PR 3b means no type is written twice.

## RW-Q9 — The wire rendering of a path — RULED 2026-10-18

- **Problem.** `INPUT_GRAMMAR.md` IG-1 joined a name's segments with hyphens only, while RT-O23 joined `option set`'s terms with `_` on the wire (`option_set`), so no gate could check a method name.
- **Ruling.** IG-1 states the renderings of one path: words at the prompt; `-`-joined in option names and TOML keys; `_`-joined on the wire for method, parameter and reply-field names. No other spelling.

## RW-Q10 — Parameter and reply-field names — RULED 2026-10-18

- **Problem.** The grammar's scope is every identifier a person types or a script depends on (`INPUT_GRAMMAR.md` §1). A script depends on a method's parameter names and its reply's field names as much as on the method name.
- **Ruling.** Parameter and reply-field names are glossary paths rendered with `_` (RW-Q9) and join Part C's census. A field's name never encodes its kind or unit; height versus count is named per RW-Q4.

## Findings at the ground

- **RW-F1 — a second consumer of `get_blocks_by_height.bin`.** `shekyl-chain-ingest`'s fetch (`fetch.rs:45`, `ROUTE`) builds corpora from it for `shekyl-chain-replay`; it is the chain-ingest file source IG-Q26 names as offline bootstrap's successor. RW-Q5's replacement serves it.
- **RW-F2 — the REST alias the first count left out.** `/getblocks_by_height.bin` (`server.rs:267`) answers beside `/get_blocks_by_height.bin`. With it the alias spellings are 13: nine on JSON-RPC (`getblockcount`, `on_getblockhash`, `getblockheaderbyheight`, `getblockheaderbyhash`, `getlastblockheader`, `getblockheadersrange`, `getblock`, `getblocktemplate`, `submitblock`) and four REST paths (`/getheight`, `/gettransactions`, `/getinfo`, `/getblocks_by_height.bin`). `on_get_block_hash` is not an alias: it is a C++ handler name leaked onto the wire, which RW-Q1's problem lists separately.
- **RW-F3 — the counts, measured.** At `0be5ead54`, `git grep -n 'pub status:' rust/shekyl-rpc-types rust/shekyl-daemon-rpc` finds 20 fields, and `git grep -c skip_serializing_if` over the same two crates finds 61 sites.

## Carried decisions

The KV cutover is retired (record: [`DAEMON_RPC_KV_CUTOVER.md`](../completed/DAEMON_RPC_KV_CUTOVER.md)). These of its decisions stay in force on the wire, with their IDs.

- **RK-D1 — Rust owns the wire types, once.** `shekyl-rpc-types` is the single definition of every daemon method's request and reply, consumed by `shekyl-daemon-rpc` (the server), `shekyl-rpc-client` (the wallet), `shekyl-cli` and the GUI. A client's own reply types are a duplicate: delete them, never synchronize them. `shekyl-cli`'s private HTTP client and its reply types go with R8 (`RPC_CHANNEL.md` RT-W15). One definition is the only one that cannot drift.
- **RK-D6 — restricted-mode policy is single-sourced in Rust.** Carried by RW-Q7's method table, whose grant column is the policy, and by RT-W10's grant table, which reads it.
- **RK-D7 — store-agnostic handlers.** Each family's facts arrive through a trait (`ChainFacts`, `InfoFacts`, `P2pFacts`, `ChainReadFacts`, …), so a handler and its tests do not know which store answers. Two implementations exist: the FFI shims (`FfiChainFacts`, `FfiInfoFacts`), which the server routes today, and `StoreFacts` over the Rust chain store (`rust/shekyl-daemon-rpc/src/store_facts.rs`), built and tested by DRS-X PR 3 (#1106) and not yet routed. The flip routes `StoreFacts` and deletes the shims (`DRS_X_STORE_FLIP.md` DX-Q3); handlers and tests do not change. This line names the shims, so the flip restates it (the flip PR's obligations, `DRS_X_STORE_FLIP.md` DX-Q7).
- **RK-D10 — a hash on this wire is `HashHex`.** 32 bytes, 64 lowercase hex characters: one wire-level type that validates the hex once, in the deserializer. It wraps raw bytes, not a domain newtype, because one block header carries hashes of four kinds; consumers name the kind at their edge (rule 18). Where a field's absent form is `""` (`block_header.pow_hash`), the type is `Option<HashHex>` with an explicit `""`-as-absent serde until RW-Q4's three states replace it.
- **RK-D23 — `0` is a value; no answer is `null`.** In Rust an absence is `Option`; on the wire it is `null`. With grants, a field the caller may not see is absent (RW-Q4's three states). A refused computation is a fault, not an absence: it is an error (RW-Q3).
- **RK-D25 — the version read is the one permanent part of the wire.** Frozen across every shape change, `CORE_RPC_VERSION` 4.0 included: the reply's key is `version`, and its value is the JSON integer `(major << 16) | minor`. RW-Q6 extends the freeze to the method's name (`version`; `get_version` until the rename) and its empty params. A client reads this one field through one function in `shekyl-rpc-types` before it decodes anything else, the only lenient reader of a daemon reply in the tree, because the check that diagnoses version skew has to survive the skew. A test pins that `{"version": N}` alone reads through the function.
- **The per-lock-domain rule.** A reply that reads more than one lock domain (the chain and the pool) reads each under its own lock in turn, and never holds one while taking the other: that is the AB half of an AB-BA deadlock, since `tx_memory_pool::check_for_key_images` takes the pool lock and then the chain's. The race between the passes is named in the method's contract, not closed with a nested lock. The rule is per lock-domain, not per reply. Its example is the C++ pool's, which the flip deletes (DEL-010); the flip restates the rule over the Rust pool's lock and the store's MVCC snapshot (the flip PR's obligations, `DRS_X_STORE_FLIP.md` DX-Q7).
