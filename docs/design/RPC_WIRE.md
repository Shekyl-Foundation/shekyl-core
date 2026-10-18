# RPC wire grammar (RW) — Round 0, posed 2026-10-17

**Status:** OPEN — Round 0, posed to Rick 2026-10-17, not ruled. Family `RW-` (`RW-Q`, `RW-F`), checked free against `IMPLEMENTATION_INDEX.md` and the tree at `0be5ead54`.
**Origin:** the daemon RPC KV lane's retirement, ruled by Rick 2026-10-17:
1. Retire the KV lane as a migration program; restructure what nobody else owns.
2. RPC method names join the input-grammar glossary (`INPUT_GRAMMAR.md` §1 "brought in by ruling").
3. One call form; epee leaves the RPC wire with the rest of the C++.
4. Bans and `stop_daemon` fold into DRS-X PR 3b, so the flip deletes the C++ RPC server whole.
5. The console moves to `shekyl-cli` as an RPC-lane slice (R8).

**Ground:** `dev` `0be5ead54`; #1088 `daf109d23`; #1101 `b9be94775`; #1106 `5b1c97b2b`.

## RW-Q1 — What a method name is

- **Problem.** Today's names are Monero's:
  - a `get_` verb on every read;
  - C++ handler names leaked onto the wire (`on_get_block_hash`);
  - 14 alias spellings (`getinfo`, `getblock`, `submitblock`, …);
  - four methods for one fact (block headers by height, by hash, last, range).

  The console word and the method behind it are two vocabularies (`chain height` vs `get_block_count`).
- **Question.** Is a method name an IG path?
  - Subject first.
  - The last term is a view (a read) or a verb (a change).
  - The wire form joins terms with `_`, as RT-O23 did.
  - `get` is never a term.
- **Recommendation: yes.**
  - Examples: `chain_height`, `block_header`, `txpool_flush`, `ban_add`.
  - Where a console word exists, the word and the method share the path. Where none exists, the method still draws its terms from the glossary, and a new term is a glossary row ruled like any other.
  - One method per reply type. The four header methods become one view with a typed selector (height, hash, or the tip), because they return the same type. A range is its own list view, because its reply is a list.

## RW-Q2 — The envelope

- **Problem.**
  - The parser tolerates a missing `jsonrpc`, and decodes a missing `id` as `null` (`types.rs`, `JsonRpcRequest`).
  - Two methods take positional arrays (`on_get_block_hash`, `submit_block`).
  - REST paths answer with their own envelope and their own HTTP status.
  - Batches are already refused by the parse.
- **Question.** Is the envelope strict JSON-RPC 2.0?
  - `"jsonrpc": "2.0"` required.
  - A non-null `id` required: no notifications, so every call is answered.
  - `params` is a named object only.
  - One request per message, on one path.
  - HTTP status describes the transport only.
- **Recommendation: yes.**
  - Every tolerance is a second way to say the same thing (IG-5, applied to the wire).
  - A notification is a call whose failure nobody hears.

## RW-Q3 — Errors

- **Problem.** A failure reaches a client three ways:
  - a `status` string inside a successful reply. 25 reply types carry one, and `shekyl-cli` matches free text such as `"Already mining"` (`rust/shekyl-cli/src/daemon.rs`);
  - JSON-RPC codes inherited from Monero (`-1` … `-25`);
  - REST error envelopes.

  Only `option_set`'s `-26` carries typed diagnostics (#1088).
- **Question.** Is a failure only ever the JSON-RPC error object?
  - `status` leaves every reply.
  - A closed code registry lives in `shekyl-rpc-types`.
  - The numeric code is a class a client branches on: bad params, refused by the method, outside the grant, over a resource bound, not ready, store fault, internal.
  - `data` carries IG-11's typed diagnostic: a stable dotted code, its parameters, and one English renderer.
- **Recommendation: yes.**
  - A state a reply legitimately describes stays data (`offline` on `get_info`, 3.56). A method that cannot answer refuses.
  - Grant refusal (RT-W10) and resource refusal (`RPC_CHANNEL.md` §6.3) become two classes in this registry, so §6.2's second refusal shape ("HTTP 403 on REST") retires.

## RW-Q4 — One encoding per value kind

- **Problem.**
  - An amount is a JSON number in block headers (`reward`) but a decimal string on `get_info` (FOLLOWUPS row).
  - 56 `skip_serializing_if` sites inherit epee's omissions, including an empty list dropped from the document (RK-3b).
  - `#[serde(default)]` lets an omitted field read as zero (FOLLOWUPS row).
  - Whether a field is a count or a height still differs by field (`HEIGHT_SEMANTICS.md`).
- **Question.** Does every wire value take exactly one encoding per kind, matching IG-6?
  - amount → decimal atomic units (`AtomicUnitsString`);
  - 128-bit quantity → `HexU128`;
  - hash → `HashHex`;
  - height vs count named in the field, per `HEIGHT_SEMANTICS.md`;
  - RK-D23's three states everywhere: absent means withheld by grant, `null` means no answer, `0` is a value;
  - an empty list is `[]`;
  - no `serde(default)` on any reply field.
- **Sub-question: opaque byte bodies** (block and transaction blobs) are hex today.
  - Recommend base64 (RFC 4648 §4, padded) for bodies, and hex for the hash kind only.
  - Bodies are what a wallet scanning a remote daemon over Tor pulls in bulk. Hex doubles them; base64 costs 4/3.
  - That is two encodings for two kinds, each with its own job.
- **Recommendation: yes to all.**

## RW-Q5 — The two `.bin` methods

- **Problem.** Epee leaves the RPC wire (ruled). Two methods still use it.
  - **`get_o_indexes.bin`.**
    - Its one consumer asks once per block, for the coinbase, to learn the block's first global output index (`block_fetch.rs:28–34`, `:494–519`).
    - The wallet avoids per-output asks because they leak which outputs it owns.
    - So a by-txid output-index method leaks by construction, and is kept alive to answer a fact every block carries.
  - **`get_blocks_by_height.bin`.** Its consumer is the engine's timing rig (`daemon_observability.rs:21`, `:80`). The FOLLOWUPS attestation-witness sidecar row concerns this method.
- **Question.**
  - Does the first output index become a field of the block reply, and the by-txid method delete? The field is the same for every caller, so it says nothing about who is asking.
  - Does the block view take a bounded list of heights (resource policy §6.3), replacing `get_blocks_by_height.bin`, with the sidecar row re-homed to the block reply's shape?
- **Recommendation: yes to both.** The safest query is the one that does not exist.

## RW-Q6 — The version read

- **Problem.**
  - RK-D25 freezes `get_version`'s `version` field (the key, a JSON integer, `(major << 16) | minor`) so that a client can always report "this daemon is newer".
  - It freezes the field, not the method's name.
  - If the method is renamed at 4.0, an older client gets "method not found", which is exactly the undiagnosable skew RK-D25 exists to prevent.
- **Question.** Does RW name the version read once (proposed: `version`, already a glossary subject), and extend the freeze to the method's name and its empty params, from the ruling on?
- **Recommendation: yes.** Every release before genesis wipes, so freezing from now costs one rename.

## RW-Q7 — One method table

- **Problem.** A method's facts live in several places:
  - the dispatch match (`native_method_for`, `json_rpc.rs:206`);
  - `RESTRICTED_METHODS` (`:49`) and its spec test;
  - `RPC_CHANNEL.md` §6.1's grant table, as prose;
  - the route list in `server.rs`;
  - each client's own constants. `shekyl-cli` even runs its own HTTP client (ureq) with its own reply types (`rust/shekyl-cli/src/daemon.rs`), against RK-D1.

  RK-D6 asked for one list, and the FOLLOWUPS dual-list row is still open.
- **Question.** Is there one method table in `shekyl-rpc-types`?
  - Each row: name, request type, reply type, grant (or host-only, or armed lever), resource bound, and CLI word if any.
  - Dispatch, the grant check, the generated docs and every client's call are built from it.
  - A gate checks that every served method is a row and every row is served (the IG-9 pattern).
- **Recommendation: yes.**
  - It closes RK-D6 and the dual-list row.
  - RT-W10 gets its grant table as data.
  - The rename becomes a one-table edit.

## RW-Q8 — Sequencing

- **Problem.**
  - PR 3b writes about 15 new request and reply types soon.
  - RT-P5 has not run, and it derives RT-O6's padding classes from per-method HTTP message sizes (`RPC_CHANNEL.md:1621`).
  - RT-W10's grant table is keyed by method name.
- **Question.** Does the round land in two halves?
  - **Conventions** (Q2–Q5, Q7) are ruled now, and PR 3b is built to them.
  - **The name table** (Q1, Q6) is drafted with a census of every served method. It lands in one rename PR after the flip, at `CORE_RPC_VERSION` 4.0, with every in-tree client changed in the same PR and the GUI repository's change paired with it.
  - RT-P5 measures after the rename, and its registration names the wire it measured.
- **Recommendation: yes.**
  - Renaming after the flip keeps DX-Q8's two-binary comparison free of a name map.
  - Ruling conventions before PR 3b means no type is written twice.

## Correction to ruling 5 (R8's timing) — Claude's premise was wrong

- **What I claimed, and why it was wrong.** I said R8 had to follow RT-W10 because it needs the local leg. In fact `shekyl-cli` already reaches the daemon today and already serves `mine start`, `mine stop` and `mine status` (`rust/shekyl-cli/src/commands/mine.rs`; `daemon.rs:346`, `:366`) over its own client.
- **What the local leg changes.** It changes R8's transport, not whether R8 can exist. The transport moves with the other clients in RT-W12, whose list does not name `shekyl-cli` yet; add it.
- **R8 can start now:**
  - move the Rust console's renderers (`shekyl-daemon-rpc/src/console/`, 5,444 lines) into `shekyl-cli` under §13's words. Move them, don't rewrite them;
  - put `shekyl-cli` on `shekyl-rpc-client` and `shekyl-rpc-types`; its ureq client and free-text status matching go;
  - delete the C++ console, together with `shekyld <command>`'s client mode and `rpc_client.h`.
- **Why sooner is better.** If R8 lands before the flip, the 19 C++-console words the flip deletes already have successors.

## Brief 2, after RW is ruled (one consolidated PR)

- `DAEMON_RPC_KV_CUTOVER.md` moves to `docs/completed/`, banner `RETIRED`, citing its SHA.
- `docs/design/RPC_WIRE.md` becomes the living contract. It carries:
  - RK-D1, RK-D7, RK-D10, the per-lock-domain rule, RK-D23 and RK-D25, keeping their IDs;
  - the RW rulings;
  - RK-D6, which goes to RW-Q7 and RT-W10.
- `INPUT_GRAMMAR.md` §1 and rule 83's scope line bring method names in.
- `RPC_CHANNEL.md` changes:
  - §6.2's REST arm retires;
  - §13 gains RT-W15 (R8, `shekyl-cli` serves the console);
  - RT-W12 adds `shekyl-cli`.
- `DAEMON_RPC_KV_GET_INFO.md` stays the `get_info` contract until RPC_WIRE absorbs it.
- The FOLLOWUPS owners are re-pointed: amounts, `get_miner_data`, the witness sidecar, the claim-source tip hash, the serde defaults, and the dual-list row.
- The index rows are updated, and the 40 files citing the KV doc are re-pointed to wherever each cited decision now lives.
