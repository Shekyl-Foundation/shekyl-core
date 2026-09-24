# `tx_extra` Rust cutover — one codec, a C++ shim: Round-0 pre-flight

**Status:** LANDED — **§7 commits 1–5 landed 2026-09-23** on
`feat/tx-extra-rust-cutover` (built on `dev` @ `a744e2430`). The C++ `tx_extra`
parser, variant and helpers are deleted; `shekyl-wire` is the one codec and
the C++ daemon a transport shim over five FFI entry points. **`TXE-Q6`
REVERSED 2026-09-23 as `TXE-Q6′`** (§6): the coinbase `0x02` nonce is kept as
a **fixed 8-byte field inside a closed coinbase grammar** — census `CEN-I20`,
wire spec §9.6b — and genesis was regenerated to carry it as eight zero
bytes. This file stays in `design/` as the owner of §9's two equivalence
tables and of the grammar ruling until the `0x0B` producer amends the
grammar; the census row and the wire spec are the contract of record.
Round 0 executed 2026-09-22 at `7b9be6cd1`; Round 1 RULED 2026-09-22
(maintainer, PR #826): TXE-Q1 delete `construct_tx*` on the per-test
equivalence condition (§9.1 — the premise corrected there); Q2/Q3/Q4
defaults; Q5 the parser tests to a twin table (§9.2), the fuzzer re-pointed
as `fuzz_tx_extra_parse`. Governing rule:
[`20-rust-vs-cpp-policy.mdc`](../../.cursor/rules/20-rust-vs-cpp-policy.mdc)
§*Migration is a planning activity* — this document is that plan's first
round. FFI shape per
[`40-ffi-discipline.mdc`](../../.cursor/rules/40-ffi-discipline.mdc).
Identifier families `TXE-F` (findings) and `TXE-Q` (questions), registered
in [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 by this PR.

---

## 0. Why this, and why before alpha.9

`tx_extra` is parsed twice in this repository. `shekyl-wire::tx_extra`
(`rust/shekyl-wire/src/tx_extra.rs`) is the codec every Rust consumer uses —
the wallet stack, the scanner, `Transaction::from_bytes` (which applies
CEN-I19 over its own parse, `transaction.rs:1824`), the genesis tool, the
ingest pipeline. `parse_tx_extra` / `sort_tx_extra` and the eleven-arm
`std::variant` in `src/cryptonote_basic/tx_extra.h` are a second parser over
the same consensus-relevant bytes, and it is the one the **C++ daemon runs on
the block path today** — which, until the DRS cutover, is the consensus a
testnet enforces.

Two parsers over one wire grammar is the divergence class CEN-I19 was routed
through Rust to close (`shekyl_tx_extra_pqc_field_shape`, TXE-F3), and the
closure is partial: the C++ still parses, and hands Rust its *field
lengths*. Rule 20's instruction for a C++ surface that parses untrusted input
is not "keep it in step" but "the Rust codec is the implementation; the C++
is a transport shim." This pre-flight censuses what the daemon actually needs
from the C++ machinery (§1) — it is one writer and three reads — proposes the
FFI that replaces it (§3), and names the deletions (§4).

The alpha.9 testnet regenesis is the reason for *now*: the C++ daemon is what
the fleet will run, and a parser divergence found on a live testnet is found
by a chain split. Nothing here changes wire bytes; it changes which code
decides whether bytes parse.

---

## 1. Census at the pin (`dev` @ `7b9be6cd1`), verified at source

### 1.1 The C++ API (`cryptonote_format_utils.h:70–112`) and its production callers

"Production" is `src/` minus `debug_utilities/`. Every site listed was read;
line numbers are the pin's.

| C++ function | Production callers | What the caller needs | Disposition proposed |
|---|---|---|---|
| `parse_tx_extra` | `cryptonote_tx_utils.cpp:322` (in `construct_tx_with_tx_key` — TXE-F2, test-only); `blockchain_db.cpp:519` (the `0x07` leaf blob for the tree grow) | the `0x07` blob | **delete**; the DB read becomes one coarse call (§3, `shekyl_tx_extra_leaf_entries`) |
| `find_tx_extra_field_by_type` | `blockchain_db.cpp:522`; `cryptonote_tx_utils.cpp:326` (test-only path) | as above | **delete** |
| `sort_tx_extra` | `cryptonote_tx_utils.cpp:136`, `:262` (`construct_miner_tx`); `:582` (`construct_tx_with_tx_key`, test-only) | canonical field order for the coinbase extra | **delete**; the coinbase extra is built canonical by Rust (§3, `shekyl_coinbase_extra`) |
| `add_tx_pub_key_to_extra` (3 overloads) | `cryptonote_tx_utils.cpp:132` (coinbase); `:481` (test-only) | writes `0x01` | **delete** (folded into the coinbase call) |
| `add_extra_nonce_to_tx_extra` | `cryptonote_tx_utils.cpp:134` (coinbase); `:349`, `:382` (test-only) | writes `0x02` | **delete** (folded) |
| `remove_field_from_tx_extra` | `cryptonote_tx_utils.cpp:348`, `:480` — **both test-only** (TXE-F2) | — | **delete** |
| `get_tx_pub_key_from_extra` (3 overloads) | `core_rpc_server.cpp:580` (miner tx pubkey on a block RPC) | one 32-byte key | **replace** with `shekyl_tx_extra_tx_pubkey` (fixed-size → raw out pointer, rule 40) |
| `get_additional_tx_pub_keys_from_extra` (2 inline stubs) | none — the body is `return {}` | — | **delete** (TXE-F6) |
| `parse_archival_attestation_from_extra` | `blockchain.cpp:5140` (`headers_readable`, consensus — the `0x0B` reader FOLLOWUPS keeps) | the `0x0B` blob, with *unparseable extra* distinct from *tag absent* | **replace** with `shekyl_tx_extra_field(…, 0x0B, …)`; the two-outcome contract is the FFI's result code |
| `add_archival_attestation_to_tx_extra` | none in `src/` — only `tests/unit_tests/archival_credit_wire.cpp` | — | **delete**; the test builds its blob through the shim or a Rust fixture (TXE-Q5) |
| `set_/get_(encrypted_)payment_id_*_tx_extra_nonce` (4) | `cryptonote_tx_utils.cpp:330–381` — **all inside `construct_tx_with_tx_key`** (test-only) | — | **delete with TXE-Q1** |
| `check_tx_extra_pqc_field_shape` | `cryptonote_core.cpp:799`, `blockchain.cpp:1449`, `blockchain_db.cpp:511` | CEN-I19 | **keep the C++ name as a shim**, but its body stops parsing: it hands Rust the raw `extra` and `vout.size()` (TXE-F3) |
| the `tx_extra_field` variant, its structs, `VARIANT_TAG`s (`tx_extra.h:126–240`) | all of the above | — | **delete** with the last parser |

### 1.2 The one production writer: `construct_miner_tx` (`cryptonote_tx_utils.cpp:126–266`)

Builds the coinbase extra as: `add_tx_pub_key_to_extra` (`0x01`) →
optional `add_extra_nonce_to_tx_extra` (`0x02`, the template's reserve) →
`sort_tx_extra` → per-output `shekyl_construct_output` (already Rust) whose
KEM ciphertexts and leaf entries are concatenated into `0x06` / `0x07`
fields, serialized through the C++ variant (`:255–260`) and appended →
`sort_tx_extra` again. The only field content C++ *originates* is the tx
pubkey (a `keypair::generate` at `:131`) and the nonce it was handed; the
PQC content already comes from Rust and is round-tripped through the C++
serializer only to be laid out.

`construct_miner_tx`'s callers: `blockchain.cpp:1823`, `:1832` (the block
template). The **block template / coinbase writer has no Rust owner**
(TXE-F8): E6 slice 4 is landing the coinbase *judge* (F1–F10, F13, F20 —
`CHAIN_RULES_SLICE_4.md` §4), not the builder.

### 1.3 Test callers (`tests/`), by file

| File | Refs to the tx_extra API | What they are |
|---|---|---|
| `unit_tests/test_tx_utils.cpp` | 66 | 27 `TEST`s of the C++ parser itself: padding edge cases, `sort_tx_extra` order, `remove_field_from_tx_extra`, the PQC round trip through sort |
| `unit_tests/archival_credit_wire.cpp` | 14 | build `0x0B` blobs with `add_archival_attestation_to_tx_extra`, then read them back |
| `core_tests/chaingen.cpp` | 13 | the chain generator's tx construction (via `construct_tx*`, TXE-F2) |
| `unit_tests/mining_parity.cpp` | 9 | coinbase extra parity checks |
| `unit_tests/tx_extra_pqc_field_shape.cpp`, `pqc_spend_fixture.h`, `node_server.cpp`, `json_serialization.cpp`, `core_tests/transaction_tests.cpp`, `bulletproof_plus.cpp`, `performance_tests/*` | 1–2 each | fixtures that assemble an extra |
| `fuzz/tx-extra.cpp` | 1 | fuzzes the **C++** parser |

`construct_tx` / `construct_tx_with_tx_key` / `construct_tx_and_get_tx_key`
have **zero callers in `src/`** and ~20 in `tests/` (`transaction_tests.cpp`
8, `chaingen.cpp` 3, `check_tx_signature.h` 3, …).

### 1.4 The Rust codec (`shekyl-wire::tx_extra`, pin)

`parse`, `serialize` (canonical order; refuses an unknown tag — there is no
generic skip), `pqc_kem_per_output`, `pqc_leaf_entries_per_output`,
`check_pqc_field_shape[_of]`, `check_pqc_leaf_entries`,
`conforming_pqc_leaf_{entry,blob}`. Parity with the C++ is asserted by
`tests/tx_extra_roundtrip.rs` (the padding/nonce caps are named "oracle
parity" in-source) and by `TX_EXTRA_PQC_ROUND_TRIP.json`. After the cutover
those are the *only* tests of the grammar, and the JSON vector is the pinned
form (TXE-Q5).

---

## 2. Scope

### 2.1 In

- The FFI surface of §3 (four entry points; three if TXE-Q2 folds).
- `construct_miner_tx` builds its extra through `shekyl_coinbase_extra`.
- `blockchain_db.cpp`'s leaf read, `blockchain.cpp`'s attestation read,
  `core_rpc_server.cpp`'s pubkey read go through the shim.
- `check_tx_extra_pqc_field_shape` stops parsing (TXE-F3).
- Deletion of everything in §1.1 marked *delete*, the variant and its
  structs, and `tests/fuzz/tx-extra.cpp` — **replaced in the same commit**
  by `rust/shekyl-wire/fuzz/fuzz_targets/fuzz_tx_extra_parse.rs`, seeded
  from `tests/data/fuzz/tx-extra/` (TXE-Q5b: the fuzzer follows the
  grammar's surviving implementation; it is not retired with the oracle).
- The C++ tests of §1.3, per TXE-Q5.

### 2.2 Out (named, so it is not scope shed by omission)

- **Parsing the `0x0B` attestation blob's records.** `verify_block_attestation`
  parses record bytes in C++ after this read; that is a second grammar with
  its own owner (`ARCHIVAL_CREDIT_WIRE.md`; the producer is blocked behind the
  attestation-verify reordering, FOLLOWUPS). This cutover hands the blob over
  opaque and stops.
- **The block template in Rust.** TXE-F8 names the gap; this PR builds the
  coinbase *extra* in Rust because that is the codec's job, not the template.
  Who builds the template is a question for E6 after slice 4 (§6, TXE-Q3
  names the falsifier).
- **`debug_utilities/cn_deserialize.cpp`** (three `parse_tx_extra` calls in a
  pretty-printer). Dies with the C++ tooling at cutover; until then it shims
  through `shekyl_tx_extra_field` in a loop over the known tags, or is deleted
  now if nobody runs it — Round 1 decides with TXE-Q1's disposition of the
  test-only surface.
- The wallet-side `ExtraField` (`shekyl-scanner/src/extra.rs`) — already
  Rust over the same codec; untouched.
- **FA-6b** (whether the `0x09` view-tag hints are classically linkable) —
  an audit that gates the multisig *producer*, not the codec; owner
  `V3_1_MULTISIG_RUST_ENGINE.md`. Named here because `0x09` is STAGED on
  that producer.

---

## 3. The contract (frozen by Round 1; landed as written, with the TXE-Q6′ amendments below)

### 3.1 The FFI surface (rule 40: coarse calls; `ShekylBuffer` out for variable length, raw pointers for fixed; distinct codes, never booleans)

| Entry point | Replaces | Shape |
|---|---|---|
| **`shekyl_tx_extra_field(extra, extra_len, tag, index, out: ShekylBuffer*) -> i32`** | `parse_tx_extra` + `find_tx_extra_field_by_type`; `parse_archival_attestation_from_extra` | Parses the whole extra with `shekyl-wire::tx_extra::parse`, returns the `index`th field of `tag` as its **payload bytes**. Codes: `OK`, `ABSENT` (parse succeeded, no such field — the committed empty set for `0x0B`), `MALFORMED` (the extra does not parse — `headers_readable = false`), `UNKNOWN_TAG` (caller asked for a tag the grammar does not have — a caller bug, reported distinctly, the marshalling-error pattern of the I19 FFI). `ABSENT` vs `MALFORMED` is the two-outcome contract `parse_archival_attestation_from_extra`'s comment states in prose; here it is the return type. |
| **`shekyl_tx_extra_tx_pubkey(extra, extra_len, out32: *mut u8) -> i32`** | `get_tx_pub_key_from_extra` | Fixed-size result → raw out pointer written directly into the caller's `crypto::public_key` (rule 40, *direct-write*). Same codes minus `UNKNOWN_TAG`. |
| **`shekyl_tx_extra_leaf_entries(extra, extra_len, n_outputs, out: ShekylBuffer*) -> i32`** | `blockchain_db.cpp:511–528`'s *three* passes (shape check, re-parse, find) | One call: parse, apply CEN-I19 (`check_pqc_field_shape_of`), return the `0x07` blob. Codes: `OK`, the I19 shape codes (already minted for `shekyl_tx_extra_pqc_field_shape`), `MALFORMED`. `n_outputs == 0` returns an empty buffer with `OK` (the rule's leafless case). |
| **`shekyl_coinbase_extra(tx_pubkey32, nonce, nonce_len, kem_blob, kem_len, leaf_blob, leaf_len, n_outputs, out: ShekylBuffer*) -> i32`** | `add_tx_pub_key_to_extra` + `add_extra_nonce_to_tx_extra` + the variant serialization of `0x06`/`0x07` + both `sort_tx_extra`s | Builds `[PubKey, Nonce?, PqcKemCiphertext, PqcLeafEntries]` and serializes canonically; applies CEN-I19 to what it built before returning it (a template that cannot pass admission is refused here, not at the miner). Nonce cap is the codec's (`TX_EXTRA_NONCE_MAX_COUNT`). `n_outputs == 0` (no KEM/leaf fields) is the leafless coinbase. |

Not minted: a general `shekyl_tx_extra_sort` / `serialize`. The only
production writer is the coinbase, and a general re-sorter's callers are
`construct_tx_with_tx_key` (TXE-F2) — minting one would be pre-provisioning
for a caller that is itself proposed for deletion (rule 21). If TXE-Q1 keeps
`construct_tx*`, the sorter is minted with it, named.

**`check_tx_extra_pqc_field_shape` after the cutover:** keeps its C++
signature (three callers) but becomes `shekyl_tx_extra_pqc_field_shape_of(extra,
extra_len, n_outputs, out_msg, cap)` — Rust parses the bytes it judges. The
existing lengths-taking entry point is deleted with the C++ parser that fed
it (TXE-F3).

### 3.2 What the shim may not do

Parse. Every C++ site above receives either a fixed-size value or an opaque
payload it stores or forwards. The one C++ that still reads inside a payload
after this PR is the attestation-record parser (§2.2), and that is named as
the next boundary, not left implicit.

### 3.3 Failure discipline

Rule 40 §*Refuse, never panic*: every entry point is `catch_unwind`-guarded
as the I19 one is; a malformed extra on the block path is a refusal code the
caller already knows how to turn into `false`; `out` buffers are written only
on `OK`. No secret crosses any of these calls (the tx pubkey is public; the
KEM ciphertexts are public), so §*Secret material* does not apply and
`ShekylBuffer` is the right shape for the blobs.

---

## 4. Deletions this lands (rule 15: the default is delete)

`tx_extra.h`: the `tx_extra_field` variant, `tx_extra_padding`,
`tx_extra_pub_key`, `tx_extra_nonce`, `tx_extra_additional_pub_keys`,
`tx_extra_pqc_kem_ciphertext`, `tx_extra_pqc_leaf_entries`,
`tx_extra_pqc_view_tag_hints`, `tx_extra_pqc_spend_auth_pubkeys`,
`tx_extra_archival_attestation`, eleven `VARIANT_TAG`s; the `TX_EXTRA_TAG_*`
defines stay only if a C++ caller still names a tag (the `0x0B` read does —
one define survives, or the shim takes a named enum).
`cryptonote_format_utils.{h,cpp}`: every row of §1.1 marked *delete*
(`parse_tx_extra`, `sort_tx_extra`, `find_tx_extra_field_by_type`, the
`add_*`/`remove_*` family, the four payment-id nonce helpers, the two inline
stubs). `tests/fuzz/tx-extra.cpp`. Under TXE-Q1 default: `construct_tx`,
`construct_tx_with_tx_key`, `construct_tx_and_get_tx_key` and their ~20 test
callers' construction path.

---

## 5. Round-0 findings

| Id | Finding | Verified at |
|---|---|---|
| **TXE-F1** | **Two parsers on the block path.** The C++ daemon parses `extra` with `parse_tx_extra` (`blockchain_db.cpp:519`) and Rust parses it with `shekyl-wire` (`Transaction::from_bytes`, ingest, wallet). Both implement one grammar; the C++ is the consensus one on testnet until cutover. | `tx_extra.h:126–240`, `cryptonote_format_utils.cpp:491`, `transaction.rs:1824` |
| **TXE-F2** | **`construct_tx*` has zero production callers.** `construct_tx`, `construct_tx_with_tx_key`, `construct_tx_and_get_tx_key` (`cryptonote_tx_utils.cpp:301–725`) are called only from `tests/`. They are the wallet-era C++ transaction builder — every `remove_field_from_tx_extra`, every payment-id nonce helper, and one of the three `sort_tx_extra`s exist for them alone. The Rust tx-builder is the producer. | `rg 'construct_tx\(' src` → 0 outside the definition |
| **TXE-F3** | **CEN-I19's Rust rule judges C++-parsed lengths.** `shekyl_tx_extra_pqc_field_shape` takes `kem_lens` / `leaf_lens` the C++ parser produced; the shape is Rust's, the parse is not. `blockchain_db.cpp:511–522` then parses **again** to extract the blob, with a comment that names the second parse failing as "(bug)". One coarse call removes both the dependency and the double parse. | `shekyl_ffi.h:1423`, `blockchain_db.cpp:505–528` |
| **TXE-F4** | **The `0x0B` payload has a C++ record parser behind the read.** `parse_archival_attestation_from_extra` returns the blob; `verify_block_attestation` reads records out of it. Out of this cutover's scope (§2.2) and named as the next boundary. | `blockchain.cpp:5133–5197` |
| **TXE-F5** | **The C++ parser's tests are tests of the C++ parser.** 27 `TEST`s in `test_tx_utils.cpp` assert padding edge cases, sort order and field removal of a codec that would no longer exist. `shekyl-wire`'s round-trip tests already pin the same cases as "oracle parity". | `test_tx_utils.cpp:46–437` |
| **TXE-F6** | `get_additional_tx_pub_keys_from_extra` is two inline stubs returning `{}` ("removed in V3"); nothing calls them. Dead by inspection. | `cryptonote_format_utils.h:88–90` |
| **TXE-F7** | The C++ still serializes Rust-produced bytes: `construct_miner_tx` takes KEM ciphertexts and leaf entries from `shekyl_construct_output` and lays them out through the C++ variant serializer (`:255–260`). Rule 40's "C++ never parses Rust-emitted bytes; Rust never parses C++-emitted bytes" is violated in the *serialize* direction. | `cryptonote_tx_utils.cpp:186–262` |
| **TXE-F9** | **CEN-M4's bound is stated twice in `shekyl-wire` and the two disagree.** `transaction.rs:1808` exempts the coinbase from `MAX_TX_EXTRA` (24 576) — matching the C++, where the cap is relay-only, `kept_by_block` exempt (`tx_pool.cpp:273`) and consensus has no `tx_extra` bound (census CEN-M4) — while `block.rs:40`'s doc describes the coinbase as "`≤ MAX_TX_EXTRA` extra". The cutover moves *which implementation decides* and the coinbase writer is the path it replaces, so the bound must be shown not to move (§8). | `transaction.rs:132`, `:1808`; `block.rs:40`; `tx_pool.cpp:273`; `cryptonote_config.h:351` |
| **TXE-F10** | **The archival attestation path is one unbuilt mechanism tracked as four rows** — producer (FOLLOWUPS `0x0B`), C++ verify-behind-PoW reorder, CEN-B4 in Rust (waits on E4 S-ARCH), and TXE-Q4. `headers_readable` is constantly `true`/empty on every real block: the collapsed observable sits one level in — the loop inside `if (headers_readable)` never has a record. **`ERR_HEADERS_UNREADABLE` is reachable**, not a belt: on both acceptance paths `verify_block_attestation` (`:2242` alt, `:5299` main) runs *before* `prevalidate_miner_transaction` (`:2248`, `:5428`), which holds the I19 coinbase parse check — so an unparseable coinbase extra meets the attestation verifier first and this arm is the first refusal it gets (which is also why the verify-behind-PoW row exists). The producer breaks the cluster, and its home is the unowned block-template writer (TXE-F8). One FOLLOWUPS row now names all four. | `blockchain.cpp:5133–5197`; FOLLOWUPS (the cluster row) |
| **TXE-F8** | **The block template has no Rust owner.** E6 slice 4 lands the coinbase judge (`CHAIN_RULES_SLICE_4.md` §4: F1–F10 as a miner-transaction rule class); no DRS plan, index row or FOLLOWUPS row owns the builder. This cutover moves the coinbase *extra* into Rust and leaves the template where it is. **CLAIMED 2026-09-24 by E6 slice 6 (`CHAIN_RULES_SLICE_6.md` §5.3): the owner is the new crate `shekyl-block-template` — `create_block_template`'s successor, store-free, pure over a caller-supplied context — whose first consumer is the slice's scenario driver; `get_block_template`'s Rust handler and the built-in miner are the next two. This row is that crate's row.** | `rg -i 'block template\|construct_miner_tx' docs/design` → no owner *(records-was; the owner is now `CHAIN_RULES_SLICE_6.md` §5.3)* |

---

## 6. Round-1 questions — RULED 2026-09-22 (maintainer, on PR #826; each row line-local)

| Q | Question | Default | Why |
|---|---|---|---|
| **TXE-Q1** | Delete `construct_tx*` (TXE-F2) in this cutover and migrate its ~20 test callers, or leave the test-only builder and mint the sorter/nonce helpers it needs? | **RULED: delete — with one condition on the migration.** Premise re-verified by the maintainer: the only `src/` hit outside `cryptonote_tx_utils` is `fill_construct_tx_rct_stub` (`src/fcmp/ct_semantics.cpp:86`), which *supports* `construct_tx_with_tx_key` (`:644`) rather than calling it. **The condition:** the ~20 migrated callers must keep **exercising the same cases**, not merely compile and pass — demonstrated **per test**, in a table (C++ case → what the Rust-built fixture produces for it and why that is the same case), the same shape and for the same reason as the `nm` symbol-list gate. If Rust-built fixtures quietly produce different transactions, the C++ consensus suite's coverage changes at exactly the moment C++ is consensus. | A second writer beside the Rust tx-builder is the two-sources problem on a wire grammar — the worst place to keep one. **The distinction that decides what goes is parser-versus-scaffolding, not dies-later:** §0 argues the cutover lands *before* alpha.9 because the C++ path is consensus there, and `chaingen.cpp` is as much a part of that C++ path as `blockchain.cpp` is — so "dies with the C++ daemon" cannot be the reason its coverage may change. `construct_tx*` goes because it is a second *parser/writer* of the grammar; the suite it fed stays whole because it is the consensus suite's *scaffolding*. |
| **TXE-Q2** | Is the coinbase extra one coarse call (`shekyl_coinbase_extra`) or three primitives (`add pubkey`, `add nonce`, `append pqc`) plus a sort? | **RULED: one call** (default held). | Rule 40 §*Coarse calls*: orchestration in C++ is where contract mismatches live, and a coinbase extra that is built and I19-checked in one place cannot be assembled out of order. The primitives would exist only to reproduce `construct_miner_tx`'s current sequence. |
| **TXE-Q3** | Land before or after the DRS cutover? Three of the four readers live in `blockchain.cpp` / `blockchain_db.cpp`, which the cutover retires. | **RULED: before** (default held; the falsifier stands as written), on the grounds of §0 — the C++ daemon is consensus on the alpha.9 testnet. **Falsifier:** if the cutover's deletion of `blockchain_db.cpp`'s DB-add path lands first, TXE's scope shrinks to the coinbase writer and the RPC read; re-scope at Round 2 rather than build shims for dead readers. | The value of closing a parser-divergence class is proportional to how long the C++ path is consensus; alpha.9 makes that long enough to matter. |
| **TXE-Q4** | Does the `0x0B` record parser (TXE-F4) come in? | **RULED: no** (default held). Named as the next boundary; its owner is `ARCHIVAL_CREDIT_WIRE.md`, whose producer is itself blocked. | Rule 15: scope is the tx_extra grammar; the attestation grammar is a second one with a different owner and a live blocker. |
| **TXE-Q6** *(posed 2026-09-22 from the adjacent sweep; must be answered before commit 1, because `shekyl_coinbase_extra`'s signature depends on it)* | **Shed `0x02` Nonce from the genesis grammar in this cutover (FOLLOWUPS FA-10 row)?** The only production producer is `construct_miner_tx`'s `extra_nonce` — the `get_block_template` `reserve_size` mechanism miners use to tag templates (`core_rpc_server.cpp:597–640`); wallet payment-ids leave with `construct_tx*` (TXE-Q1). FA-10's argument: `0x02`'s presence and length are cleartext observables that partition users, and the uniform `enc_label` is the sanctioned channel. | **RULED 2026-09-22 (maintainer, PR #826): shed it, in commit 3 — but on the privacy ground, not the grammar-cleanliness one, and with the mining consequence priced here rather than discovered by a pool operator.** `shekyl_coinbase_extra` takes no nonce; `get_block_template`'s `reserve_size` / `extra_nonce` (`core_rpc_server.cpp:633`, `:640`, live RPC surface today) become a refused parameter (distinct RPC error, `CORE_RPC_VERSION` bump). **Decisive (00-mission priority 2):** `extra_nonce` is arbitrary miner-controlled bytes in every coinbase of every block, forever — a covert channel and a fingerprint (pools stamp identifiable nonces) in the chain's most public object. That is a stronger ground than `get_output_histogram` was deleted on. **The cost, stated:** the header `nonce` is 32 bits; at `T = 120 s` (`T_SECONDS`), 2³² is exhausted within one interval at ≈ 35.8 MH/s — on the order of 120–180 mid-size RandomX machines, a modest pool. Above that a pool must refresh templates more often (a fresh coinbase is a fresh merkle root and a fresh search space) or roll the timestamp inside the FTL window. Survivable; it changes how pools operate. **If per-template exhaustion at that scale proves unacceptable, the answer is a bounded, structured nonce field — a different object with a different privacy profile and its own round — never keeping `0x02`.** Keeping an arbitrary-bytes field because a bounded one would be work is how the fingerprint survives to genesis. **Reopening criterion:** a measured pool that cannot operate under template refresh within the FTL window; the re-evaluation is the bounded-field design round, not this row. | The row as first posed argued from grammar cleanliness (`0x03`/`0xDE` precedent) — the weakest ground available. The two real arguments point opposite ways: the fingerprint (for) and the 32-bit search space (against). Under the priority ordering the fingerprint decides and the search space is priced. |
| **TXE-Q6′** *(posed and RULED 2026-09-23, maintainer, reversing TXE-Q6 before it shipped)* | **Keep `0x02` — fixed width, consensus-enforced, inside a closed coinbase grammar?** The reversal's arithmetic: `T = 120 s`, header nonce 32 bits, so `2^32 / 120 ≈ 36 MH/s` exhausts a template in one interval — the constraint that makes an extra nonce necessary at all. Each added byte multiplies it by 256: 1 B → 9.2 GH/s, 2 B → 2.3 TH/s, 4 B → `1.5 × 10^17` H/s; Monero's whole RandomX network is a few GH/s, so two bytes already exceed any plausible Shekyl hashrate a thousandfold per template. The 255-byte field was not a nonce that happened to be large; it was a free-text region usable as one. | **RULED: keep, as a fixed 8-byte field inside a closed grammar (census `CEN-I20`, wire spec §9.6b).** Width 8: never binds, matches the pool convention (`reserve_size: 8`); 4 would be equally ample for no gain. **Fixed** kills the length channel — a 0..255 choice was itself miner-controlled signal on top of the content — and makes the rule statable. **Closed grammar**, not one bounded tag: the coinbase extra is exactly `[0x01, 0x02(8), 0x06(1120·n), 0x07(64·n)]` in order and nothing else (padding, `0x04`, the staged `0x09`/`0x0A`, `0x0B` all refused) — bounding one tag while the rest stayed admissible would bound the door somebody noticed, and the 5.8 KB/day figure is true only under the closed grammar. Verified before ruling that no coinbase produces `0x04` (`construct_miner_tx` never did), so closing costs nothing. **The whitelist is the consensus rule; additions are consensus amendments** — when `0x0B`'s producer lands it changes this grammar and arrives as a ruled amendment, not as an implementation detail in the producer's PR. Genesis regenerated to carry the field (point 2): an unconditional grammar is one rule and one property test; a height-0 exemption is two rules and a branch a validator can forget, and zeros are the honest value for a block that was not nonce-searched. Net: channel capacity 184 KB/day → 5.8 KB/day, the length channel to zero, and a consensus bound on the coinbase extra for the first time (CEN-M4's hole: the largest grammar-valid coinbase extra is 18 994 bytes, under the 24 576 relay cap). **What this does not do, stated:** 8 bytes hold a pool id — the fingerprint TXE-Q6 was first decided on survives; the row records capacity and uniformity bought and miner-tagging accepted, not the channel closed. Off the coinbase `0x02` is refused outright (no Rust producer exists: `shekyl-scanner`'s `push_nonce` was dead code). Surviving from TXE-Q6: the `--extra-messages-file` / `miner_conf.json` deletion (arbitrary bytes with no mining purpose). Reversing: `shekyl_coinbase_extra` takes an 8-byte nonce; `get_block_template` accepts `reserve_size ≤ 8` / `extra_nonce ≤ 8 bytes` (zero-padded), always reserves 8, returns `reserved_offset`; `-23` is a bound violation (`COINBASE_NONCE_BOUND`), not a not-offered. Also found while landing: xmrig (upstream and the fork) sends `extra_nonce`, not `reserve_size`, and its tx_extra parser returns false on `0x06`/`0x07` — so no xmrig mines a Shekyl template without a fork patch regardless; and `shekyl-chain-rules` applies neither CEN-I19 nor this grammar yet (E6 slice 4 wires `check_tx_extra_shape`, not a second rule). | The two real arguments still point opposite ways — the fingerprint (for shedding) and the search space (against) — and TXE-Q6 weighed them under priority 2. What TXE-Q6′ adds is the arithmetic that makes the search-space cost *zero* at 8 fixed bytes, and the observation that the length channel and the missing consensus bound were the larger part of the harm and are closed by a fixed width and a closed grammar; the fingerprint is then a re-weighting the row states rather than a claim the row makes. |
| **TXE-Q5** | The 27 C++ parser tests and the fuzzer (TXE-F5): port or delete? | **RULED: the two are different objects. (a) The 27 parity tests — delete**, against a **table** in the deleting commit: one row per C++ `TEST` → its `shekyl-wire` twin by name, or "added in this commit" — not a sentence saying the confirmation was done (twenty-seven is exactly the size where reading the list feels sufficient and isn't); promote `TX_EXTRA_PQC_ROUND_TRIP.json` to the pinned vector for the cases that were "oracle parity". **(b) The fuzzer — NOT deleted.** `tests/fuzz/tx-extra.cpp` fuzzes *the grammar*; its oracle is "doesn't crash", which survives the C++ parser's removal intact. It is **re-pointed at the surviving implementation**: a `fuzz_tx_extra_parse` target under `rust/shekyl-wire/fuzz/` (the crate has no `fuzz/` today; eight workspace crates do), **seeded from the C++ corpus** (`tests/data/fuzz/tx-extra/`, two seeds), registered in `rust-audit-test.yml`'s fuzz-inventory smoke gate so it is not "built nowhere in CI" (the `shekyl-fcmp` FOLLOWUPS finding). Same commit as the deletion. | (a) Once the oracle is gone, "parity with the oracle" tests have no subject; the cases belong with the grammar's one implementation. (b) Deleting the fuzzer would take adversarial coverage of the `tx_extra` grammar from one target to **zero**, on the codec that is about to become the single implementation parsing untrusted bytes on the block path — the opposite of this plan's stated purpose. |

---

## 7. Commit sequence — LANDED 2026-09-23 (commits 1, 2, 3, 4a, 4b, 5; commit 4 split in two, commit 3 reworked in place for TXE-Q6′)

1. **FFI surface.** The four entry points in `shekyl-ffi` (`tx_extra_ffi.rs`
   grows), `shekyl_ffi.h`, the I19 entry point re-shaped to take bytes; unit
   tests in Rust for every code.
2. **Readers on the shim.** `blockchain_db.cpp`, `blockchain.cpp`,
   `core_rpc_server.cpp`, `check_tx_extra_pqc_field_shape`'s body.
3. **Writer on the shim.** `construct_miner_tx` builds its extra through
   `shekyl_coinbase_extra`; `mining_parity.cpp` re-pointed.
4. **Deletion, with its two tables and the fuzz target.** §4; the
   `construct_tx*` test migration with the **per-test case-equivalence
   table** (TXE-Q1's condition); the 27 parity tests with the **per-case
   twin table** (TXE-Q5a); `tests/fuzz/tx-extra.cpp` and its CMake target
   deleted **in the same commit that adds** `rust/shekyl-wire/fuzz/` with
   `fuzz_tx_extra_parse`, seeded from `tests/data/fuzz/tx-extra/`, and
   registers it in the fuzz-inventory gate (TXE-Q5b). Both tables live in
   this document's §9 so they are grep-visible after the C++ is gone.
5. **Docs** (rule 91): this file's status, index rows, `FCMP_PLUS_PLUS.md` /
   `POST_QUANTUM_CRYPTOGRAPHY.md` where they cite the C++ parser, CHANGELOG
   (API-relevant: the C++ `tx_extra` API is gone), FOLLOWUPS sweep (the
   `0x0B` row's blocker text cites `parse_archival_attestation_from_extra`).

---

## 8. Denominator

- `check_test_only_features.py`, the FFI symbol gates, `rust-audit-test`
  (including its fuzz-inventory smoke gate, which gains
  `fuzz_tx_extra_parse`), the C++ unit/core tests as migrated.
- **Adversarial coverage of the grammar is ≥ 1 target before and after**
  (TXE-Q5b): the C++ fuzzer is removed only in the commit that lands its
  Rust successor.
- **CEN-M4 did not move** (TXE-F9): one test that a coinbase whose extra
  exceeds 24 576 bytes is accepted by the block path after the cutover
  exactly as before, and that a non-coinbase one is still refused at relay;
  `block.rs:40`'s doc corrected to what `transaction.rs:1808` does, in the
  same commit.
- `TX_EXTRA_PQC_ROUND_TRIP.json` must not move (no bytes change).
- `mining_parity.cpp`: a block template's coinbase extra before and after the
  cutover is **byte-identical** for the same inputs — the one test that
  proves this PR changed no wire.

---

## 9. Equivalence tables (owed by §7 commit 4; empty until then by design)

Two tables the deleting commit fills, kept here so the evidence outlives the
C++ it describes:

- **9.1 `construct_tx*` callers → where the case lives now** (TXE-Q1's
  condition, filled by §7 commit 4a, 2026-09-23). **Verified premise
  correction first:** every `construct_tx*` caller was a test that had been
  *disabled* since 2026-05-05 (`chaingen_main.cpp`: the builder "produces
  CTTypeFcmpPlusPlusPqc stubs with empty pqc_auths; check_tx_inputs rejects
  them"), a `--test_transactions` mode no CTest or CI invoked, or a benchmark.
  The 41 enabled core tests build blocks and coinbases only and call none of
  it, so deleting the builder changes zero *live* coverage. What went dark in
  May was a C++ capability gap — the transaction format moved to FCMP++/PQC
  and the C++ builder was never taught it — not a handoff to a finished Rust
  path. The Rust side *does* build a validating user transaction
  (`regtest_e2e.rs:865` `e2e_fcmp_spend_accepted_by_daemon`: Engine-built
  spend, accepted into a block by a live `shekyld`, armed per PR in
  `build.yml`'s live-daemon gates); what no test does yet is put one **into a
  chain and reorg or re-derive rewards around it**. That gap is a DEFERRED
  with an owner (FOLLOWUPS "user-transaction chain cases", E2 corpus), not a
  deletion note.

  | C++ case (deleted) | What it exercised | Dark since | Where the case lives now |
  |---|---|---|---|
  | `gen_simple_chain_001` (`chaingen001.cpp`) | user txs across rewinds and a side block | 2026-05-05 | **no test**; buildable on `regtest_e2e` (Engine spend + `generateblocks`); owner E2 corpus |
  | `gen_simple_chain_split_1` (`chain_split_1`) | reorg with user txs in the switched-out branch | 2026-05-05 | **no test**; same home |
  | `gen_chain_switch_1` (`chain_switch_1`) | chain switch with txs in both branches, txpool return | 2026-05-05 | **no test**; same home |
  | `gen_block_reward` (`block_reward`) | reward with fee-paying txs in the block | 2026-05-05 | **no test** with user txs; coinbase-only reward is `economics_c2a_prime_layer3_pop_replay` (enabled) |
  | `gen_uint_overflow_1/2` (`integer_overflow`) | input/output amount overflow in a user tx | 2026-05-05 | **no C++ test**; amount arithmetic is checked in Rust (`shekyl-wire` validation, `shekyl-ct-balance`); a chain-level case is the E2 corpus's |
  | `test_transaction_generation_and_ring_signature`, `test_block_creation` (`transaction_tests.cpp`, `--test_transactions`) | serialize → parse round trip of a built tx / block | never run by CTest or CI | `shekyl-wire` `coinbase_roundtrip.rs`, `fcmp_spend_roundtrip.rs`, `coinbase_hash.rs` (daemon-oracle hashes) |
  | 16 `gen_bpp_*` (`bulletproof_plus`) | Monero BP+ hard-fork ladder (`HF_VERSION_BULLETPROOF_PLUS - 1`, proof counts, wrong amount) | never enabled; rule 60 | BP+ verification with no fork ladder: `shekyl-bulletproofs` tests; `fcmp_spend_e2e.rs` (Bp+ + CT balance on a real spend) |
  | `test_construct_tx`, `test_check_tx_signature{,_aggregated_bulletproofs}` (`performance_tests`) | timing of a builder whose output no validator accepted | n/a (benchmark) | none owed; spend-path timing lives with `shekyl-tx-builder` |
  | `test_ge_tobytes`, `test_ge_frombytes_vartime` (`performance_tests`) | point (de)compression timing — built a tx only to obtain a point | n/a | **kept**, re-pointed at a fresh account's spend key |
  | chaingen scaffolding (`construct_tx_to_key`, `construct_tx_with_fee`, `construct_tx_rct`, `fill_tx_sources*`, `fill_tx_destinations`, `block_tracker`, `output_index`, `get_balance`, `MAKE_TX*`) | fed the rows above | 2026-05-05 | deleted with them; `construct_miner_tx_manually` / `append_v3_output_to_miner_tx` (live, 36 block-validation tests) **kept**, moved onto `shekyl_coinbase_extra` in §7 commit 3 |
  | `construct_tx_with_tx_key` / `construct_tx_and_get_tx_key` / `construct_tx` / `tx_source_entry` / `tx_destination_entry` / `fill_construct_tx_rct_stub` (`src/`) | the builder itself — zero production callers | — | the one builder is `shekyl-tx-builder`. The callerless `legacy_tx.rs` forwarders (`shekyl_construct_output_labeled`, `shekyl_label_plaintext_for_payment_uri`, `shekyl_compute_output_key_image_from_ho`, and the other zero-hit exports in that file) were deleted in the follow-up sweep; the Rust functions they wrapped stay. `shekyl_fcmp_build_witness_header` stays — it is the witness writer, not a forwarder |
- **9.2 C++ parser `TEST`s → `shekyl-wire` twins** (TXE-Q5a, filled by §7
  commit 4b, 2026-09-23). Every retired C++ case, its twin in
  `rust/shekyl-wire/tests/tx_extra_roundtrip.rs` unless another file is named,
  or the reason none is owed. The census said 27 cases in `test_tx_utils.cpp`;
  the deleting commit found 31 across it, `cryptonote_format_utils.cpp` (4) and
  the two `tx_extra_pqc_field_shape` parse-arm fixtures that used the parser.
  `validate_parse_amount` is not a parser test and stays. The **sorter**
  (`sort_tx_extra`) and the **field remover** (`remove_field_from_tx_extra`)
  have no successor by design: canonical order is produced by construction
  (`shekyl_coinbase_extra`) and judged by `check_coinbase_extra_shape`, and
  nothing rewrites an extra in place; their *refusal* cases are parser
  refusals and have twins.

  | C++ `TEST` | Twin | Note |
  |---|---|---|
  | `parse_tx_extra.handles_empty_extra` | `empty_extra_parses_to_no_fields` (added) | |
  | `parse_tx_extra.handles_padding_only_size_1` | `padding_only_parses_with_its_length_up_to_the_cap` (added) | one test, sizes 1 / 2 / 255 |
  | `parse_tx_extra.handles_padding_only_size_2` | same | |
  | `parse_tx_extra.handles_padding_only_max_size` | same | |
  | `parse_tx_extra.handles_padding_only_exceed_max_size` | `padding_past_the_cap_is_refused_on_parse` (added) | |
  | `parse_tx_extra.handles_invalid_padding_only` | `a_nonzero_byte_inside_padding_is_refused` (added) | |
  | `parse_tx_extra.handles_pub_key_only` | `pubkey_only_parses` (added) | the C++ case's 33 bytes |
  | `parse_tx_extra.handles_extra_nonce_only` | `nonce_only_parses` (added) | `{2, 1, 42}` |
  | `parse_tx_extra.handles_pub_key_and_padding` | `pubkey_then_padding_parses_as_two_fields` (added) | |
  | `parse_and_validate_tx_extra.is_valid_tx_extra_parsed` | `tx_extra_codec_ffi::tests::the_coinbase_writer_lays_out_pubkey_nonce_kem_leaf_and_the_reads_find_each`; `mining_parity.coinbase_writer_reproduces_the_genesis_extra_byte_for_byte` (C++) | a built coinbase's pubkey reads back |
  | `parse_and_validate_tx_extra.fails_on_big_extra_nonce` | `test_tx_utils` **kept and re-pointed** in §7 commit 3: `construct_miner_tx` refuses a 9-byte nonce (the width is fixed at 8) | then deleted in 4b with the file's parser tests; its subject is now `tx_extra_codec_ffi::tests::the_coinbase_grammar_is_judged_on_both_reads_and_off_the_coinbase_the_nonce_is_refused` (7-byte nonce refused) and `coinbase_grammar::the_nonce_is_exactly_eight_bytes_and_exactly_one` (`src/tx_extra.rs`) |
  | `parse_and_validate_tx_extra.fails_on_wrong_size_in_extra_nonce` | `a_nonce_length_past_the_bytes_is_refused` (added) | |
  | `sort_tx_extra.empty` / `pubkey` / `two_pubkeys` / `keep_order` / `switch_order` | none owed — no sorter | order is constructed and judged; `coinbase_grammar::the_order_is_part_of_the_grammar` covers the judgement |
  | `sort_tx_extra.invalid` | `a_truncated_pubkey_field_is_refused_alone_and_as_a_suffix` (added) | `{1}` |
  | `sort_tx_extra.invalid_suffix_strict` | same | valid nonce field then a lone `1` |
  | `sort_tx_extra.invalid_suffix_partial` | none owed — REJECTED behaviour | returning the parsed prefix of a bad extra is the fail-open the codec refuses |
  | `remove_field_from_tx_extra.remove_first` / `remove_last` / `remove_middle` | none owed — no in-place rewrite | the parse half of each is `pubkey_then_padding_parses_as_two_fields` / `nonce_only_parses` |
  | `remove_field_from_tx_extra.invalid_varint` | `a_non_canonical_varint_length_is_refused` (added) | `0x80 0x00` refused on both sides, verified |
  | `tx_extra_pqc_round_trip.kem_and_leaf_entries_survive_sort` | `tx_extra_pqc_round_trip_vector_cases_hold_without_a_sorter` (added), case 1, reading `docs/test_vectors/TX_EXTRA_PQC_ROUND_TRIP.json` | the vector is promoted to the pinned record; "double sort idempotent" is serialize∘parse identity |
  | `tx_extra_pqc_round_trip.kem_and_leaf_entries_reverse_order` | same, case 2 | contents survive a non-canonical order on parse; the grammar refuses the order — what "sort reorders" became |
  | `cn_format_utils.add_extra_nonce_to_tx_extra` | `every_nonce_length_up_to_the_cap_round_trips_and_the_cap_plus_one_is_refused` (added) | 0..=255 with and without a pubkey prefix; 256 refused |
  | `cn_format_utils.rejects_the_inherited_merge_mining_tag` | `retired_and_reserved_tags_parse_as_unknown` (existing) | `0x03` |
  | `cn_format_utils.rejects_the_inherited_minergate_tag` | same | `0xDE` |
  | `cn_format_utils.still_accepts_the_tags_that_remain` | `every_nonce_length_…` (pubkey + 8-byte nonce) and `synthetic_tx_extra_field_kinds_round_trip` (existing) | |
  | `tx_extra_pqc_field_shape.*` parse-arm fixtures (`parse_tx_extra` used to assert "the fixture must actually be unparseable") | kept; assert through `shekyl_tx_extra_field(…) == SHEKYL_TX_EXTRA_MALFORMED` | the 17 I19 tests are unchanged in subject |
  | `tests/fuzz/tx-extra.cpp` (TXE-Q5b) | `rust/shekyl-wire/fuzz/fuzz_targets/fuzz_tx_extra_parse.rs`, seeds moved from `tests/data/fuzz/tx-extra/` to `fuzz/seeds/fuzz_tx_extra_parse/`, registered in `rust-audit-test.yml` `REQUIRED_TARGETS` | same crash oracle plus parse∘serialize identity and totality of both shape arms |

## 10. Decision log

| Date | Entry |
|---|---|
| 2026-09-23 | **Grammar has one constructor.** Acceptance of a coinbase extra is the slice match `canonical_nonce` in `shekyl-wire`'s `tx_extra::coinbase`; `build_coinbase_extra` is the only writer (the FFI `shekyl_coinbase_extra`, the genesis tool, and the fixtures call it). Layout failures are `CoinbaseGrammarError` — a missing pubkey is not CEN-I19's `Missing` — and the template's nonce offset is `shekyl_coinbase_nonce_offset_from_pubkey`, the grammar's distance from the pubkey byte, not a `+ 2` in the RPC server. |
| 2026-09-23 | **LANDED** (§7 commits 1, 2, 3, 4a, 4b, 5 on `feat/tx-extra-rust-cutover`). Three things changed against the plan as ruled, each recorded where it lives: (1) **TXE-Q6 reversed as TXE-Q6′** before it shipped — the coinbase nonce is a fixed 8-byte field inside a closed coinbase grammar (`CEN-I20`, wire spec §9.6b), genesis regenerated on all three networks (new ids; regtest corpus recaptured, the daemon's h0 equal to geblock's), commit 3 reworked in place since the branch was unpushed; (2) **TXE-Q1's premise corrected** (§9.1) — every `construct_tx*` caller was a test disabled since 2026-05-05 or a benchmark, so live coverage changed by zero, and the real gap (a chain containing a validating user transaction that then reorgs) is a FOLLOWUPS DEFERRED owned by E2's corpus, not a deletion note; a validating Rust-built spend exists and is gated per PR; (3) **TXE-F9 / CEN-M4 closed rather than moved** — the grammar bounds the coinbase extra at 18 994 bytes, under the relay cap. §9.2's twin table counts 31 parser cases, not 27 (four in `cryptonote_format_utils.cpp`). Three FFI exports were left callerless by the builder's deletion and are a FOLLOWUPS row for F-7's sweep. **PR #837 review (Bugbot, same day):** the inherited two-phase template loop in `Blockchain::create_block_template` (and its twin in `tests/core_tests/chaingen.cpp`) still padded a lighter second-pass coinbase's `extra` with zero bytes back up to the weight estimate — a foreign tag under the grammar, so the miner would have spent work on a template connect refuses. Padding deleted in both; the loop re-prices at the block's actual weight until weight and reward agree (below the effective median the reward is weight-independent and this settles on pass two; in the penalty zone the ten-try budget fails the template loudly if a varint boundary makes the two weights trade places). The template now asserts `check_tx_extra_shape` on the settled coinbase before caching, so any future C++ mutation of the extra fails at the template, not at connect. Who owns the template fixed point in Rust remains TXE-F8's open question. |
| 2026-09-22 | **TXE-Q6 RULED** (maintainer, PR #826): shed `0x02`, on the privacy ground — a permanent miner-controlled free-text field in every coinbase is a covert channel and a pool fingerprint (00-mission priority 2) — with the cost stated: a 32-bit header nonce exhausts within one 120 s interval at ≈ 35.8 MH/s, so pools above a modest size refresh templates or roll the timestamp inside the FTL; if that proves unacceptable the fallback is a **bounded, structured** nonce field designed in its own round, never keeping `0x02`. Also written in: `ERR_HEADERS_UNREADABLE` is reachable (attestation verify precedes the I19 coinbase parse check on both paths), and the collapsed observable of TXE-F10 sits one level in — the records loop, not the flag. |
| 2026-09-22 | **Adjacent sweep (maintainer, on PR #826) — four findings folded in.** (1) The attestation path is one unbuilt mechanism tracked as four rows (TXE-F10); one FOLLOWUPS row now names them and the breaker (the producer, in the unowned template writer). Correction to the sweep's premise while verifying it: `headers_readable` is constantly **`true`** with an empty blob, not `false` — a parsed extra without the tag is the committed empty set — so it is the *unreadable* branch that is dead. (2) `0x0A`'s picker: #825 keeps it, deliberately — the tag is STAGED (rule 23 keeps symbols under a named live consumer); #825 removes the picks for `0x05`/`0x08`. (3) CEN-M4: verified on both sides, and a disagreement found inside `shekyl-wire` between `block.rs:40`'s doc and `transaction.rs:1808`'s exemption (TXE-F9); §8 gains the did-not-move test. (4) FA-6b and FA-10's FOLLOWUPS rows had been **truncated to their headings** (bodies lost since `c7df00c55c`); restored with owners. FA-6b is out of scope here (an audit on the multisig producer, §2.2); FA-10's `0x02` shedding is **posed as TXE-Q6**, because `shekyl_coinbase_extra`'s signature depends on it. |
| 2026-09-22 | **Round 1 RULED** (maintainer, PR #826). Q1 delete with the per-test equivalence condition, and the reasoning corrected: what decides deletion is *parser-versus-scaffolding*, not *dies-later* — `chaingen.cpp` is part of the C++ consensus path §0 says must stay whole through alpha.9, so its coverage may not silently change while `construct_tx*`, a second writer of the grammar, goes. Q2/Q3/Q4 defaults held. Q5 split: the 27 parity tests go against a per-case twin table; the fuzzer does **not** go with them — it fuzzes the grammar with a crash oracle that survives the C++'s removal, `shekyl-wire` has no `fuzz/` at all, and deleting it would take grammar fuzz coverage from one to zero on the codec becoming the single parser of untrusted block-path bytes. Re-pointed as `fuzz_tx_extra_parse`, seeded from the C++ corpus, registered in the inventory gate. §9 added to hold both tables. |
| 2026-09-22 | **Round 0 executed** at `7b9be6cd1`. Eight findings (TXE-F1…F8); five questions posed with defaults (TXE-Q1…Q5). The daemon's production need from the C++ `tx_extra` machinery is one writer (the coinbase) and three reads (leaf blob, attestation blob, tx pubkey); everything else serves `construct_tx*`, which has no production caller. Adjacent-lane check: E6 slice 4 (`feat/chain-rules-slice-4`) lands the coinbase *judge* and touches none of these files; the block-template *builder* is unowned (TXE-F8). PR #825 (the producerless-tag disposition) is the precursor: four fewer variants for the shim to carry. |
