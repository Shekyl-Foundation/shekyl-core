# RTN-7 — the wire crate's hash surface is typed, and a gate keeps it so

**Status:** CLOSED-as-record — **LANDED 2026-09-18** (PR #777, merged as
`474dd72f5`; last verified on the branch at `dev` = `d89f99791`, post-#772).
Round 0 ruled 2026-09-17 (Q1–Q5, §6). Archived per rule 95 when the work
it owns landed; the living contract for the newtype family is
[`RAW_TYPE_NEWTYPE_MIGRATION.md`](../design/RAW_TYPE_NEWTYPE_MIGRATION.md).
Written 2026-09-17 against `dev` = `398d85e7b` (post-#768); the halt (no
production code until #771, which brings `AttestationRoot` and `#![no_std]`
`shekyl-types`) lifted when #771 merged the same day, and the first
production commits were cut against `eac99894a` (post-#771). Family: `RTN-1…RTN-N`, registered by #771
([`IMPLEMENTATION_INDEX.md`](../design/IMPLEMENTATION_INDEX.md) §2); this is the
seventh item. Work plan of record:
[`RAW_TYPE_NEWTYPE_MIGRATION.md`](../design/RAW_TYPE_NEWTYPE_MIGRATION.md) §6, whose
two open wire rows this item closes.

## 1. The property, stated once

After this lands, **no `[u8; 32]` appears on `shekyl-wire`'s public surface
as a chain identity.** Txids are `TxHash`, block hashes `BlockHash`, tree
roots `CurveTreeRoot`, attestation roots `AttestationRoot`, persona ids
`PCanonicalId`. What remains raw is raw for a reason the gate (§4) can read.

The reason this is one PR and not two (ruled 2026-09-17): typing the
*returns* (`Transaction::hash()`, `Block::hash()`) while leaving the *fields*
they flow into (`BlockHeader.previous`, `Block.transaction_hashes`) as
`[u8; 32]` produces a tree where every `previous = block.hash()` grows a
`.to_bytes()` — **a typed value unwrapped at the exact boundary the type
exists to protect**, and at review indistinguishable from a legitimate
conversion. Both endpoints are defensible; the midpoint is worse than
either. Returns and fields are one unit.

## 2. Verified at source (2026-09-17)

- **Exposure arm.** `BlockHash`, `TxHash`, `CurveTreeRoot`, `PrunableHash`,
  `PqcAuthHash` are minted under `hash32!`'s **default arm**
  (`rust/shekyl-types/src/lib.rs:397–471`): `@core + @as_ref + @display`,
  full `Debug`. `AsRef<[u8]>`, full-hex `Display`, `from_bytes` /
  `to_bytes` / `as_bytes`. `hex::encode(tx.hash())` compiles; logger
  `impl AsRef<[u8]>` accepts. Only `KeyImage` is `redact, no_display`, and
  the crate's exposure-policy doc (`:52–57`) states the split: public hashes
  render in full. **Nothing to reopen** — a txid is public chain data; the
  key-image suppression exists because a key image in a log links a spend
  to a wallet, and neither half applies here.
- **Layout.** The default arm emits `#[repr(transparent)] pub struct
  $name([u8; 32])`, so `Vec<TxHash>` has the layout of `Vec<[u8; 32]>` and
  a `&[[u8; 32]]` batch path stays sound. `hash_concat` / `merkle_root` in
  `shekyl-wire/src/hash.rs` are `pub(crate)` and take `[u8; 32]`; they stay
  raw (they are the mixer, not the surface) and convert at the call.
- **The store's key boundary.** `Hash32` (`shekyl-chain-store/src/lmdb_order/hash.rs`)
  is the layout type inside [`LmdbHashKey`]; `LmdbHashKey`'s `redb::Value::from_bytes`
  / `Key::compare` carry `.expect("LmdbHashKey is 32 bytes (redb fixed_width)")`.
  RTN-7's `From<BlockHash>` / `From<TxHash>` on `Hash32` (and on `LmdbHashKey`)
  is the signature a later `Tagged<V>` retrofit lands against (orphan rule
  keeps `impl redb::Key for shekyl_types::*` out; #771's "will not do" list).
  **Finding, filed 2026-09-18:** the `Tagged<V>` retrofit is a FOLLOWUPS
  pre-genesis row (rule 23). Falsify by `rg 'Tagged<' docs/FOLLOWUPS.md`.

## 3. Scope

### 3.1 In — typed in the wire PR (type-only; serializer writes 32 bytes either way)

| Surface | Today | Becomes | Why this type |
| --- | --- | --- | --- |
| `Transaction::hash()` | `[u8; 32]` | `TxHash` | `TxidParts.hash` already is; `hash()` is that field |
| `Transaction::hash_with_supplied_prunable` / `hash_with_supplied_components` return | `[u8; 32]` | `TxHash` | same txid, reconstructed |
| `Block::hash()` | `[u8; 32]` | `BlockHash` | |
| `BlockHeader.previous` | `[u8; 32]` | `BlockHash` | CEN-A2 compares it to `Tip.hash: BlockHash` |
| `BlockHeader.curve_tree_root` | `[u8; 32]` | `CurveTreeRoot` | CEN-B5 compares it to `root_at(h): CurveTreeRoot` |
| `BlockHeader.attestation_root` | `[u8; 32]` | `AttestationRoot` | minted by #771 for exactly this field |
| `Block.transaction_hashes` | `Vec<[u8; 32]>` | `Vec<TxHash>` | `repr(transparent)` keeps the merkle path sound |
| `Ct::Fcmp.reference_block` | `[u8; 32]` | `BlockHash` | **ruled in 2026-09-17, for a reason beyond symmetry:** it is `ref_height`'s companion — the field CEN-I12's finding is about. Raw beside a typed `previous` is the asymmetry someone asks about in six months and finds no answer for. **Scope consequence, stated:** this reaches `shekyl-tx-builder`, the *construction* side, and reference-block selection is the path the I12 gap lives on. **Q5 (ruled): the review is narrow and the commit says so** — what the reviewer establishes is that no `reference_block` / `ref_height` *selection* logic moved, only the type. Naming it that way keeps the scope from expanding into the I12 question. |
| `BondPost.p_canonical_id` | `[u8; 32]` | `PCanonicalId` | **Q1 — in (ruled).** `PCanonicalId` exists under the `redact` arm (truncated `Debug`, full `Display`), is already on the wire, and truncated `Debug` is the right rendering for a persona identity inside a `BondPost`. |
| `Transaction::prefix_hash()` | `[u8; 32]` | `PrefixHash` (**new**, `shekyl-types`, default arm) | **Q3 — overridden (ruled): typed, and not as `SignableTxHash`.** `prefix_hash()` is `keccak256(varint(TX_VERSION) ‖ TxPrefix::write)` — the **first** component of the txid preimage; `PrunableHash` (`lib.rs:427`) is the fourth and `PqcAuthHash` the third. The component-hash family already exists and this is its missing member, not a new category; a fresh name would make the next reader work out whether `SignableTxHash` and `PrunableHash` are the same kind of thing. And it closes the confusion the allowlist would only have named: raw, it passes into `TxHash::from_bytes` or any `[u8; 32]` parameter without complaint. `TxHash` is the output, the component hashes are the inputs, and the type system refuses either direction. Consumer: `shekyl-tx-builder` (`wire.rs:324,347,377,520`) signs its bytes — `as_bytes()` at the signing call. |

### 3.2 Out — stays `[u8; 32]`, named in the gate's allowlist with the reason

| Surface | Reason |
| --- | --- |
| `Output.key`, `CtBase.commitments`, `BpPlus.{a,b,l,r}`, `Prunable.pseudo_outs` | curve points / scalars — transform-shaped crypto objects, `RAW_TYPE_NEWTYPE_MIGRATION.md` original PR E, **DEFERRED — addressee named (Q4 ruling: a cause with no addressee is how `DEFERRED_DOCS`-shaped lists rot):** `Output.key` → `shekyl-tx-builder` / `shekyl-scanner` (the one-time-key derivation and match sites; #771's `OneTimePubkey` is minted for `TransferDetails` persistence in `shekyl-engine-state` and its adoption at the codec is that crate pair's decision); `commitments`, `pseudo_outs` → `shekyl-tx-builder` (`CommitmentBytes`, same provenance); `BpPlus.{a,b,l,r}` → `shekyl-proofs` (proof scalars/points; their newtypes, if any, live where the proof is built and verified). Reopen: when any addressee adopts the newtype on its own side of the boundary, the wire field follows in the same PR. |
| `PqcOwnershipEntry.group_id` (`tx_extra.rs:108`) — **CELL DELETED 2026-09-22** with tag `0x05` (REJECTED; `PQC_MULTISIG.md` §7.4 *Retired tag*), so this ruling has no subject | **Q2 — allowlist (ruled), with the discriminator in the cell so a later reviewer re-runs the test instead of re-deriving it:** *adjacency* — could a code path plausibly pass a txid, key image or component hash where a group id belongs? It is parsed into a struct and consumed by group logic; no site takes a bare `[u8; 32]` that could be either. Low. Reopen when a second consumer of `group_id` appears, or when any site accepts it as a bare array beside another 32-byte value. Zero-hash for single-signer. |
| `hash.rs` `hash_concat` / `merkle_root` / `hash_pair` | `pub(crate)` mixers over raw digests; not surface. The gate scans `pub` items only. |
| `TxSegments` byte vectors, `Vec<u8>` blobs | not 32-byte, not in the gate's pattern. |

### 3.3 Call-site inventory (`dev` `398d85e7b`, `rg` excluding `txid.rs`)

**156** sites of `.hash()` / `hash_with_supplied_*` across 9 crates:
engine-core 72, wire 32, chain-store 30, daemon-rpc 9, genesis-tool 5,
chain-rules 5, wallet-rpc / scanner / rpc-types 1 each. By shape:

- **12** `TxHash::from_bytes(x.hash())` / `BlockHash::from_bytes(…)` → become `x.hash()`. Deletions.
- **~15** hex-encode the result → unchanged (`AsRef`).
- **~17** compare/assert → against another `.hash()`, unchanged; against a raw literal (tests), the literal is wrapped.
- **The remainder** flow into the §3.1 fields (`previous = block.hash()`, `candidate(1, genesis.hash(), …)`, `transaction_hashes = vec![body.hash()]`) → **unchanged once the fields are typed** — which is §1's argument in numbers.
- Store codec key: `Hash32::from_bytes(block.hash())` → `Hash32::from(block.hash())`.

## 4. The gate — `scripts/ci/check_wire_raw_hash_surface.py`

Ruled 2026-09-17: **without a gate this is a cleanup that decays invisibly.**
The value of RTN-7 is that raw `[u8; 32]` stops appearing on the wire
surface; the moment it lands, nothing stops the next wire field arriving as
`[u8; 32]`. §6 rows record intent; rows do not gate. This is the fourth
instance of one pattern in this tree — the census bijection map,
`RUST_ONLY_TABLES`, `DEFERRED_DOCS`, `CXX_HOLDER_RE` — named exceptions
with a reason, unnamed occurrences red.

- **Subject:** every `pub` field type and `pub fn` signature in
  `rust/shekyl-wire/src/**/*.rs` containing `[u8; 32]` (including
  `Vec<[u8; 32]>`, `Option<[u8; 32]>`, `&[[u8; 32]]`). A declaration is
  one item even when rustfmt wraps it: fields, enum-variant fields, and
  tuple-variant payloads are buffered until the type's bracket depth
  returns to zero (completeness is depth, not a trailing comma — the last
  field of a struct has none); signatures are buffered to the body's `{`.
  `pub(crate)` is not surface and is not scanned.
- **Allowlist:** `ALLOWED: dict[str, Allow]` of
  `"<file>::<item>": Allow(reason, addressee)` — §3.2's rows, byte-exact.
  The addressee is a **field**, not a phrase inside the reason, so `check`
  can assert it exists (second-round, 2026-09-18). **Q4 (ruled): the
  broad reading** — every `[u8; 32]` on the surface is the subject, the
  crypto objects are the named exceptions, and every exception names its
  addressee crate, because the red-when-the-item-is-gone leg cannot help
  an entry whose owner is unspecified.
- **Red in both directions (rule 47):** an occurrence not in the allowlist;
  an allowlist entry whose item no longer exists (the allowlist may not
  outlive its subject); an entry with an empty reason or no addressee;
  an empty scan (the crate moved, the parse broke — absence of signal is
  first evidence the subject is absent).
- **Self-test** (`--selftest`): a synthetic `pub previous: [u8; 32]` goes
  red; a rustfmt-wrapped field (`Vec<\n [u8; 32],\n>`) goes red; a
  synthetic allowlisted item passes; empty reason / empty addressee go
  red; a stale allowlist entry goes red; an empty tree goes red.
- Wired into `docs-gates.yml`'s bundled grep gates.

## 5. Commit plan (rule 90; ≤ 10)

1. `types: PrefixHash — the txid preimage's first component` — beside
   `PqcAuthHash` and `PrunableHash`, default arm.
2. `wire: hash returns and header fields are typed` — `txid.rs` returns,
   `Block::hash()`, `prefix_hash() -> PrefixHash`,
   `BlockHeader.{previous,curve_tree_root,attestation_root}`,
   `Block.transaction_hashes`, `BondPost.p_canonical_id`. Serializer
   unchanged; every parity KAT (`pruned_tx_hash_parity`,
   `serve_credit_tx_parity`, live-oracle pin, block vectors) green
   unchanged — that is the proof the change is type-only.
3. `wire: Ct::Fcmp.reference_block is a BlockHash` — its own commit, its
   own reviewer (§3.1); the message states that no selection logic moved.
4. `chain-store: Hash32 converts from the identity types` — `From<BlockHash>`,
   `From<TxHash>`; codec call sites.
5. `chain-rules: …`, 6. `engine-core + tx-builder: …`, 7. `daemon-rpc +
   genesis-tool + singletons: …` — one fixup commit per consuming crate;
   deletions of `from_bytes` wrappers, wrapped literals in tests.
8. `ci: check_wire_raw_hash_surface — the wire surface refuses raw [u8; 32]`
   — gate + selftest + workflow wiring.
9. `docs:` — §6 rows closed in `RAW_TYPE_NEWTYPE_MIGRATION.md` (status
   table gains the RTN-7 row, LANDED); index RTN row `UPDATE`; CHANGELOG
   API entry; this doc's banner → LANDED and `git mv` to `docs/completed/`
   (rule 95). FOLLOWUPS row for the `Tagged<V>` finding (§2) — **filed
   2026-09-18** (pre-genesis, `LmdbHashKey` expect).

## 6. Questions — ruled 2026-09-17

- **Q1** `BondPost.p_canonical_id: PCanonicalId` — **in**, as defaulted (§3.1).
- **Q2** `group_id` — **allowlist**, with the adjacency discriminator
  written into the reason cell (§3.2).
- **Q3** `prefix_hash()` — **overridden: typed as `PrefixHash`**, a new
  `shekyl-types` member of the existing component-hash family, not
  `SignableTxHash` and not allowlisted (§3.1).
- **Q4** Gate breadth — **the broad reading**; every exception names its
  addressee crate (§3.2, §4).
- **Q5** Reviewer for the `reference_block` commit — the implementer's
  call; the commit states the narrow subject (type only, no selection
  logic moved) so the review stays that narrow (§3.1).

## 7. What the gate found about this document (2026-09-17 → 09-18)

`check_wire_raw_hash_surface.py`'s **first run failed** — on its author's
own §3.2 enumeration. That is the outcome the gate exists for, so it is
recorded rather than quietly fixed:

- **Four occurrences §3.2 missed:** `BpPlus.r1`, `BpPlus.s1`,
  `KemCiphertext.x25519` (`tx_extra.rs`), and
  `pqc_signing_payload_hashes() -> Vec<[u8; 32]>`. The enumeration was
  written by reading the structs I expected to matter; the gate read every
  `pub` item.
- **Three allowlist entries with no subject:** `BpPlus.v` and
  `CtBase.enc_amounts` do not exist in that shape — `enc_amounts` is
  `Vec<[u8; 9]>`, and I allowlisted it from a recollection of "an array
  field on `CtBase`", which is the recall-instead-of-reading failure rule
  17 names. The third, `Input::ToKey.key_image`, was **present but
  unscanned**.
- **That last one was a gate defect, not a bad entry.** An enum variant's
  fields are public with **no `pub` keyword**, so a `pub`-only scan misses
  them — and `key_image` is a 32-byte public wire field. Fixed in the
  scanner (`VARIANT_FIELD_RE`) with its own self-test leg, rather than by
  deleting the entry, which would have closed the report and left the hole.

Two dispositions the run forced, both now in the allowlist with reasons and
addressees:

- **`pqc_signing_payload_hashes()` stays `[u8; 32]`.** Q3 typed
  `prefix_hash` because it *is* the txid's first component and the
  component-hash family already existed. These are per-input §1.5 signing
  messages and components of no txid, so the same reasoning gives the
  opposite answer: minting a name for one consumer is the
  fresh-name-for-nothing Q3 declined. Reopen if a second consumer appears,
  or if any site can pass one where a txid component is expected.
- **`Input::ToKey.key_image` stays raw here.** `shekyl_types::KeyImage`
  exists but is `redact, no_display`, and the wire codec's RPC projections
  hex-encode this field — typing it is the key-image *exposure* question,
  owned by the wallet-RPC and scanner lanes, not this slice.

Figure after the first run: 78 public items, 15 raw, all allowlisted.

**Second round (PR #777 review, 2026-09-18) — three more scanner gaps,
same lesson.** Copilot read the scanner rather than its output and found
what a `pub`-keyword, one-line scan still misses: (a) a `pub enum`'s
**tuple variants** — `TxExtraField::PubKey([u8; 32])` and
`AdditionalPubKeys(Vec<[u8; 32]>)` were public and unscanned; (b) a
**multi-line `pub fn` signature** puts the raw type on a line that does not
say `pub fn` (no such site exists today, which is exactly when to close the
gap); (c) the gate **never validated the allowlist's own invariant** — the
success line claimed every entry had a named addressee, and nothing checked
it. All three fixed with self-test legs: tuple variants are reported as
`Enum::Variant.0`; signatures are buffered to the body's `{`; the addressee
is a field on an `Allow(reason, addressee)` record that `check` asserts
non-empty. The two tuple variants are the tx public keys `R` — curve
points, one class with `Output.key` — allowlisted with the same addressee.

Figure after the second round: 78 public items, 17 raw, all allowlisted.

**Third round (PR #777 review, 2026-09-18, at `7906dab1d`) — wrapped
fields.** The same line-regex hole the second round closed for signatures
was still open for fields: `pub digest: Vec<\n    [u8; 32],\n>` puts the
raw type on a line with no `name:`, `pub_items` stays nonzero, and the
gate is vacuously green. Fields, enum-variant fields, and tuple-variant
payloads now share one buffer with signatures — a declaration is complete
when its type's bracket depth is zero, not when a comma appears (the last
field of a struct has none). Self-test legs for the wrap, the no-comma
last field, a wrapped enum field, and a wrapped tuple variant. The
archived §4 still described the pre-review `dict[str, str]` shape with
the addressee buried in the reason; that paragraph is the
`Allow(reason, addressee)` contract above. The unified implementation
index stamp was left at `20ebdf1e5` by this pass (rule 94: RTN-7 is a
row-local UPDATE; stamping HEAD would have claimed the DRS-E6 coverage
gate ran against a tree it never read) — the E6 lane's post-merge re-run
is what moves it (§7's closing note).

**Fourth round (2026-09-18) — public trait methods.** Copilot again read
the scanner: a `pub trait`'s methods are written `fn` with no `pub` and
are public through the trait — the third keyword-less surface, after
enum struct-variant fields and tuple-variant payloads (`varint::VarInt` is
the live instance). Now scanned as `Trait::method()`, with the item
closing at the top-level `}` so an `impl`'s `fn` is not mistaken for one;
self-test legs for a one-line and a multi-line trait method and for the
impl exclusion. The same round typed `BlockHeaderFacts`' roots in
`shekyl-daemon-rpc` — its comment said "neither root has a domain newtype
in this tree", which RTN-7 had made false, and the fix for a comment made
false by a type is the type, not a reworded comment — and minted
`BlockHash::NULL` so the genesis parent is one constant
(`A2::GENESIS_PREVIOUS` aliases it) instead of a `[0u8; 32]` in thirty
fixtures and the genesis tool.

Final figure: **81 public items scanned, 17 raw occurrences, all 17
allowlisted with a reason and a checked addressee.**

**Completion sweep (2026-09-18, post-merge, at `dev` = `51d7f2416`).** The
fourth round's "thirty fixtures" was a grep with one spelling: 32 more
`BlockHash::from_bytes([0; 32])` / `([0u8; 32])` sites survived across 24
fixture files (`shekyl-wire/tests`, engine-core test modules, the
curve-tree KATs, the rules crate's own `harness.rs` — where
`tip.map_or(BlockHash::NULL, |t| t.hash)` is CEN-A2 verbatim). All are
`BlockHash::NULL` now; the tree has no zero-array block hash left
(`rg 'BlockHash::from_bytes\(\[0(u8)?; 32\]\)' rust/` is empty). The
lesson is the A7 one from slice 1 in miniature: a sweep's denominator is
what the regex matched, and a literal has more than one spelling.

## 8. Two boundaries the implementation named that §3 did not

- **Persisted rows stay bytes.** `engine-state`'s `BlockchainTip`,
  `ReorgBlocks`, `LedgerIndexes::ingest_block` and the pscan cursor take
  `[u8; 32]`; their typing is `RAW_TYPE_NEWTYPE_MIGRATION.md` PR C's, and
  changing them touches postcard schemas. RTN-7 converts **at** those
  boundaries, once each, with the reason in a comment
  (`anchor_ledger_block`, `merge`'s `process_scanned_outputs`,
  `parent_hash_for_start`, `VerifiedBatch::frontier_hash`).
- **Transform-shaped crates take the signable hash as bytes.**
  `shekyl-fcmp`'s `proof::prove` / `verify` and
  `shekyl-archival-retention`'s `emission_vin_verify_*` / `auth_msgs` are
  original-PR-E territory. `PrefixHash` reaches their call site and becomes
  `to_bytes()` / `as_bytes()` there — visibly, at one line per call, which
  is what makes the un-typing reviewable instead of ambient.

Found by the types, disclosed rather than fixed: two tests
(`fcmp_spend_e2e`, `pl_d1_fix_falsifier`) sign the **prefix hash's bytes**
as a PQC payload message, where production signs
`phase1_payload_hashes()`. Their own comments already call it a stand-in
and never verify the auths, so the types now force a visible
`.to_bytes()`; switching them to the real payload is the e2e oracle
owner's call.
