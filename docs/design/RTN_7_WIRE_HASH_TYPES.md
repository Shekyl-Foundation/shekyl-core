# RTN-7 — the wire crate's hash surface is typed, and a gate keeps it so

**Status:** OPEN — Round 0 (rule-26 pre-flight), written 2026-09-17 against
`dev` = `398d85e7b` (post-#768). **Halt condition:** no production code
lands until PR #771 (`RTN-1…RTN-6`) is on `dev` — this item's `AttestationRoot`
and `#![no_std]` `shekyl-types` arrive there, and #771 edits the same
`block.rs` doc lines. Family: `RTN-1…RTN-N`, registered by #771
([`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2); this is the
seventh item. Work plan of record:
[`RAW_TYPE_NEWTYPE_MIGRATION.md`](RAW_TYPE_NEWTYPE_MIGRATION.md) §6, whose
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
  is the redb key wrapper; its `redb::Value::from_bytes` carries the one
  `.expect("Hash32 is 32 bytes (redb fixed_width)")` on a typed daemon
  value (`:117`). RTN-7 adds `From<BlockHash>` / `From<TxHash>` on it (the
  orphan rule keeps `impl redb::Key for shekyl_types::*` out; #771's "will
  not do" list). **Finding:** the `Tagged<V>` retrofit that is meant to fold
  that `expect` in is **not recorded anywhere greppable** — not in
  `FOLLOWUPS.md`, `DAEMON_REDB_STORE.md`, `DRS_E1_SCHAIN_R.md`, nor the
  S-CHAIN-R worktree. Under rule 23 an intended change with no row is
  undisposed. Owed to whoever owns it: a FOLLOWUPS row naming `Hash32`'s
  `expect` and this PR's `From` impls as the signature it lands against.
  Falsify by `rg 'Tagged<' docs/ rust/` returning a row.

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
| `Ct::Fcmp.reference_block` | `[u8; 32]` | `BlockHash` | **ruled in 2026-09-17, for a reason beyond symmetry:** it is `ref_height`'s companion — the field CEN-I12's finding is about. Raw beside a typed `previous` is the asymmetry someone asks about in six months and finds no answer for. **Scope consequence, stated:** this reaches `shekyl-tx-builder`, the *construction* side, and reference-block selection is the path the I12 gap lives on. Type-only or not, that changes who reviews it — the tx-builder owner reviews the `reference_block` commit, not only the wire owner. |
| `BondPost.p_canonical_id` | `[u8; 32]` | `PCanonicalId` | **Q1** — `PCanonicalId` exists (`redact` arm: truncated `Debug`, full `Display`); the wire field predates it. Same class as the hashes (an identity, not a crypto object). Default: **in**. |

### 3.2 Out — stays `[u8; 32]`, named in the gate's allowlist with the reason

| Surface | Reason |
| --- | --- |
| `Output.key`, `CtBase.commitments`, `BpPlus.{a,b,l,r}`, `Prunable.pseudo_outs` | curve points / scalars — transform-shaped crypto objects, `RAW_TYPE_NEWTYPE_MIGRATION.md` original PR E, **DEFERRED** to the defining crates. #771 mints `OneTimePubkey` / `CommitmentBytes` for `TransferDetails` (engine-state persistence), not for the wire codec; adopting them here is that family's next item, not this one. |
| `PqcOwnershipEntry.group_id` (`tx_extra.rs:108`) | a multisig group id — an identity, but with no `shekyl-types` newtype and no consumer that would distinguish it; **Q2**: mint `GroupId` here, or allowlist with this reason and a reopening criterion (a second consumer). Default: allowlist. |
| `Transaction::prefix_hash()` | the FCMP++ `signable_tx_hash` — a *signing preimage digest*, not a chain identity; consumed by `shekyl-tx-builder` as bytes to sign. Not a `TxHash` (it would be wrong to let one be passed where the other is expected — that is the confusion the types exist to refuse). **Q3**: allowlist as-is, or mint `SignableTxHash`. Default: allowlist; reopen if a second consumer appears. |
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
`RUST_ONLY_TABLES`, `DEFERRED_DOCS`, `CXX_HOLDER_RE` — `{item: reason}`,
unnamed occurrences red.

- **Subject:** every `pub` field type and `pub fn` signature in
  `rust/shekyl-wire/src/**/*.rs` containing `[u8; 32]` (including
  `Vec<[u8; 32]>`, `Option<[u8; 32]>`, `&[[u8; 32]]`). `pub(crate)` is not
  surface and is not scanned.
- **Allowlist:** `ALLOWED: dict[str, str]` of `"<file>::<item>": "<reason>"`
  — §3.2's rows, byte-exact.
- **Red in both directions (rule 47):** an occurrence not in the allowlist;
  an allowlist entry whose item no longer exists (the allowlist may not
  outlive its subject); an empty scan (the crate moved, the regex broke —
  absence of signal is first evidence the subject is absent).
- **Self-test** (`--selftest`): a synthetic `pub previous: [u8; 32]` goes
  red; a synthetic allowlisted item passes; a stale allowlist entry goes
  red; an empty tree goes red.
- Wired into `docs-gates.yml`'s bundled grep gates.

## 5. Commit plan (rule 90; ≤ 10)

1. `wire: hash returns and header fields are typed` — `txid.rs` returns,
   `Block::hash()`, `BlockHeader.{previous,curve_tree_root,attestation_root}`,
   `Block.transaction_hashes`, `BondPost.p_canonical_id` (Q1). Serializer
   unchanged; every parity KAT (`pruned_tx_hash_parity`,
   `serve_credit_tx_parity`, live-oracle pin, block vectors) green
   unchanged — that is the proof the change is type-only.
2. `wire: Ct::Fcmp.reference_block is a BlockHash` — its own commit, its
   own reviewer (§3.1).
3. `chain-store: Hash32 converts from the identity types` — `From<BlockHash>`,
   `From<TxHash>`; codec call sites.
4. `chain-rules: …`, 5. `engine-core: …`, 6. `daemon-rpc + genesis-tool +
   singletons: …` — one fixup commit per consuming crate; deletions of
   `from_bytes` wrappers, wrapped literals in tests.
5. `ci: check_wire_raw_hash_surface — the wire surface refuses raw [u8; 32]`
   — gate + selftest + workflow wiring.
6. `docs:` — §6 rows closed in `RAW_TYPE_NEWTYPE_MIGRATION.md` (status
   table gains the RTN-7 row, LANDED); index RTN row `UPDATE`; CHANGELOG
   API entry; this doc's banner → LANDED and `git mv` to `docs/completed/`
   (rule 95). FOLLOWUPS row for the `Tagged<V>` finding (§2) if its owner
   has not landed one.

## 6. Open questions for ruling

- **Q1** `BondPost.p_canonical_id: PCanonicalId` — default in (§3.1).
- **Q2** `group_id` — allowlist with reason, or mint `GroupId`. Default: allowlist.
- **Q3** `prefix_hash()` — allowlist as a signing-preimage digest, or mint
  `SignableTxHash`. Default: allowlist.
- **Q4** Gate breadth — chain-identity types only (this doc), or every
  `[u8; 32]` on the surface with the crypto objects allowlisted (§3.2 is
  written for the latter; the ruling's wording — "refusing `[u8; 32]`
  outside a named allowlist" — is the latter). Default: the latter.
- **Q5** Reviewer of record for commit 2 (`reference_block`): the
  tx-builder / I12 owner.
