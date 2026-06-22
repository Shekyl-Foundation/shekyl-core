# FCMP++ spend serialization & PQC signing preimage — C++ ↔ shekyl-wire reconciliation

**Status:** spec-grounded; consensus-critical. Written to ground the tx-builder
spend-encoding migration (§8 step-4) and the open §1.1 "Live FCMP++ spend KAT".
**No code lands on this spec alone** — it pins the C++ (daemon) layout so the
eventual implementation PR is reviewable, and documents that the *current*
tx-builder spend encoder diverges from the daemon in four consensus-critical spots.

## Why this doc

`shekyl-tx-builder/src/wire.rs` does two consensus-critical things: (1) serialize
the final FCMP++ spend, and (2) compute the per-input **PQC signing preimage**
(`phase1_payload_hashes`, mirroring C++ `get_transaction_signed_payload`). The two
are inseparable — the PQC signature signs a hash of the serialized form, so encode
and preimage must serialize the *same* bytes.

Migrating tx-builder onto `shekyl-wire` is therefore not a transparent swap. The
current encoder is built on `shekyl-oxide`, whose spend layout **does not match the
C++ daemon**; `shekyl-wire`'s layout **does**. So the migration is a *correctness
fix* whose parity target is the **C++ daemon / shekyl-wire**, never the current
shekyl-oxide output. Its full end-to-end proof is the live C++ oracle — the open
§1.1 spend KAT, blocked on the daemon spend path.

## 1. Canonical layout — the C++ daemon

### 1.1 Per-input PQC signing preimage
`get_transaction_signed_payload(tx, i)` (`src/cryptonote_core/tx_pqc_verify.cpp:58-152`):

```
payload(i) = prefix_blob ‖ rct_base_blob ‖ prunable_hash ‖ pqc_header(i) ‖ all_key_hashes
signed_hash(i) = keccak256(payload(i))         # PQC sig (ML-DSA+ed25519) signs this
```

- **prefix_blob** = `serialize(transaction_prefix)` — see §1.2. *Includes the tx version.*
- **rct_base_blob** = `rctSigBase::serialize_rctsig_base(inputs, outputs)` — see §1.3.
- **prunable_hash** = `keccak256(rctSigPrunable::serialize_rctsig_prunable(type, inputs, outputs))` — see §1.4 (a 32-byte digest, not the blob).
- **pqc_header(i)** = the i-th auth's header — see §1.5 (no signature bytes).
- **all_key_hashes** = `‖ over all auths: keccak256(hybrid_public_key)` (binds every input's key).

### 1.2 transaction_prefix (`src/cryptonote_basic/cryptonote_basic.h:368-374`)
```
VARINT(version)        # = 3 at genesis (Q12)   ← present in prefix_blob
VARINT(unlock_time)
FIELD(vin)             # varint(count) + inputs
FIELD(vout)            # varint(count) + outputs
FIELD(extra)           # varint(len) + bytes
```
The FCMP++ **`signable_tx_hash`** (what the membership/SAL proof signs) is the prefix
hash = `keccak256(serialize(transaction_prefix))` — **also includes `version=3`**.

### 1.3 rctSigBase (`src/fcmp/rctTypes.h:198-…`)
```
FIELD(type)                       # 1 byte: RCTTypeNull(coinbase) | RCTTypeFcmpPlusPlusPqc
if Fcmp:
    VARINT(txnFee)
    FIELD(referenceBlock)         # crypto::hash = 32 raw bytes   ← in BASE
enc_amounts                       # outputs × 9 bytes (amount[8] ‖ amount_tag[1]), no len prefix
enc_labels                        # outputs × 9 bytes,            no len prefix
outPk                             # outputs × 32 bytes (commitments), no len prefix
```

### 1.4 rctSigPrunable (`src/fcmp/rctTypes.h:348-…`)
```
VARINT(nbp)                       # bulletproof+ count (= 1 at genesis)
bulletproofs_plus[nbp]            # Bp+ structure
VARINT(curve_trees_tree_depth)
VARINT(proof_len) ‖ fcmp_pp_proof[proof_len]
pseudoOuts                        # inputs × 32 bytes, no len prefix
```
No `referenceBlock` here.

### 1.5 pqc_header (`tx_pqc_verify.cpp:109-124`, `cryptonote_basic.h:334-…`)
```
do_serialize(auth_version: u8)    # 1 byte
do_serialize(scheme_id:    u8)    # 1 byte
do_serialize(flags:        u16)   # 2 bytes LE (fixed)
FIELD(hybrid_public_key)          # VARINT(len) ‖ bytes        ← varint length
```

## 2. shekyl-wire matches the canonical layout

| Component | C++ | shekyl-wire | Match |
|---|---|---|---|
| prefix (minus version) | unlock_time ‖ vin ‖ vout ‖ extra | `TxPrefix::write` (`transaction.rs:972-984`) | ✅ |
| version | `VARINT(version)` first in prefix_blob | `Transaction::write` writes `varint(TX_VERSION=3)` (`:1044`); `TxPrefix` does **not** | ✅ (compose `varint(3) ‖ TxPrefix::write`) |
| rct base | type ‖ [fee ‖ refBlock] ‖ enc_amounts ‖ enc_labels ‖ outPk | `Ct::Fcmp::write` head (`:890-893`) + `CtBase::write` (`:645-655`) | ✅ |
| referenceBlock | `crypto::hash` 32B in base | `reference_block: [u8;32]` in base (`:863,892`) | ✅ |
| prunable | nbp ‖ bp+ ‖ tree_depth ‖ proof ‖ pseudoOuts | `Prunable::write` (`:808-819`) | ✅ |
| pqc_header | auth_ver ‖ scheme ‖ flags(u16) ‖ varint(len)‖pk | `PqcAuth` fields (`:678-…`) | ✅ (header-only writer needed) |

The coinbase live-oracle KAT (#168) pins the prefix + base byte-identity vs the
daemon; the spend round-trip (#169) exercises the prunable. This table is the
source-level confirmation that shekyl-wire's *spend* layout equals the C++ daemon's.

## 3. Divergences in the CURRENT tx-builder (`shekyl-tx-builder/src/wire.rs`, via shekyl-oxide)

These are bugs vs the C++ daemon — i.e. the present encoder produces spends/sigs the
daemon would reject (consistent with the known broken-spend status):

1. **prefix_blob omits `version`** (`serialize_prefix_blob` `:43-57`), and the prefix
   hash prepends `varint(2)` (`:61`) — should be `varint(3)` and present in the preimage.
2. **`reference_block` placement/type** — written as `varint(u64)` in *prunable*
   (`shekyl-oxide fcmp.rs:182,200`; `wire.rs:155`); the daemon has a 32-byte
   `crypto::hash` in *base*.
3. **prunable layout** carries `reference_block` and a different field set/order than
   the daemon's `nbp ‖ bp+ ‖ tree_depth ‖ proof ‖ pseudoOuts`.
4. **pqc_header length** — pubkey length as `u32`-LE (`wire.rs:74`); the daemon uses a
   `varint` length.

## 4. Migration spec (for the eventual consensus PR)

**Add to shekyl-wire** (the wire authority owns the format *and* its signing hashes):
- `Transaction::prefix_hash() -> [u8;32]` = `cn_fast_hash(varint(TX_VERSION) ‖ TxPrefix::write)`
  — the FCMP++ `signable_tx_hash`.
- `Transaction::pqc_signing_payload_hashes() -> Vec<[u8;32]>` — per input, the §1.1
  composition then `keccak256`, reusing the existing component serializers:
  `prefix_blob = varint(3) ‖ TxPrefix::write`; `rct_base_blob` = the `Ct::Fcmp` head
  (`CT_TYPE_FCMP ‖ varint(fee) ‖ reference_block ‖ CtBase::write`); `prunable_hash =
  keccak256(Prunable::write)`; `pqc_header(i)` (header-only); `all_key_hashes`.
  Expose **only** these two high-level methods; keep the component writers private.
- A private `pqc_header` writer on `PqcAuth` (auth_version ‖ scheme_id ‖ flags(u16) ‖
  varint(pk_len) ‖ pubkey) — no signature.

**tx-builder/wire.rs** then delegates: `encode_final_tx` → `Transaction::serialize`;
`phase1_payload_hashes` → `pqc_signing_payload_hashes`; `tx_prefix_hash*` →
`prefix_hash`. Map `WireEncodeInput` → `shekyl_wire::Transaction` (`Bulletproof` →
`BpPlus`, enc/commitments → `CtBase`, proof → `Prunable`). **Keep** shekyl-oxide's
*crypto* (`fcmp::bulletproofs::Bulletproof`, `primitives::keccak256`) — only the wire
encoding + preimage move. The `shekyl_oxide::transaction` + `shekyl_oxide::fcmp`
proof-type imports are removed.

## 5. Validation strategy

- **Source parity (this doc):** the shekyl-wire composition equals C++ §1.1–§1.5.
- **Component parity (already landed):** coinbase KAT #168 (prefix/base), spend
  round-trip #169 (prunable).
- **Golden vectors (new):** pin `prefix_hash` + `pqc_signing_payload_hashes` for fixed
  inputs so a future drift fails closed (mirror the `scan_output_kat` idiom).
- **Live C++ oracle (residual = §1.1):** build via tx-builder → the C++ daemon
  verifies the PQC auths + FCMP++ proof. Blocked on the daemon spend path; this is the
  end-to-end proof that closes both this migration and §1.1. Until it lands, the
  migration is *source- and corpus-validated but not live-proven*.

## 6. Decision (informed by this spec)

Two viable paths, to choose explicitly:
- **Implement now** as a consensus PR (source + corpus + golden validation; live
  oracle flagged as the §1.1 residual). Moves tx-builder onto the canonical format —
  strictly better than the confirmed-wrong shekyl-oxide encoding it replaces.
- **Defer** and do it together with §1.1 when the daemon spend path is free
  (post-PoW-cutover), so the first landing is live-oracle-proven.

Either way, the four §3 divergences are now documented so the broken-spend status has
a precise, reviewable root-cause.
