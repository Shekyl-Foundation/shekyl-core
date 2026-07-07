# Block/Tx Wire-Format Port — Rust ⇄ C++ consensus parity

**Status:** Open — design + implementation slice (scoped 2026-06-20, split out of
Track 2). **Authoritative spec for:** the Rust block/transaction (de)serializer as
the consensus wire format. **Parent:** [`TRACK2_REGTEST_PARITY.md`](TRACK2_REGTEST_PARITY.md)
(the differential rig that surfaced this).

This document is the executable brief for the slice — it can be handed to a fresh
context as the instruction set. Read the "Bootstrap" section first.

---

## 1. Objective

Make the Rust block/transaction (de)serializer in
`rust/shekyl-oxide/shekyl-oxide/src/{block.rs,transaction.rs}` parse — and
byte-faithfully **round-trip** — **live Shekyl PQC blocks** as produced by the
C++ daemon. Today `Block::read` fails with `UnexpectedEof` on a real block. Because
this is the block/tx **consensus wire format**, the work is a *genesis-format-
definition act*: design the canonical layout against the C++ oracle, implement one
Rust (de)serializer that owns it, and differential-test it to byte-identity.

## 2. Strategic context — why this gates the genesis freeze

- The **all-Rust consensus port is on the genesis critical path and gates the rule
  freeze**: you cannot freeze rules on an implementation you are mid-replacing —
  the Rust consensus must be the proven reference *before* the freeze.
- Collapsing each C++↔Rust FFI seam **is** the consensus migration. The Rust
  serializer written here becomes the **sole** implementation; the C++ serializer
  becomes the retiring **reference oracle**.
- **The C++ body is the oracle of intended rules** (no chain history exists
  pre-genesis). Each piece must be **differentially tested** — Rust against C++
  over a corpus, asserting **byte-identical** results — *before* C++ retires.
- **Hazard to guard hardest:** retiring C++ on "Rust passes current tests" when
  the tests are not yet a complete spec. Once C++ is gone the corpus *becomes* the
  consensus spec, so it must be comprehensive enough to *be* the spec first.
- At the seam, **arbitrate the canonical layout deliberately** — do not
  auto-default to whatever Rust currently does. Here the canonical layout is
  almost certainly the C++ format; confirm it is *intended* (not a C++ defect),
  then make Rust conform.
- **LMDB stays** — it is storage, not logic. Rust owns serialization/validation/
  consensus/crypto above it via `heed`.

## 3. The finding (precisely localized — do not re-investigate the green parts)

Reproduce on branch `feat/track2-regtest`:

```bash
SHEKYLD_BIN=/abs/path/build/bin/shekyld \
  cargo test -p shekyl-engine-core --lib e2e_refresh_detects_matured_coinbase \
  -- --ignored --nocapture
```

Parse-first, top-down diagnosis (already done):

- `get_height` → `Ok(71)` — RPC transport fine.
- `get_block` (json_rpc) returns a **1368-byte** blob — transport fine.
- `shekyl_oxide::block::Block::read(blob)` → **`UnexpectedEof` ("failed to fill
  whole buffer")**.

**Confirmed already-correct** (don't touch unless a corpus failure points here):
the block header incl. the Shekyl `curve_tree_root` field (`block.rs:47,77`); the
tagged-key coinbase outputs (`transaction.rs:214`, tag 3); the opaque ~1120-byte
PQC `tx_extra` (read length-prefixed, `transaction.rs:373`).

**The overshoot:** `transaction.rs:505` `Transaction::read` reads `version`(3) →
`TransactionPrefix::read` → then unconditionally
`P::Proofs::read(inputs.len(), outputs.len(), r)` (line 514). For the **coinbase**
(one `Input::Gen`), that proof/rct-section read overshoots → EOF. Expect the
coinbase's null-rct/proof framing — and then the spend tx's full FCMP++ proof
framing — to be where Rust and the C++ serializer disagree.

**Why it was invisible:** the vendored `shekyl-oxide` block/tx (de)serializer has
**never been run against a live block**. Every prior test replays `recon_kat` /
`ct2_tier_a.json` *fixtures* (JSON), so the wire-format gap never surfaced.

## 4. The oracle (C++ — the intended format)

- Block + tx + rct serialization: `src/cryptonote_basic/cryptonote_basic.h`
  (`BEGIN_SERIALIZE`/`FIELD` blocks for `block`, `block_header` — note
  `FIELD(curve_tree_root)` — `transaction`, `transaction_prefix`).
- Coinbase construction: `src/cryptonote_core/cryptonote_tx_utils.cpp:119`
  `construct_miner_tx`; per-output PQC at `:200` `shekyl_construct_output`.
- The rct/proof section + proof type (`FcmpPlusPlusPqc`, and the coinbase's null
  case): `src/ringct/` + `cryptonote_basic`.
- Ground truth at runtime: the daemon's `get_block` `blob` and `get_transactions`
  bytes. Treat these as authoritative.

## 5. The Rust side (where you implement)

`rust/shekyl-oxide/shekyl-oxide/src/transaction.rs` (`Transaction::read/write`
@505/~487, `ProofBase::read` @~415, `Proofs::read`, `TransactionPrefix` @348,
`Output` @214) and `block.rs` (`Block::read/write` @223/159, `BlockHeader` @21).

This is **vendored `shekyl-oxide`** — *ours* per rule 10 (the RPC sibling already
carries two tracked local patches; see [`SHEKYL_OXIDE_VENDORING.md`](../SHEKYL_OXIDE_VENDORING.md)).
Record new local patches there and plan to upstream to
`Shekyl-Foundation/monero-oxide@fcmp++` (divergence dissolves on the next
re-vendor that includes them).

## 6. Methodology — the differential rig

1. **Build the oracle corpus.** Use the Track-2 `RegtestDaemon` harness
   (`rust/shekyl-engine-core/src/engine/regtest_e2e.rs`): spawn
   `shekyld --regtest --fixed-difficulty 1`, mine, and pull raw `get_block` /
   `get_transactions` blobs. Cover coinbase-only blocks, blocks with a spend tx,
   staked outputs (output tag 4), and multi-tx blocks. Persist the **deterministic
   projection only** — raw daemon blobs + expected parsed structure — never
   wallet-randomized artifacts.
2. **Differential round-trip per item:** `Block::read(blob)` must succeed **and**
   `block.write()` must reproduce the **byte-identical** `blob`; likewise for
   `Transaction`. Byte-identity (not merely "parses") is the spec assertion.
3. **Coinbase first** (the current blocker), then the spend tx (full FCMP++ proof
   framing). Confirm each divergence is the *intended* C++ layout before conforming
   Rust to it.
4. **Collapse** only once the corpus is comprehensive: the Rust serializer becomes
   authoritative and the C++-retirement path is documented. Do **not** retire C++
   in this slice — make Rust conform and prove it.

## 7. Constraints / rules

- **Rule 42 (serialization-policy):** a *persisted-block wire change* ⇒
  version-constant bump (CI-enforced). This slice **implements the existing C++
  format in Rust, not changing it** → expected **no** bump; confirm. If the format
  itself must change, that is a genesis-format-definition decision to **surface**,
  not make silently.
- Rule 10 (shekyl-oxide is ours), rule 18 (byte-layout / type-placement), rule 30
  (crypto discipline), rule 45 (`cargo fmt` + `cargo clippy --all-targets -- -D
  warnings`), rule 50 (testing / diagnostics), rule 06 (short-lived branch off
  `dev`, each push separately authorized).
- Genesis-format-definition discipline: arbitrate canonical layout against the
  oracle; corpus = spec; differential byte-identity is the gate.

## 8. Deliverables

1. Rust `Block`/`Transaction` (de)serializer that round-trips live PQC blocks
   byte-identically vs the C++ oracle (coinbase + spend tx + staked).
2. A differential round-trip test/corpus (the seed of the consensus spec) — a test
   module driven by the regtest harness, `#[ignore]`d and `SHEKYLD_BIN`-gated.
3. Local-patch record in `SHEKYL_OXIDE_VENDORING.md` + upstream TODO.
4. This document, kept current with the canonical layout decisions (the genesis
   block/tx format definition).

## 9. Bootstrap (read first)

- Memories `consensus-port-gates-genesis` (strategic frame) and
  `track2-regtest-blockwire` (this finding + Track-2 state).
- [`TRACK2_REGTEST_PARITY.md`](TRACK2_REGTEST_PARITY.md).
- Branch `feat/track2-regtest` (commits `52fa21a9b` Phase 0 — harness + RPC fixes;
  `6963a0efe` the WIP refresh test documenting this finding). The `Block::read`
  differential probe in `regtest_e2e.rs::e2e_refresh_detects_matured_coinbase` is
  the starting rig.

## 10. Start here

Cut a branch off `dev` for this slice. Stand up a minimal differential harness
that pulls one coinbase block's raw blob via `get_block` and asserts
`Block::read`→`write` byte-identity; watch it fail at the coinbase proof framing;
trace `Proofs::read` for the `Input::Gen` case against the C++ coinbase
serialization; conform Rust to the oracle; expand the corpus outward (spend tx,
staked, multi-tx) until it is spec-complete.
