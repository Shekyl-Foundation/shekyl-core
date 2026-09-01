# Consensus surface census — Survey A

**Status:** OPEN — Survey A of the consensus-validation surface.
Last-verified 2026-08-30 against `dev` `0e6d340e`. This is a survey, not
a set of rulings: it classifies and flags; it does not decide.
**Method:** fresh clone, `dev` @ `0e6d340e` (2026-08-30). Every claim below is
a `file:line` observation, not a doc reading.
**Dispositions since:** U-5 and the `rpc_port` half of L-6 landed 2026-08-31
(PR #587 deletes both fields from the P2P wire; `peer_id` — the rest of
L-6 — stays open for P2P-2).

**Classification buckets** (per `16-architectural-inheritance.mdc` §"When to
migrate vs. when to keep", which already requires a recorded "why" for every
inherited subsystem):

| Bucket | Meaning | C++ as oracle? |
|---|---|---|
| **S** | Shekyl-specific. Written spec exists. | N/A — spec is the oracle |
| **R** | Inherited, examined, ratified. Rationale recorded. | **Yes** |
| **D** | Inherited, examined, marked for deletion. | No — it's going |
| **U** | Inherited, **never examined**. | **No — and differential testing here fossilizes it** |

Bucket **U** is the product of this survey. Everything else is bookkeeping.

---

## 1. Surface inventory

C++ consensus core, 17,712 lines across `cryptonote_core` + `cryptonote_basic`:

| File | Lines |
|---|---|
| `blockchain.cpp` | 7,769 |
| `tx_pool.cpp` | 2,396 |
| `cryptonote_core.cpp` | 1,794 |
| `cryptonote_format_utils.cpp` | 1,558 |
| `miner.cpp` | 1,151 |
| `cryptonote_tx_utils.cpp` | 811 |
| `account.cpp` | 589 |
| `hardfork.cpp` | 424 |
| `cryptonote_basic_impl.cpp` | 339 |
| `tx_verification_utils.cpp` | 287 |
| `tx_pqc_verify.cpp` | 249 |

Plus `blockchain_db` + LMDB at 17,849. **`blockchain.cpp` carries 256 lines
referencing archival/bond/shard/serve-credit**, so the staking consensus is
already interleaved through the inherited core rather than sitting beside it.

Rust consensus-relevant crates already exist and are substantial:
`shekyl-consensus`, `shekyl-difficulty`, `shekyl-archival-retention`,
`shekyl-fcmp`, `shekyl-fcmp-proofs`, `shekyl-bulletproofs`, `shekyl-ct-balance`,
`shekyl-curve-tree`, `shekyl-economics`, `shekyl-pow-randomx`, `shekyl-levin`,
`shekyl-wire`, `shekyl-tx-weight`, `shekyl-standoff`.

**Observation.** The Rust side is not a greenfield — much of the *new*
consensus is already there. What is C++-only is the **chain-assembly and
storage spine**: block connect/disconnect, alt-chain handling, the pool, the
DB. That is a materially smaller and more tractable target than "rewrite the
daemon", and it is exactly the part with the least examination.

---

## 2. Bucket S — Shekyl-specific, spec'd (fortify, don't touch)

| Surface | Where | Note |
|---|---|---|
| FCMP++ membership | `shekyl-fcmp`, `shekyl-curve-tree` | replaces rings from genesis |
| Hybrid PQC | `shekyl-crypto-pq`, `tx_pqc_verify.cpp` | ML-KEM-768+X25519 / ML-DSA-65+Ed25519 |
| RandomX v2 | `randomx-v2-sys`, `shekyl-pow-randomx` | + `shekyl-randomx-differential` |
| LWMA-1 DAA | `shekyl-difficulty/src/lwma1.rs` | **Not Monero's DAA.** Verbatim transcription of `DAA_LWMA1.md` §5.3, step-annotated |
| Archival staking | `shekyl-archival-retention` (30+ modules) | bond posts, serve credit, challenges, settlement |
| Deferred tree insertion | Phase 4 audit, genesis-frozen 2026-04-04 | `eligible_height`, compound key |
| 2021 fee scaling | validated in the A3 round | KAT-pinned; era-max cap derived |

**Strength worth naming:** the DAA is already a clean-room replacement with a
spec document and step-level traceability. That is the model for what bucket-U
items should look like when they exit this census.

---

## 3. Bucket R — inherited and ratified

- **2021 dynamic fee scaling** (`blockchain.cpp:6595` cites the ArticMine
  document). Examined in the A3 fee round; the 65×–1077× tier spread is
  KAT-pinned at `tests/unit_tests/scaling_2021.cpp`, and the era-max cap is
  derived rather than literal. **C++ is a legitimate oracle here.**
- **Block weight / long-term-weight penalty**, same origin, same round.
- **LMDB transactional semantics** — `pop_block` reversal atomicity was ruled
  in the Phase 4 audit.

This bucket is thin. That is the finding, not an accident of survey depth.

---

## 4. Bucket D — inherited, disposition recorded

Rule 60 already lists: MLSAG, Borromean, CLSAG, `RCTType*`, CryptoNight,
mixin enforcement, `partial_block_reward`, `get_outs.bin` decoy selection.
Rule 60's own text is the disposition record.

**Verified partially discharged:** `bulletproof` appears once in
`blockchain.cpp`; `get_random_outs` zero times; `m_blocks_txs_check` zero.
Rule 60 is being enforced where PRs have reached.

---

## 5. Bucket U — inherited, never examined

### U-1 — The hardfork machinery (HIGH: pure dead weight, consensus-adjacent)

`src/hardforks/hardforks.cpp:35-37`:

```c
// Rebooted chain: all features active from genesis.
const hardfork_t mainnet_hard_forks[] = {
  { 1, 1, 0, 1341378000 },
};
```

**One fork. Version 1. Height 1.** Yet `hardfork.cpp` retains 424 lines of
Monero's *voting* machinery: `default_threshold_percent`, `get_effective_version`
from a voting version, a window, `get_earliest_ideal_height_for_version`, and a
DB-backed version history. `blockchain.cpp` still calls
`get_earliest_ideal_height_for_version(HF_VERSION_DYNAMIC_FEE)` at `:2688` —
resolving a fork height on a chain with exactly one fork at height 1.

`cryptonote_config.h` still defines **11** `HF_VERSION_*` constants.

This is the single clearest instance of rule 60's "no version dispatch" and
rule 16's "user-protection defaults in user-absent contexts": miner-voted
activation thresholds exist to coordinate a deployed network through an
upgrade. There is no deployed network. **Disposition to consider: collapse the
hardfork subsystem entirely; `get_current_hard_fork_version()` becomes a
constant.** That deletes 424 lines plus every call site, and removes a
consensus input that can be wrong.

*Caveat for the competing survey to test:* is there a post-genesis upgrade
story that needs versioning? If yes, the answer is a *designed* mechanism, not
Monero's miner-voting inheritance.

### U-2 — `unlock_time` (HIGH: partially removed, residue is live)

Phase 4 ruled timestamp-based `unlock_time` rejected from genesis, and
`blockchain.cpp:3438` enforces it. **But the field and its machinery survive:**

- `:1683` — coinbase must have `unlock_time == height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW`
- `:2681` — `is_tx_spendtime_unlocked(m_db->get_tx_unlock_time(...))`
- `:4559-4562` — the function itself, still branching on `CRYPTONOTE_MAX_BLOCK_NUMBER`
- `:347` — `handle_output(output_index.unlock_time, ...)` in the output visitor

Meanwhile the Phase 4 ruling made the **curve tree the spendability enforcer**
via `eligible_height`. So there are plausibly **two** spendability mechanisms:
the tree, and the inherited per-output unlock check. If the tree is
authoritative, the unlock path is a second definition of the same rule — the
three-IP-classifier shape, on consensus. If both are load-bearing, the
interaction has never been written down.

**This is the highest-value item in the census.** It needs a ruling, not a
port.

### U-3 — Alt-chain / reorg handling (HIGH: large, unexamined, safety-critical)

`switch_to_alternative_blockchain` at `:1386`, 42 `alt_chain` references,
`get_alternative_blocks` at `:2639`. Inherited wholesale. Never audited against
Shekyl's model, and Shekyl adds two things Monero doesn't have:

1. the **curve tree**, whose `pop_block` reversal must be atomic (Phase 4)
2. **archival serve-credit and slash settlement**, which are epoch-scoped and
   whose reorg semantics across an epoch boundary are not obviously covered by
   inherited alt-chain logic

`FCMP_REFERENCE_BLOCK_MIN_AGE=5` exists for reorg safety, which shows the
interaction was considered *once*, for one parameter. The general question —
what does a reorg do to serve credit, challenge assignment, and slash
watermarks — needs an explicit answer.

### U-4 — The transaction pool (MEDIUM-HIGH: 2,396 lines, 189 relay-related)

`tx_pool.cpp` carries 189 references to relay/`kept_by_block`/`do_not_relay`.
Shekyl has its own relay privacy design (Dandelion++, zones, noise carriers,
`shekyl-relay`, `shekyl-relay-privacy`). The inherited pool has its own
relay-decision logic, its own `do_not_relay` semantics, and its own eviction
and re-relay timing.

**The question is whether two relay-decision systems coexist.** If the pool
makes any relay timing decision independent of the Dandelion++ layer, that is
a privacy leak channel that no Dandelion++ round would have caught, because
the rounds examined the relay layer and not the pool.

### U-5 — `rpc_credits_per_hash` in the P2P handshake (LOW severity, ZERO cost)

> **LANDED 2026-08-31 (PR #587):** deleted from the wire; the survey text
> below records the pre-deletion state.

`p2p_protocol_defs.h:185,194` carries `rpc_credits_per_hash` in
`basic_node_data`, serialized on every handshake. 21 references tree-wide,
across `net_peerlist`, `connection_context`, boost serialization.

This is Monero's **RPC-payment / mining-pool-credit** system — a feature
Shekyl does not have and, under the ratified operator-to-operator RPC posture
(`RPC_TRANSPORT_POSTURE.md` RT-1…RT-9), will never have. It is a field on the
wire that advertises a capability that does not exist.

**Free deletion, pre-genesis.** Post-genesis it is a permanent wire field.

### U-6 — `NOTIFY_NEW_BLOCK` alongside `NOTIFY_NEW_FLUFFY_BLOCK` (MEDIUM)

Both survive: `cryptonote_protocol_defs.h:184` and `:334`, with
`handle_notify_new_block` live at `cryptonote_protocol_handler.inl:590`.

Monero kept the legacy full-block notify for backward compatibility during the
fluffy-block transition. **Shekyl has no such transition.** Two block-propagation
paths means two code paths that must agree on validation, two surfaces for a
propagation-level attack, and — given the Dandelion++ work assumed a specific
propagation shape — a path the privacy analysis may not have covered.

The relay round adopted "Design A: fluffs traverse every configured zone."
Whether `NOTIFY_NEW_BLOCK` traverses zones the same way is a question the
census should force.

### U-7 — Output histogram / distribution (LOW: RPC-only, but consensus-adjacent)

`get_output_histogram` / `get_output_distribution` exist and are RPC-exposed
(`core_rpc_server.cpp:1872`). In Monero these serve **decoy selection**. With
FCMP++ there is no decoy selection. `blockchain.cpp:2686-2688` still contains
`// rct outputs don't exist before v4` and a `HF_VERSION_DYNAMIC_FEE` height
lookup.

Under RT-9's precedent (`--public-node` removed because an affordance is what
people reach for), an endpoint whose only purpose was ring selection is a
candidate for deletion rather than maintenance.

### U-8 — Timestamp validation (MEDIUM: partially Shekyl, partially inherited)

`check_block_timestamp` at `:5568`/`:5589` with a median window. The DAA crate
owns `FTL_SECONDS` and `MTP_WINDOW` as named constants
(`shekyl-difficulty/src/consts.rs:39,43`), so the *parameters* are Shekyl's.
Whether the *algorithm* in `blockchain.cpp` matches the DAA spec's assumptions,
or is still Monero's inherited median-past-time check with Shekyl numbers
plugged in, is unverified. A DAA is only as sound as its timestamp validation.

### U-9 — `miner.cpp` (1,151 lines, unexamined)

In-daemon mining. Under Shekyl's design, mining is where the **miner-chosen
mandatory coinbase-revealed challenge** originates. Whether the inherited
miner has been audited against that requirement — and whether an in-daemon
miner should exist at all, given it is an attack surface on a node that may
hold staking keys — is unrecorded.

---

## 6. Levin — specific weaknesses worth fixing pre-genesis

`shekyl-levin` is 1,781 lines of Rust and is already a clean-room
reimplementation, which is a strength. The **wire format** is inherited, and
these are the known-weak points:

### L-1 — The signature is a fixed constant, and it fingerprints the protocol

`header.rs:14`: `LEVIN_SIGNATURE = 0x0101_0101_0101_2101`. Eight fixed bytes
at the head of every connection is a **perfect DPI signature**. Any censor or
ISP can identify Shekyl P2P traffic with an 8-byte match on the first packet.

For a privacy-maximalist chain this is the single largest protocol-level
fingerprint. Monero has it because Monero inherited it and cannot change it
without a network-wide flag day. **Shekyl can change it for free, right now,
and never can again after genesis.**

Options worth the competing survey's attention: derive the prefix from the
network id; or drop the fixed prefix entirely in favour of an authenticated
handshake whose first bytes are indistinguishable from random. The latter is
what modern censorship-resistant transports do, and it composes with the Tor
work rather than duplicating it.

### L-2 — `DEFAULT_MAX_PACKET_SIZE = 100 MB` (`header.rs:27`)

100 MB per packet, versus a 256 KiB pre-handshake limit. A 100 MB allocation
ceiling on a post-handshake peer is a memory-amplification lever: a handful of
peers each claiming a large payload can exhaust a node. `fragment.rs:30` checks
the claim *before* allocation, which is the right shape — but the ceiling
itself is inherited, not derived. It should be **derived from the largest
legitimate message** (a max-weight block plus overhead), the way the fee cap
was re-derived from the era maximum.

### L-3 — Unknown flag bits are preserved verbatim

`header.rs:29-30`: "Unknown bits are preserved verbatim so a decode/encode
round-trip is byte-identical." That is correct for a *relay* of foreign
packets and wrong for a protocol with one implementation. Preserved unknown
bits are a covert channel: two colluding peers can signal through them across
an honest relay. Pre-genesis, the correct posture is **reject unknown flag
bits**, not preserve them.

### L-4 — `return_code: i32` on every bucket (`header.rs:103`)

An inherited RPC-over-Levin affordance. Error codes on a P2P wire leak
implementation state to a peer. Worth asking whether any Shekyl command
actually reads it, and deleting it if not.

### L-5 — Compression: zstd level 1, min payload 256 B (`compress.rs:25,32`)

Compression before encryption is a **CRIME/BREACH-class oracle** whenever an
attacker can influence part of a compressed message and observe its length.
The Dandelion++ work established a 16 KiB/s per-node ceiling and fixed-size
padding for noise carriers — compression interacts directly with those
size-based defences. Whether compression is disabled on the paths where
padding is load-bearing is a question the relay rounds may not have asked,
because compression lives in the Levin layer and padding lives above it.

`DECOMPRESSED_MAX_SIZE = 128 MB` (`compress.rs:29`) is also a zip-bomb
ceiling that exceeds the packet ceiling.

### L-6 — Handshake carries `my_port`, `rpc_port`, `peer_id`

> **PARTIALLY LANDED 2026-08-31 (PR #587):** the `rpc_port` half is deleted
> from the wire; `my_port` and `peer_id` remain open (P2P-2). The survey
> text below records the pre-deletion state.

`p2p_protocol_defs.h:180-196`. `peer_id` is a persistent random identifier
that **links a node across IP changes** — the exact linkage a privacy chain
should not volunteer. Monero uses it for self-connection detection. There are
cheaper ways to detect self-connection (a per-connection nonce) that do not
create a persistent cross-session identifier.

`rpc_port` advertises an RPC endpoint over P2P — directly contrary to RT-9's
removal of `--public-node` advertising. **Deleting `--public-node` while
leaving `rpc_port` in the handshake is an incomplete disposition.**

---

## 7. Cross-cutting observations

**O-1 — The staking consensus is interleaved, not layered.** 256
archival/bond references inside `blockchain.cpp` means a store-and-core rewrite
cannot treat staking as a separate module. Any rewrite plan that assumes it can
port the "Monero part" and keep the "Shekyl part" is wrong at the outset.

**O-2 — Bucket R is thin and bucket U is large.** The ratified-inheritance list
is three items; the unexamined list is nine plus six Levin items. That
asymmetry is the argument for the census preceding any rewrite: **most of the
consensus surface currently has no specification other than its own source.**

**O-3 — Every U-item is cheapest now.** U-1, U-5, U-6, U-7, and every L-item
are free pre-genesis and permanent after. This is not a rewrite argument; it is
a deadline that applies whether or not the rewrite happens.

**O-4 — The strengths are real and worth protecting.** LWMA-1 with a
step-annotated spec, the derived fee cap, the FCMP++ and PQC surfaces, the
existing Rust crate decomposition, and `shekyl-levin` as a clean-room reader
are all in good shape. The census should *close* these as bucket S/R rather
than reopening them.

---

## 8. Proposed disposition shape (for synthesis, not a ruling)

1. **Free deletions, no design needed:** U-5 (`rpc_credits_per_hash`), L-6's
   `rpc_port`, U-7 if confirmed ring-only.
2. **Deletions needing one ruling each:** U-1 (hardfork machinery), U-6
   (legacy block notify), L-3 (unknown flag bits), L-4 (`return_code`).
3. **Design rounds required:** U-2 (`unlock_time` vs. tree — the highest-value
   item), U-3 (reorg × serve-credit × tree), U-4 (pool vs. Dandelion++),
   L-1 (protocol fingerprint), L-5 (compression × padding).
4. **Derivations owed:** L-2 (packet ceiling from max legitimate message),
   U-8 (timestamp validation against the DAA spec).
5. **Audit, disposition unknown:** U-9 (`miner.cpp`).

**What the second survey should be asked to falsify:** that bucket R is really
this thin; that `unlock_time` and the curve tree are really two mechanisms;
that the pool really makes independent relay decisions; and whether U-1's
hardfork collapse breaks a post-genesis upgrade story that this survey did not
consider.