# Genesis Allocations

The complete, verifiable record of what genesis creates on each Shekyl
network: who receives it, how much, and how to rebuild the exact bytes
pinned in the source. This document fulfils the commitment made in
[`GENESIS_TRANSPARENCY.md`](GENESIS_TRANSPARENCY.md) §5.

Every figure here is checkable against the repository — nothing below is a
claim you have to take on trust. See [Reproducing genesis](#reproducing-genesis).

---

## 1. Summary

| | |
|---|---|
| Recipients per network | 5 |
| Allocation each | 20,000 SHEKYL (`20,000,000,000,000` atomic) |
| Total at genesis | 100,000 SHEKYL (`100,000,000,000,000` atomic) |
| Share of the 2^32 supply ceiling | 0.002329% |
| Foundation allocation | none |
| Premine beyond the above | none |

Amounts use the full currency name **SHEKYL** (the ticker SKL is not used
in this document). Genesis is the only block whose contents are not earned
by proof of work, and it is deliberately small, equal, and public. All five
allocations are identical; there is no tiered or preferential distribution.
The remaining 99.997671% of all SHEKYL that will ever exist must be mined.

Genesis outputs carry **cleartext amounts** (CT type Null) — unlike every
later transaction, they are not confidential. That is intentional: the
founding allocation is auditable by anyone, forever. Once spent, these
outputs receive exactly the same FCMP++ membership privacy as any other
output; the transparency is scoped to the allocation itself.

## 2. Allocations

Every network's genesis is built the same way (`NETWORK_IDENTITY.md`
NI-R4): five recipients, the transaction key derived from the network's
name and its recipients, and the block header with nonce 0. The pins live
in the network table, `rust/shekyl-network/genesis/<network>.tx.hex` and
`<network>.hash`.

### mainnet

Source of truth: [`config/genesis_recipients.mainnet.json`](../config/genesis_recipients.mainnet.json)

**Provisional.** Mainnet's recipients are re-derived by their custodians
at the genesis ceremony under the current wallet derivation, and this
table and the pin move with them (NI-R11; `docs/FOLLOWUPS.md`). The
genesis below is not the one mainnet launches with.

| # | Label | Amount | Address |
|---|---|---|---|
| 1 | Founder allocation 1 | 20,000 SHEKYL | `shekyl1q9y7r7cn8…xqjudqx2ex3q` |
| 2 | Founder allocation 2 | 20,000 SHEKYL | `shekyl1q8slynhua…mz3c8s48rrt0` |
| 3 | Founder allocation 3 | 20,000 SHEKYL | `shekyl1q9g0g2vmt…9epsysdwr77m` |
| 4 | Founder allocation 4 | 20,000 SHEKYL | `shekyl1qyuvwck4v…z32unsvq9jqx` |
| 5 | Founder allocation 5 | 20,000 SHEKYL | `shekyl1qypaqfqxf…leqzus5pdly4` |

Genesis identity:

```text
tx hash        027cd4eab42c68d4906a5106d6015de2c5b7e9c7fd9b1bbad6ab311ee3e5d7ab
block id       f91dd5408ce12f0032ec3d48b367d8bf40f8c3498f3ea199153532d41c254279
```

### stagenet

Source of truth: [`config/genesis_recipients.stagenet.json`](../config/genesis_recipients.stagenet.json)

| # | Label | Amount | Address |
|---|---|---|---|
| 1 | Founder allocation 1 | 20,000 SHEKYL | `sshekyl1qyfcskvl…k7r4lqmna0wy` |
| 2 | Founder allocation 2 | 20,000 SHEKYL | `sshekyl1q834vknk…cnyujq9hpd72` |
| 3 | Founder allocation 3 | 20,000 SHEKYL | `sshekyl1qywmgzk8…vjc9eq945auw` |
| 4 | Founder allocation 4 | 20,000 SHEKYL | `sshekyl1q8rk2wxf…mda6lqqt2rn4` |
| 5 | Founder allocation 5 | 20,000 SHEKYL | `sshekyl1qxwz8w4h…qtthdq0qv0st` |

Genesis identity:

```text
tx hash        3396d303a926c50e8dc745915d91597ecdb7c20aebd8245cf2e8c1ad57b5688d
block id       73bc5f22c340c37ff589f4f08ecd00113c55553f1c8ce539ce0abe3335c5833f
```

### testnet

Source of truth: [`config/genesis_recipients.testnet.json`](../config/genesis_recipients.testnet.json)

| # | Label | Amount | Address |
|---|---|---|---|
| 1 | Developer 1 | 20,000 SHEKYL | `tshekyl1qylh4dak…av8rvsxypdv0` |
| 2 | Developer 2 | 20,000 SHEKYL | `tshekyl1qyqsj9em…qpv7ns64wtly` |
| 3 | Developer 3 | 20,000 SHEKYL | `tshekyl1q9hqaurw…9u556su2pkz4` |
| 4 | Developer 4 | 20,000 SHEKYL | `tshekyl1q8nx0z5w…5qv65qz3u27m` |
| 5 | Developer 5 | 20,000 SHEKYL | `tshekyl1qxgvt06s…383jmsmk4cue` |

Genesis identity:

```text
tx hash        a4ce0b6b0a434e77a5b31f58d2cc6516b5e224335bc397b371b3fa6715e82344
block id       b76542286f60b2a21be1672c5494f66b8a80e5f89bea66e5a26aab977989ef39
```

### regtest

Source of truth: [`config/genesis_recipients.regtest.json`](../config/genesis_recipients.regtest.json)

Regtest's recipients are test wallets whose seeds are published in the
repository (`REGTEST_GENESIS_SEEDS`, `rust/shekyl-genesis-tool/src/table.rs`)
so a regtest harness can spend its genesis outputs. They hold nothing of
value and exist on no other network.

| # | Label | Amount | Address |
|---|---|---|---|
| 1 | Regtest test wallet 1 | 20,000 SHEKYL | `rshekyl1q8kzj2s4…5k2f2svnjpx9` |
| 2 | Regtest test wallet 2 | 20,000 SHEKYL | `rshekyl1q82e75az…h4vsksw663vd` |
| 3 | Regtest test wallet 3 | 20,000 SHEKYL | `rshekyl1qytj4xn0…fsl4cq74lrau` |
| 4 | Regtest test wallet 4 | 20,000 SHEKYL | `rshekyl1q97w3w35…sdtfxs03n8wc` |
| 5 | Regtest test wallet 5 | 20,000 SHEKYL | `rshekyl1q8es9vja…8v86zsvcw5xy` |

Genesis identity:

```text
tx hash        3a96f09b3b1cabc7b4bf7e3b0d91dbd9410f3f7180ee0874ec26503be1753b6e
block id       7662cdc11aa4e5df3da1231532d2b027714dc14e4f16a6d785be76f1bce4f2a3
```

Addresses are truncated above for readability only — the full strings are
in the linked JSON files, which are the bytes genesis actually commits to.
Each address is a three-segment Bech32m string
(`<classical>/<ML-KEM part A>/<ML-KEM part B>`) carrying the hybrid
post-quantum key material Shekyl requires from genesis.

## 3. Reproducing genesis

The genesis transaction key is **derived deterministically from the
network's name and its recipients file**, so every pinned genesis is
reproducible by anyone — you do not have to trust that the published
addresses are the ones actually paid. From a checkout at the commit that
pins this genesis:

```bash
cd rust
cargo run -p shekyl-genesis-tool --bin geblock -- verify
cargo run -p shekyl-genesis-tool --bin geblock -- build --network mainnet > /dev/null
```

`verify` rebuilds all four networks from the committed recipients files and
byte-compares each transaction and block hash against the network table's
pins; `build` prints the transaction hash to check against the tables
above. CI runs the same comparison on every change
(`rust/shekyl-genesis-tool/tests/genesis_table.rs`), which also recomputes
each pinned coinbase's transaction key from the network's name, so the
pins, the names and the published recipients cannot drift apart unnoticed.

### Why the transaction key is public

Genesis publishes its amounts and its recipients by design, so a genesis
transaction key protects nothing: its jobs — amount privacy and recipient
unlinkability — are deliberately absent at height 0. It also cannot spend:
moving these funds requires the recipients' secret spend keys and an FCMP++
membership proof. Deriving it publicly therefore discloses nothing this
document does not already state, and buys full reproducibility of the
founding block.

Derivation (implemented in `rust/shekyl-genesis-tool/src/txkey.rs`):

```text
R = varint(n_recipients)
    ‖ for each recipient, in file order:
        spend_pk(32) ‖ view_pk(32)
        ‖ varint(len(ek)) ‖ ek              ML-KEM-768 encap key
        ‖ amount_atomic as u64 little-endian

seed      = frame("shekyl/genesis-txkey-v3", name_id, [R])     32 bytes
tx_secret = seed reduced mod ℓ
tx_pub    = tx_secret · G                   (the tx_extra 0x01 field)
```

`frame` is the signing envelope's: cSHAKE256 under the customization,
over the 16-byte binding and then each field behind its u64
little-endian length. The binding is the network's `name_id`, derived
from its name (`shekyl/network-name-v1`), the value every key derivation
is salted with. This is how genesis commits to the network's name
(NI-R12): the same recipients under another name give another key, so
another transaction and another block.

## 4. Key custody

Testnet's and stagenet's recipient wallets were generated on 2026-11-04,
under the derivation salt `name_id ‖ shekyl-master-derive-v3`, with fresh
operating-system entropy (`geblock gen-wallets`), one 32-byte
seed per wallet, written once as its 24 BIP-39 words to custody files
outside any repository; every address is decoded back for its network
before it is written. Mainnet's custodians generate theirs the same way at
the genesis ceremony. No component of the Shekyl stack can re-export a seed
after creation.

Only public addresses appear in this repository. Seed material for
mainnet, stagenet and testnet has never been committed to any repository
and is held offline. Regtest's seeds are the exception, published on
purpose (§2).

## 5. Change policy

Genesis is frozen at launch: after the first block is mined on a network,
its allocations cannot change. Before launch, any change to this table
means regenerating the genesis transaction and re-pinning every derived
artifact together: `geblock pin` writes the network table's pins, and
the procedure is `shekyl-dev/docs/GENESIS_WALKTHROUGH.md`. The header nonce
is 0 on every network. The network id is not a constant beside the chain:
it is the first 16 bytes of
`cSHAKE256(S = "shekyl/p2p-network-id-v1", X = genesis_block_hash)`, so
regenerating the genesis transaction rotates it. There is no id byte to
leave untouched.
