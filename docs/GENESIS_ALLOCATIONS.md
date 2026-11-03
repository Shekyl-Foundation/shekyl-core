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
tx hash        a0fdfc7e4dab84e393f79ccf2c2f3783a95a9c1cdd9268c8d6221fdd9d582a90
block id       b5d7806b89f44f8b554dc280703ea37b2deb4703c9aa0098a8cac1844fccbd43
```

### stagenet

Source of truth: [`config/genesis_recipients.stagenet.json`](../config/genesis_recipients.stagenet.json)

| # | Label | Amount | Address |
|---|---|---|---|
| 1 | Founder allocation 1 | 20,000 SHEKYL | `sshekyl1qxf6qycn…sjq7kqx05v53` |
| 2 | Founder allocation 2 | 20,000 SHEKYL | `sshekyl1qy8pq22u…02233qh6f85r` |
| 3 | Founder allocation 3 | 20,000 SHEKYL | `sshekyl1qyvpyewa…aws4vqeqpuhs` |
| 4 | Founder allocation 4 | 20,000 SHEKYL | `sshekyl1qx2gcqvt…w28ycq49vu52` |
| 5 | Founder allocation 5 | 20,000 SHEKYL | `sshekyl1qytrrznj…60rn5sy6nxvj` |

Genesis identity:

```text
tx hash        78cc64efc390c5f58bda754234f2a4b912be43a3f5225cc11cf7010ae61f3676
block id       cac00a967665094f24cf805457dac58f9500b4c72d5cd1474871bb8905e58dce
```

### testnet

Source of truth: [`config/genesis_recipients.testnet.json`](../config/genesis_recipients.testnet.json)

| # | Label | Amount | Address |
|---|---|---|---|
| 1 | Developer 1 | 20,000 SHEKYL | `tshekyl1qxqn5fxs…kvev6sllnmq6` |
| 2 | Developer 2 | 20,000 SHEKYL | `tshekyl1q982fkyr…k07rpsuf8weu` |
| 3 | Developer 3 | 20,000 SHEKYL | `tshekyl1q96u7dvt…g6vy8sdgs86n` |
| 4 | Developer 4 | 20,000 SHEKYL | `tshekyl1qxsqrckq…9cql3s3wlecu` |
| 5 | Developer 5 | 20,000 SHEKYL | `tshekyl1qy56gmrp…xe22zs3mru89` |

Genesis identity:

```text
tx hash        36f8a897bf2c1dc700a6c3026d5f3a5fb3b9514ad5fe385a5105ceeff0fc91d4
block id       230bc902a5b375615c335f0e02ffe663c0779ae26912abb800d58a3cf3f417c3
```

### regtest

Source of truth: [`config/genesis_recipients.regtest.json`](../config/genesis_recipients.regtest.json)

Regtest's recipients are test wallets whose seeds are published in the
repository (`REGTEST_GENESIS_SEEDS`, `rust/shekyl-genesis-tool/src/table.rs`)
so a regtest harness can spend its genesis outputs. They hold nothing of
value and exist on no other network.

| # | Label | Amount | Address |
|---|---|---|---|
| 1 | Regtest test wallet 1 | 20,000 SHEKYL | `rshekyl1qxrehuwl…za7nss9cq933` |
| 2 | Regtest test wallet 2 | 20,000 SHEKYL | `rshekyl1qy7pgxjx…0ak2cs772z3t` |
| 3 | Regtest test wallet 3 | 20,000 SHEKYL | `rshekyl1qyrcv3c5…x4z8dqnrfq4e` |
| 4 | Regtest test wallet 4 | 20,000 SHEKYL | `rshekyl1qx2rxnny…vnxh2q74tkmx` |
| 5 | Regtest test wallet 5 | 20,000 SHEKYL | `rshekyl1q8vklna0…8f968s446lkg` |

Genesis identity:

```text
tx hash        d48f1669887960058dee197fa35ec4adf90daefbe53d73084baaf82a86ce5c45
block id       128ed909d9a222faaa2130be4da83bfd418f83726b12358f5cc147bcee3a9423
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
M = varint(len(net)) ‖ net_ascii            net = the network's name:
                                            mainnet | testnet | stagenet | regtest
    ‖ varint(n_recipients)
    ‖ for each recipient, in file order:
        spend_pk(32) ‖ view_pk(32)
        ‖ varint(len(ek)) ‖ ek              ML-KEM-768 encap key
        ‖ amount_atomic as u64 little-endian

seed      = cSHAKE256-32(customization = "shekyl/genesis-txkey-v2", input = M)
tx_secret = seed reduced mod ℓ
tx_pub    = tx_secret · G                   (the tx_extra 0x01 field)
```

This is how genesis commits to the network's name (NI-R12): the same
recipients under another name give another key, so another transaction
and another block.

## 4. Key custody

Testnet's and stagenet's recipient wallets were generated on 2026-11-03
with fresh operating-system entropy (`geblock gen-wallets`), one 32-byte
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
