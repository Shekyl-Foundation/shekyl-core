// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Foundational **state-shaped** domain newtypes shared across the Shekyl
//! wallet and consensus stack.
//!
//! These are the identity, position, and clock types that `wallet2.cpp`
//! carried as interchangeable raw `u64` / `[u8; 32]` scalars, lifted into
//! distinct types so the compiler rejects the confusions that a KAT would
//! otherwise have to catch later: a block hash passed where a tx hash is
//! expected, a wall-clock timestamp subtracted from a block height, an
//! in-transaction output index used as a ledger-wide global index.
//!
//! This crate is the canonical home for these types per
//! `18-type-placement.mdc` (state-shaped types live with a foundational
//! semantic owner, not in `shekyl-curve-tree` where some predecessors
//! incidentally landed). It is the vocabulary crate of
//! `docs/design/RAW_TYPE_NEWTYPE_MIGRATION.md` (`RTN-1…RTN-N`); downstream
//! crates import from here rather than redefining. `#![no_std]` so a leaf
//! math crate (`shekyl-difficulty`) can consume the same types the store
//! and wallet do — refusing that edge is how `BlockHeight` got redefined
//! as `u64` in the DAA.
//!
//! ## Two clocks, four types
//!
//! Per the 2026-06-14 decision-log entry "Time fields: block-height vs
//! wall-clock dichotomy", plus the count/ordinal split
//! (`HEIGHT_SEMANTICS.md`):
//!
//! - [`BlockHeight`] — an **absolute chain instant** (ordinal). Consensus-
//!   and on-chain-evaluated deadlines (maturity, spend eligibility,
//!   stake-claim windows) live here.
//! - [`BlockCount`] — a **relative block span** (à la `Duration` vs
//!   `Instant`). Instant arithmetic on this axis is expressed against it.
//! - [`Timestamp`] — **wall-clock Unix seconds, UTC**. Off-chain,
//!   human-facing, cross-party, or wallet-local-audit deadlines live here.
//! - [`ChainCount`] — the chain's total **block count**. The dispatch
//!   clock for same-clock thresholds (`anchor_t0`, due, alarm,
//!   `Dispatched::at`): COUNT compared only to COUNT. Not an ordinal
//!   index — flipping a count to [`ChainCount::tip`] fires those
//!   thresholds one block late.
//!
//! Height, count, and timestamp are distinct types: `height + span`
//! yields a height, `count + span` yields a count, `height - height`
//! yields a span, and `height + height` / `count + height` /
//! `height - timestamp` do not compile. The named bridges between
//! [`ChainCount`] and [`BlockHeight`] are [`ChainCount::tip`],
//! [`ChainCount::next_height`], [`ChainCount::from_next_height`], and
//! [`ChainCount::has_block`]. `from_raw` / `to_raw` are the decode/encode
//! edge, not a quantity bridge.
//!
//! ## Boundaries
//!
//! Inner fields are private. Conversion is through the named edge
//! constructors/accessors ([`BlockHeight::from_raw`] / [`BlockHeight::to_raw`],
//! [`TxHash::from_bytes`] / [`TxHash::to_bytes`]), so the conversion call
//! sites are the greppable edge set that bounds each migration — the same
//! discipline `AtomicUnits` uses. `#[serde(transparent)]` +
//! `#[repr(transparent)]` keep every type wire- and ABI-identical to the
//! primitive it wraps: postcard bytes match the bare `u64`. A type-name
//! change in a persisted field still bumps the owning block's version
//! (`42-serialization-policy.mdc`); the schema snapshot is the identity.
//!
//! ## What lives here when two stores need it
//!
//! **A type both stores need lives in `shekyl-types`; the computation lives
//! in the owning crate.** The daemon store (`shekyl-chain-store`) and the
//! wallet-side store (`shekyl-curve-tree`) key and hold the same chain facts
//! and neither may depend on the other's graph. [`KeyImage`],
//! [`CurveTreeRoot`], [`TreePosition`] and [`TreeLeaf`] each reached this
//! answer by the same argument (`18-type-placement.mdc`, "Where each shape
//! lives"); the sentence is here so the next instance is a lookup, not a
//! question. The arithmetic over those bytes — the Selene hash, path
//! assembly, the drain order — stays in `shekyl-curve-tree` / `shekyl-fcmp`;
//! this crate holds the word, never the computation.
//!
//! ## Exposure policy on the 32-byte identities
//!
//! Not every 32-byte chain fact may reach a string. The `hash32!` family has
//! three arms, and the arm a type is minted with is its **exposure policy**
//! (see the macro's table): public hashes ([`BlockHash`], [`TxHash`],
//! [`CurveTreeRoot`]) render in full; a persona id ([`PCanonicalId`]) keeps a
//! full-hex `Display` but truncates `Debug`; a wallet-correlating identity
//! ([`KeyImage`]) truncates `Debug`, has **no `Display`**, and has **no
//! `AsRef<[u8]>`** — `to_string()` and `hex::encode(key_image)` do not compile.
//! A `KeyImage` in a log is an on-chain spend linked to a wallet; the policy
//! is on the type so no call site has to remember it.
//!
//! ```compile_fail
//! let key_image = shekyl_types::KeyImage::from_bytes([0u8; 32]);
//! let _ = key_image.to_string(); // no `Display`: this is the type's policy, not an omission
//! ```
//!
//! ```compile_fail
//! fn assert_as_ref<T: AsRef<[u8]>>() {}
//! assert_as_ref::<shekyl_types::KeyImage>();
//! ```
//!
//! A chain **count** is not an ordinal **height**. Passing one where the
//! other is required is the Phase 1 defect (`HEIGHT_SEMANTICS.md` C9);
//! the mix does not compile.
//!
//! ```compile_fail
//! fn needs_height(_h: shekyl_types::BlockHeight) {}
//! needs_height(shekyl_types::ChainCount::from_raw(1));
//! ```
//!
//! ```compile_fail
//! fn needs_count(_c: shekyl_types::ChainCount) {}
//! needs_count(shekyl_types::BlockHeight::from_raw(0));
//! ```
//!
//! ```compile_fail
//! let _ = shekyl_types::ChainCount::from_raw(10) + shekyl_types::BlockHeight::from_raw(1);
//! ```
//!
//! ```compile_fail
//! let _ = shekyl_types::ChainCount::from_raw(10) - shekyl_types::BlockHeight::from_raw(1);
//! ```

#![no_std]
#![deny(unsafe_code)]

// `alloc`, not `std`: the archival vocabulary (`archival::ShardSet`, a
// bounded id list) needs `Vec`. A `no_std` consumer with any global
// allocator — every crate that takes this one today — is unaffected.
extern crate alloc;

use core::fmt;

/// Defines a `u64`-backed, transparent domain newtype with the common edge
/// surface (`ZERO`, `from_raw`, `to_raw`, `is_zero`). Block-axis Instant/
/// Duration algebra lives in the `block_axis` module.
macro_rules! scalar_u64 {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(
            Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default,
            ::serde::Serialize, ::serde::Deserialize, ::zeroize::Zeroize,
        )]
        #[cfg_attr(feature = "schema", derive(::postcard_schema::Schema))]
        #[serde(transparent)]
        #[repr(transparent)]
        pub struct $name(u64);

        impl $name {
            #[doc = concat!("The zero ", stringify!($name), ".")]
            pub const ZERO: Self = $name(0);

            /// Wrap a raw `u64`. An *edge* constructor — use it only where a
            /// value crosses into the typed domain (FFI, RPC decode,
            /// deserialization helpers).
            #[must_use]
            pub const fn from_raw(value: u64) -> Self {
                $name(value)
            }

            /// Unwrap to the raw `u64`. An *edge* accessor — use it only
            /// where a value crosses back out to a `u64`-typed boundary.
            #[must_use]
            pub const fn to_raw(self) -> u64 {
                self.0
            }

            /// Whether this is the zero value.
            #[must_use]
            pub const fn is_zero(self) -> bool {
                self.0 == 0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

/// Defines a `[u8; 32]`-backed, transparent identity-hash newtype with
/// `from_bytes` / `to_bytes` / `as_bytes`.
///
/// Three arms, one per **exposure policy** — how much of the value may reach a
/// string:
///
/// | arm | `Debug` | `Display` | `AsRef<[u8]>` | for |
/// | --- | --- | --- | --- | --- |
/// | `Name` | full hex | full hex | yes | public, non-correlating hashes (`TxHash`, `BlockHash`) |
/// | `Name, redact` | first two bytes | full hex | yes | ids whose *log* leak correlates an origin edge, but whose hex encoding is a wire form (`PCanonicalId`) |
/// | `Name, redact, no_display` | first two bytes | **none** | **no** | ids whose stringly-typed leak correlates a wallet to its on-chain spends (`KeyImage`) — `to_string()` and `hex::encode(value)` must not compile |
///
/// The derives and accessors are shared (`@core`); `Display` is opt-in
/// (`@display`); `AsRef<[u8]>` is opt-in (`@as_ref`) so a `no_display` identity
/// is not a generic byte sink; each arm picks its `Debug`.
macro_rules! hash32 {
    // Default `Debug` renders the full hex — public, non-correlating hashes
    // (`TxHash`, `BlockHash`, …) where the whole value aids debugging and the
    // chain already publishes it.
    ($(#[$doc:meta])* $name:ident) => {
        hash32!(@core $(#[$doc])* $name);
        hash32!(@as_ref $name);
        hash32!(@display $name);

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                // Delegate to the hex `Display` rather than dumping the raw byte
                // array; `debug_tuple().field(...)` keeps the single field
                // represented so `missing_fields_in_debug` is satisfied.
                f.debug_tuple(stringify!($name))
                    .field(&format_args!("{self}"))
                    .finish()
            }
        }
    };

    // `redact` opts a correlation-sensitive identity into a **truncated** `Debug`
    // (first two bytes only). The value is public on chain, but the *full* id in a
    // local log or panic backtrace is an origin-edge correlation artifact — it
    // links the principal's machine to the persona. 16 bits disambiguate for
    // debugging without reproducing the whole identifier in an unsanitised stream.
    // `Display` is deliberately left full: it is the canonical hex *encoding*, not
    // a log line.
    ($(#[$doc:meta])* $name:ident, redact) => {
        hash32!(@core $(#[$doc])* $name);
        hash32!(@as_ref $name);
        hash32!(@display $name);
        hash32!(@debug_redacted $name);
    };

    // `redact, no_display` is the tighter posture: truncated `Debug` **and no
    // `Display` at all**. For an identity whose leak links a wallet to its
    // on-chain spends (a key image), a `Display` is not an encoding — it is the
    // stringly-typed boundary (`to_string()`, `format!("{}")`, a `Display`-based
    // error message) through which the full value reaches a log. The hex form is
    // still reachable on purpose through `as_bytes()`; it is not reachable by
    // accident. Adding a `Display` later is a policy change for the type's owner,
    // not a convenience for a call site.
    ($(#[$doc:meta])* $name:ident, redact, no_display) => {
        hash32!(@core $(#[$doc])* $name);
        hash32!(@debug_redacted $name);
    };

    // Truncated `Debug`, shared by both `redact` arms.
    (@debug_redacted $name:ident) => {
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                // Render through the debug builder, like the default arm — one idiom
                // for all three, just truncated content. `format_args!` (Debug) emits
                // the two bytes unquoted, so the output is `Name(dead..)`.
                f.debug_tuple(stringify!($name))
                    .field(&format_args!("{:02x}{:02x}..", self.0[0], self.0[1]))
                    .finish()
            }
        }
    };

    // Lowercase-hex `Display` — the canonical encoding, opted into by the arms
    // whose policy allows the full value to reach a string.
    (@display $name:ident) => {
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                // Iterate by reference: avoids copying the `[u8; 32]` out of
                // `&self`, and `&self.0` is the form the workspace's denied
                // `explicit_iter_loop` clippy lint requires over `.iter()`.
                for &byte in &self.0 {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
        }
    };

    // Generic byte-view for public hashes. Deliberately **not** on the
    // `no_display` arm: `AsRef<[u8]>` is the bound `hex::encode` and any
    // `impl AsRef<[u8]>` logger accept, which is the stringly-typed
    // accident `no_display` exists to prevent. Named `as_bytes` stays.
    (@as_ref $name:ident) => {
        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }
    };

    // Shared core — derives, accessors; **neither** `Debug` nor `Display`
    // nor `AsRef`, which the arms above add per exposure policy.
    (@core $(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        // `PartialOrd`/`Ord` (lexicographic over the bytes) so these hashes
        // can key the `BTreeMap`/`BTreeSet`s that wallet-state uses for
        // deterministic txid/block ordering — the engine-state txid maps that
        // PR C migrates require `Ord` keys.
        #[derive(
            Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash,
            ::serde::Serialize, ::serde::Deserialize, ::zeroize::Zeroize,
        )]
        #[cfg_attr(feature = "schema", derive(::postcard_schema::Schema))]
        #[serde(transparent)]
        #[repr(transparent)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Wrap raw bytes. An *edge* constructor.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                $name(bytes)
            }

            /// Unwrap to the raw bytes. An *edge* accessor.
            #[must_use]
            pub const fn to_bytes(self) -> [u8; 32] {
                self.0
            }

            /// Borrow the raw bytes (e.g. for a hash input or a map key).
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl Hash32Bytes for $name {
            fn from_bytes(bytes: [u8; 32]) -> Self {
                $name(bytes)
            }
            fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}

/// The byte edge of a `hash32!` identity, as a bound.
///
/// Each member already exposes inherent `from_bytes` / `as_bytes` /
/// `to_bytes`. This trait is what a generic helper names so a new family
/// member is usable without a second hex-serde (or store-key) copy.
pub trait Hash32Bytes: Copy + Sized {
    /// Wrap raw bytes. Same contract as the inherent edge constructor.
    fn from_bytes(bytes: [u8; 32]) -> Self;
    /// Borrow the raw bytes. Same contract as the inherent accessor.
    fn as_bytes(&self) -> &[u8; 32];
    /// Unwrap to the raw bytes.
    fn to_bytes(self) -> [u8; 32] {
        *self.as_bytes()
    }
}

scalar_u64! {
    /// An absolute block height on the Shekyl chain.
    ///
    /// The canonical "chain instant." Arithmetic is expressed against
    /// [`BlockCount`] (a span), never against another `BlockHeight` directly
    /// for addition — `height + height` is meaningless and does not compile.
    BlockHeight
}

scalar_u64! {
    /// A relative span of blocks (a *duration*, not an instant).
    ///
    /// `StakeTier.lock_blocks` and reorg-window depths are [`BlockCount`]s,
    /// not [`BlockHeight`]s. The distinction mirrors `Duration` vs `Instant`.
    BlockCount
}

scalar_u64! {
    /// Wall-clock time as Unix seconds since the epoch, UTC.
    ///
    /// Used for off-chain, human-facing, cross-party, or wallet-local-audit
    /// deadlines (invoice expiry, multisig-proposal TTL, address provenance)
    /// — *not* for any consensus- or chain-evaluated deadline, which is a
    /// [`BlockHeight`].
    Timestamp
}

scalar_u64! {
    /// The chain's total **block count** — the daemon's `m_db->height()`
    /// operand, which is **one past the tip** (a chain of N blocks has tip
    /// height N − 1).
    ///
    /// Distinct from both [`BlockHeight`] (an absolute instant — a count is
    /// not a position) and [`BlockCount`] (a relative span between two
    /// instants — a count is anchored at genesis). C++ overloads the word
    /// "height" for this value, which is exactly the confusion this type
    /// exists to stop: laundering a count into a height via
    /// `BlockHeight::from_raw` admitted records one block early in the
    /// emission-claim spendability anchor and stored a not-yet-existing
    /// "height" in refusals (claim-builder PR-3 review).
    ///
    /// Same-clock thresholds (assemble `anchor_t0`, due, alarm, dispatch
    /// `at`) hold this type and compare it only to another count. The
    /// named bridges to [`BlockHeight`] are:
    ///
    /// - [`ChainCount::tip`] — the newest existing block (`count − 1`;
    ///   `None` on an empty chain), the spendability / anchoring operand;
    /// - [`ChainCount::next_height`] — the height the *next* block will
    ///   carry (numerically the count itself), the earliest-inclusion
    ///   operand and the exclusive end of a `0 .. count` scan;
    /// - [`ChainCount::from_next_height`] — C6's inverse: exclusive-end
    ///   ordinal back to count. Not "this existing block, laundered."
    /// - [`ChainCount::has_block`] — whether an ordinal is in `0 .. count`.
    ///
    /// Which fact a call site means is spelled at the call site instead
    /// of carried in a comment. `from_raw` is the decode edge, not a
    /// quantity bridge.
    ChainCount
}

scalar_u64! {
    /// A ledger-wide global output index (the daemon's `next_output_seq`
    /// counter), assigned densely to every output in **chain scan order** —
    /// coinbase first, then each transaction's `vout` in block order.
    ///
    /// This is **not** the curve-tree position: leaves enter the tree in
    /// `(maturity, gindex)` drain order and coinbase matures 50 blocks after
    /// a transaction output from the same block, so the two orders diverge in
    /// the first block that carries a transaction (`SOK-10`). The tree's own
    /// dense position is `shekyl_curve_tree::TreePosition`; a value of this
    /// type is never a tree position and never converts to one implicitly.
    ///
    /// Canonical replacement for the historical `shekyl-curve-tree::Gindex`.
    /// Distinct from [`OutputIndexInTx`]: this is the chain-wide position, not
    /// the position within a single transaction's output vector.
    GlobalOutputIndex
}

/// An archival-persona slot ordinal — the index into the staker's derive-forward
/// persona set (`ARCHIVAL_BOND_CONSTRUCTION.md` §10.2 Model D).
///
/// Distinct from [`OutputIndexInTx`] / [`GlobalOutputIndex`] / raw `u32` so a
/// persona slot cannot be silently passed where a tx-output index or a
/// chain-wide gindex is expected. Wire-transparent (`#[serde(transparent)]` +
/// `#[repr(transparent)]`) over `u32`.
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Default,
    ::serde::Serialize,
    ::serde::Deserialize,
)]
#[cfg_attr(feature = "schema", derive(::postcard_schema::Schema))]
#[serde(transparent)]
#[repr(transparent)]
pub struct PSlot(u32);

impl PSlot {
    /// Wrap a raw slot index at the typed-domain edge.
    #[must_use]
    pub const fn from_raw(value: u32) -> Self {
        Self(value)
    }

    /// Unwrap to the raw `u32` at a `u32`-typed boundary (e.g. HKDF slot args).
    #[must_use]
    pub const fn to_raw(self) -> u32 {
        self.0
    }

    /// Alias for [`Self::to_raw`] — matches the historical `stake_engine::PSlot::index`
    /// call sites that feed `derive_archival_p_keys`.
    #[must_use]
    pub const fn index(self) -> u32 {
        self.0
    }
}

scalar_u64! {
    /// The position of an output within its own transaction's output vector.
    ///
    /// May be sparse (outputs can be absent/burned). Distinct from
    /// [`GlobalOutputIndex`], which is the dense chain-wide position; mixing
    /// the two is the confusion this type exists to prevent.
    OutputIndexInTx
}

scalar_u64! {
    /// An archival reward **settlement-epoch** index — the epoch in whose units
    /// a bond's rewards settle, counted in spans of `SETTLEMENT_EPOCH_BLOCKS`
    /// (consensus), distinct from a raw [`BlockHeight`].
    ///
    /// The archival firewall's funding-inflow accrual and reward claims are
    /// keyed by [`SettlementEpoch`], not a bare `u64`, so an epoch index can
    /// never be silently passed where a block height or an amount is expected.
    SettlementEpoch
}

scalar_u64! {
    /// An archival **shard** identifier — a corpus partition, not a height,
    /// epoch, or gindex.
    ///
    /// Bond-post `shard_ids`, serve-credit `(P, s, E)`, and emission preimages
    /// all name shards. A bare `u64` here transposes against [`SettlementEpoch`]
    /// or [`BlockHeight`] and binds the wrong commitment.
    ShardId
}

scalar_u64! {
    /// A leaf's position **inside a frozen segment** (the archival serve unit),
    /// not a ledger-wide [`GlobalOutputIndex`] and not the curve tree's dense
    /// drain-order position (`shekyl_curve_tree::TreePosition` — that type is
    /// not in this crate).
    LeafIndex
}

scalar_u64! {
    /// A block's **weight** (serialized size used by the median / long-term
    /// window), not an amount and not a difficulty.
    ///
    /// Distinct from [`LongTermWeight`] so a connect fact cannot pass one
    /// where the other is expected.
    BlockWeight
}

scalar_u64! {
    /// A block's **long-term weight** (the clipped weight that feeds the
    /// long-term median), not [`BlockWeight`] and not an amount.
    LongTermWeight
}

hash32! {
    /// A block's **proof-of-work longhash** — RandomX v2 over the block's
    /// PoW preimage (`Block::pow_blob`) under a seed block's identity
    /// (CEN-D2, CEN-D3). What CEN-D1 compares against the difficulty target
    /// (`hash · difficulty < 2^256`, CEN-D1b).
    ///
    /// Not a [`BlockHash`]: the identity is `keccak256` over the same bytes
    /// with a length prefix, and the two are never interchangeable — a
    /// longhash passed as a block id, or a block id compared against a
    /// target, is exactly the transposition this type refuses. Minted by
    /// the validation crate's stateless stage (`shekyl-chain-rules::form`,
    /// DRS-E6 slice 2) from a `Substrate::longhash` the daemon implements;
    /// no consensus code computes RandomX except behind that call.
    PowHash
}

hash32! {
    /// A block identity hash.
    ///
    /// Distinct from [`TxHash`], from [`PowHash`] (the longhash over the
    /// same preimage), and from a curve-tree root: a block hash can never
    /// be passed where a transaction hash is expected.
    BlockHash
}

impl BlockHash {
    /// The **null hash** — 32 zero bytes — as a block identity: the genesis
    /// block's `previous` (CEN-A2: a candidate's parent is the tip's hash,
    /// or null when there is no tip), the C++ `null_hash`.
    ///
    /// Named once, here, so the genesis parent is a constant every crate
    /// reads rather than a `[0u8; 32]` each one spells — the consensus rule
    /// aliases it as `A2::GENESIS_PREVIOUS`, fixtures chain from it, and the
    /// genesis tool writes it. It is a *block hash* on purpose: no
    /// `CurveTreeRoot` or `TxHash` gets a `NULL`, because for a root the
    /// all-zero encoding is the identity point (CEN-I12's hazard;
    /// [`CurveTreeRoot::EMPTY`] is the real empty state), and a null txid
    /// names no transaction.
    pub const NULL: Self = Self::from_bytes([0u8; 32]);
}

hash32! {
    /// A transaction identity hash (txid).
    ///
    /// Distinct from [`BlockHash`]. Canonical replacement for the ad-hoc
    /// `TxHash([u8; 32])` previously defined in `shekyl-engine-core`.
    ///
    /// The **output** of the txid construction. Its inputs are the
    /// component hashes — [`PrefixHash`] (first), the base hash (second,
    /// never surfaced), [`PqcAuthHash`] (third), [`PrunableHash`] (fourth)
    /// — and each is a distinct type so no component can be passed where
    /// the txid is expected, or the txid where a component is
    /// (`RTN-7`, `RTN_7_WIRE_HASH_TYPES.md` Q3).
    TxHash
}

hash32! {
    /// `keccak256(varint(TX_VERSION) ‖ transaction_prefix)` — the **first
    /// component** of a transaction's [`TxHash`], and the FCMP++
    /// `signable_tx_hash` the membership/SAL proof signs
    /// (`FCMP_SPEND_SIGNING_PREIMAGE.md` §1.2; the C++ `cn_fast_hash` over
    /// `transaction_prefix`, version varint first).
    ///
    /// A member of the component-hash family beside [`PqcAuthHash`] and
    /// [`PrunableHash`], not a signing-specific category: the value the
    /// builder signs *is* the txid's first component, and one type for one
    /// value is what lets the type system refuse the confusion a bare
    /// `[u8; 32]` permits — a prefix hash passed to `TxHash::from_bytes`, or
    /// a txid handed to the signer (`RTN-7`, Q3). Distinct from [`TxHash`]
    /// in both directions.
    PrefixHash
}

hash32! {
    /// `keccak256` of a transaction's **prunable byte region** — the bytes
    /// past `unprunable_size` (C++ `calculate_transaction_prunable_hash`).
    ///
    /// The fourth component of an FCMP++ spend's [`TxHash`], and what the
    /// chain store records per transaction (`txs_prunable_hash`) so a pruned
    /// body can be bound back to its txid. Derived once by the validation
    /// crate beside the txid (S-CHAIN-W SCW-10); the store records it and
    /// never computes it (C2-R8 Q4).
    ///
    /// **Not** the txid's substitute for an absent region: a coinbase's txid
    /// uses the null hash as its third component, but its prunable region is
    /// the empty byte string and this value is `keccak256("")`. Distinct
    /// from [`TxHash`] so the two can never be swapped at a store boundary.
    PrunableHash
}

hash32! {
    /// The **third component** of an FCMP++ spend's [`TxHash`]:
    /// `keccak256(varint(count) ‖ pqc_auths)` over the per-input hybrid
    /// authorizations (`PDM-Q-F26`; `DAEMON_REDB_STORE.md` §7.7).
    ///
    /// Exists so a node that discards `pqc_auths` after verification
    /// (`PDM-Q6` item 2) can still reconstruct the txid from what it kept:
    /// this and the [`PrunableHash`], mixed with the retained skeleton.
    /// Derived once by the validation crate beside the txid; the store
    /// records it and never computes it (C2-R8 Q4).
    ///
    /// Carried as `Option<PqcAuthHash>` wherever a txid's components are
    /// named, and the `None` is a fact about the **txid**, not about what a
    /// node holds: a coinbase, a serve-credit and the malformed gen-first
    /// shape hash **3-part**, so no third component exists to be stored or
    /// supplied. The arity is the wire crate's one predicate, never a
    /// per-input-arm judgment — a bond-post is 4-part like any spend.
    ///
    /// **Not** the hash of the stored `txs_pqc_auths` segment, which carries
    /// no count prefix and so verifies nothing the chain signed. Distinct
    /// from [`PrunableHash`] so the two components can never be swapped when
    /// a store hands them back for reconstruction.
    PqcAuthHash
}

hash32! {
    /// The block-header **attestation root** (archival credit-wire witness
    /// commitment), not a [`CurveTreeRoot`] and not a [`BlockHash`].
    ///
    /// The wire header field is this type (`shekyl_wire::BlockHeader`). The
    /// codec reads and writes the 32 bytes via [`Self::from_bytes`] /
    /// [`Self::as_bytes`].
    AttestationRoot
}

hash32! {
    /// An output's **one-time public key** (CryptoNote `P = H_s(rA) G + B`),
    /// 32-byte compressed Ed25519 encoding.
    ///
    /// Distinct from [`KeyImage`] (the spend identifier `I = x · H_p(P)`),
    /// from [`CommitmentBytes`] (the amount commitment), and from [`TxHash`].
    /// On-chain public; full-hex `Debug`.
    OneTimePubkey
}

hash32! {
    /// An output's **Pedersen amount commitment** as 32 compressed bytes.
    ///
    /// Distinct from [`OneTimePubkey`] and from [`KeyImage`]. The curve type
    /// lives in `shekyl-curve-primitives`; this is the store/wire *name* so a
    /// commitment cannot be passed where a pubkey is expected.
    CommitmentBytes
}

hash32! {
    /// The root of the FCMP++ curve tree **as recorded** after a block — the
    /// membership anchor a spend's proof is verified against.
    ///
    /// A *name* for a value the tree crate computes: growing the tree with a
    /// block's matured leaves and producing the root the next block's header
    /// must carry is the consensus state transition (`CONSENSUS_C2_R8_STORE_PLACEMENT.md`
    /// §5), owned by `shekyl-curve-tree` and the validation crate. Minted here
    /// so a rule can *read* a recorded root without depending on the crate that
    /// computes it. The wire header field is this type
    /// (`shekyl_wire::BlockHeader.curve_tree_root`); the codec reads and
    /// writes the 32 bytes via [`Self::from_bytes`] / [`Self::as_bytes`].
    ///
    /// Distinct from [`BlockHash`] / [`TxHash`]: a root is a commitment to a set
    /// of outputs, not an identity, and one can never be passed where the other
    /// is expected. Public, non-correlating; full-hex `Debug`.
    CurveTreeRoot
}

scalar_u64! {
    /// A leaf's **dense position in the FCMP++ curve tree** — the index in
    /// drain order `(maturity, gindex)`, assigned when a matured output's
    /// leaf enters the tree (`CT2_DRAIN_ORDER.md` §2.2).
    ///
    /// Not a [`GlobalOutputIndex`]: outputs are indexed in chain-scan order at
    /// creation and enter the tree later in maturity order, so the two
    /// diverge in the first block that carries both a coinbase and a
    /// transaction output. Not a [`BlockHeight`]. A value of this type is
    /// never a position in any other sequence.
    ///
    /// Both stores key their leaf tables by it — the daemon store's
    /// `curve_tree_leaves` (DRS-E1 S-CURVE) and the wallet-side store's
    /// `leaves` — which is why the word lives here (crate docs, *What lives
    /// here when two stores need it*; ruled `SCU-Q2`). Each store wraps it in
    /// its own redb key type; the drain-order arithmetic that *assigns* one
    /// stays in `shekyl-curve-tree`.
    TreePosition
}

/// One **curve-tree leaf as stored**: the four Selene scalars
/// `{O.x, I.x, C.x, CM.x}` — the output key, its key-image generator, its
/// amount commitment and the commitment-mask point, each as a 32-byte
/// x-coordinate — in that order, 128 bytes (`CT_LEAF_SIZE`).
///
/// A *name* for bytes the tree crate builds from a public output identity
/// and hashes into the layer above; this crate holds no field arithmetic.
/// The x-coordinate form is what `build_layers` consumes and cannot be
/// decompressed back to points — a path assembler keeps the output identity
/// beside it (`shekyl_curve_tree::LeafEntry`). Both stores hold leaves in
/// this shape (`SCU-Q2`); the daemon store's codec name is `tree_leaf`.
///
/// Public, non-correlating (every field is on-chain); `Debug` prints the
/// first scalar's hex prefix and the length rather than 128 bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct TreeLeaf([u8; TreeLeaf::LEN]);

impl TreeLeaf {
    /// Width of a stored leaf: four 32-byte Selene scalars.
    pub const LEN: usize = 4 * 32;

    /// Wrap the 128 stored bytes. An *edge* constructor (store decode,
    /// FFI); the tree crate builds leaves from identities, not from bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// The 128 stored bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; Self::LEN] {
        self.0
    }

    /// Borrow the 128 stored bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl fmt::Debug for TreeLeaf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TreeLeaf(")?;
        for b in &self.0[..4] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "…; {} bytes)", Self::LEN)
    }
}

impl CurveTreeRoot {
    /// The root of the **empty** curve tree — the tree state at chain height
    /// 0, before genesis drains anything: the Selene hash-initialisation
    /// point (`SELENE_HASH_INIT`, `shekyl-curve-generators`) in its
    /// compressed encoding, which is what the daemon's `get_curve_tree_root`
    /// returns for a tree with no leaves.
    ///
    /// Pinned **here**, as bytes, so a store can name the empty state
    /// (`root_at(0)`, S-CHAIN-W §3.4) without depending on the crate that
    /// computes generators. A constant pinned in one crate and defined in
    /// another is exactly the shape that drifts silently, so the equality
    /// `CurveTreeRoot::EMPTY == shekyl_fcmp::tree::selene_hash_init()` is
    /// held by a KAT in `shekyl-fcmp`'s own test suite
    /// (`tests/empty_root_kat.rs`), not by this comment.
    ///
    /// **Not** the all-zero encoding: 32 zero bytes decode to the identity
    /// point, which is *not* the empty tree's root (CEN-I12's absent-key
    /// walk, `CONSENSUS_STORE_RECONCILIATION.md` §5.4.1).
    pub const EMPTY: Self = Self::from_bytes([
        0x86, 0x81, 0x75, 0x9f, 0xee, 0x95, 0xc1, 0xc9, 0x71, 0x69, 0xb8, 0xd1, 0x47, 0x6c, 0xfa,
        0xb7, 0xda, 0x10, 0x1e, 0xde, 0xf5, 0x93, 0x2c, 0xf0, 0x30, 0x53, 0xae, 0x56, 0xf7, 0x08,
        0x1d, 0x07,
    ]);
}

hash32! {
    /// Per-output key image `I = x · H_p(O)` — the public on-chain
    /// double-spend identifier.
    ///
    /// 32-byte canonical compressed Ed25519 point encoding. `x` is the
    /// per-output spend-secret derivative and `H_p(O)` the deterministic
    /// hash-to-point of the output's one-time public key; the *computation*
    /// lives in `shekyl-crypto-pq` (`output::scan_output_recover` /
    /// `compute_key_image`), which re-exports this type. Under a well-formed
    /// spend a second transaction reusing the same output produces the same
    /// `I`, and consensus rejects it (CEN-I7 chain-wide, CEN-L1 within a
    /// block).
    ///
    /// # Type placement
    ///
    /// Moved here from `shekyl-crypto-pq` for DRS-E6 (`CHAIN_RULES_CRATE.md`
    /// §3.4): the validation crate must *name* a key image without acquiring
    /// the crypto crate's dependency graph, and two same-named newtypes in two
    /// crates are an unchecked drift source. The derivation `I = x · H_p(O)`
    /// remains transform-shaped and stays in `shekyl-crypto-pq` (rule 18);
    /// the *name* lives here because that is the consumer graph, not because
    /// the value became state-shaped.
    ///
    /// # Privacy-correlation discipline
    ///
    /// Pre-spend, a wallet's set of unspent key images is privacy-relevant:
    /// an observer who learns "these `KeyImage`s belong to wallet X" can
    /// correlate later on-chain spends to wallet X by direct byte comparison.
    /// Post-spend the value is public. The defensive posture, `redact,
    /// no_display`:
    ///
    /// - **No `Display` and no `AsRef<[u8]>`.** A `Display` is the
    ///   stringly-typed boundary (`to_string()`, `format!("{}")`); `AsRef<[u8]>`
    ///   is the bound `hex::encode` and any generic byte logger accept. The hex
    ///   form is reachable on purpose through [`KeyImage::as_bytes`], never by
    ///   accident.
    /// - **Truncated `Debug`** (`KeyImage(0000..)`): 16 bits disambiguate two
    ///   values during debugging without reproducing the identifier in a
    ///   backtrace.
    /// - **`Zeroize` without `ZeroizeOnDrop`.** Publicly derivable from
    ///   on-chain data plus the spend secret, so not itself a wipe-on-drop
    ///   concern — but containers that hold one beside genuinely secret
    ///   material (`shekyl_engine_state::TransferDetails`,
    ///   `shekyl_scanner::RecoveredWalletOutput`) wipe every field
    ///   structurally, and `Copy + Zeroize` lets them without a raw-bytes
    ///   special case at the wipe site.
    ///
    /// # Wire format
    ///
    /// `#[serde(transparent)]`: byte-identical to `[u8; 32]`, which is what
    /// keeps `TransferDetails`' on-disk and postcard-schema layouts unchanged
    /// (`schema_snapshot` tests, rule 42).
    KeyImage, redact, no_display
}

impl KeyImage {
    /// Wrap the canonical 32-byte key-image encoding.
    ///
    /// **Boundary constructor**, kept beside the family's [`KeyImage::from_bytes`]
    /// because "canonical" is a genuine predicate for a curve point and not for
    /// a hash: it is the caller's responsibility that the bytes are the
    /// canonical compressed Ed25519 encoding of `I = x · H_p(O)` produced by
    /// `shekyl-crypto-pq`'s derivation. The newtype does not re-validate the
    /// encoding — invalid bytes produce a `KeyImage` that fails downstream
    /// verification, which is the correct failure surface (consensus rejects a
    /// malformed key image at block validation, not at construction).
    #[must_use]
    pub const fn from_canonical_bytes(bytes: [u8; 32]) -> Self {
        Self::from_bytes(bytes)
    }
}

hash32! {
    /// An archival-bond persona's **canonical id** — `cSHAKE256` over the persona's
    /// canonical hybrid bond-id bytes
    /// (`shekyl_archival_retention::id::p_canonical_id_from_hybrid_pubkey`), the
    /// public identifier an on-chain bond-post carries.
    ///
    /// The 2d-1 firewall's public-by-design pseudonym handle: `P` is public by
    /// function (the firewall protects only `P`↔principal), and this id is how a
    /// bond-post, a scan match, the funding accrual, and the DQ8 retire path all
    /// name the *same* persona. A domain type, not a wire field: low-level consensus
    /// wire structs store the raw `[u8; 32]` (rule 18 byte-layout) and convert at
    /// their edge via [`PCanonicalId::as_bytes`] / [`PCanonicalId::from_bytes`].
    /// Distinct from [`TxHash`] / [`BlockHash`] so a hash of one kind can never be
    /// passed where another is expected.
    ///
    /// `Debug` is **truncated** (`redact`): the full persona id in a local log or
    /// panic backtrace would correlate the principal's machine to `P` — the exact
    /// `P`↔principal edge the firewall protects. `Display` stays full hex (it is
    /// the canonical encoding, not a log line).
    PCanonicalId, redact
}

pub mod archival;
pub use archival::{
    storage_ids_through, BadInterval, HoldingsDescriptor, HoldingsKind, HoldingsKindError,
    ShardSet, ShardSetError, MAX_ATTESTATION_WITNESS_BYTES, MAX_BOND_BAD_INTERVALS,
    MAX_CLAIMED_EPOCH_ENTRIES, MAX_CLAIM_AGE_W_EPOCHS, MAX_HOLDINGS_SHARDS, SHARD_TX_COUNT,
};

pub mod relay;
pub use relay::{NetZone, RelayCategory, RelayMethod};

scalar_u64! {
    /// **Wall-clock** seconds since the Unix epoch — a pool entry's
    /// `receive_time`, a relay clock's instant (DRS-E1 S-POOL, SPL-5).
    ///
    /// Not a [`Timestamp`]: that is a block header's field, consensus time
    /// the chain agreed on; this is one node's clock at the moment a
    /// transaction arrived or was relayed, and the two must not be
    /// subtractable from each other. The store's other time words are
    /// block time; this one is the pool's, and it never enters a rule.
    UnixSeconds
}

hash32! {
    /// The pool's FCMP++ verification-cache key — `H(proof ‖ referenceBlock
    /// ‖ key images)` (CEN-M8; `tx_pool.cpp:495`). A cached verdict is
    /// `Some(hash)`; "no cache" is `None`, never a zero hash with a bit
    /// beside it (DRS-E1 S-POOL, SPL-10).
    FcmpVerificationHash
}

mod block_axis;

impl Timestamp {
    /// Unix seconds below this are height-shaped. Invoice minting
    /// (CLI `--expiry`, wallet-RPC `create_payment_request` / `make_uri`)
    /// refuses them so a chain instant cannot be stored as a wall-clock
    /// (RTN-6). Block timestamps are not gated here.
    pub const INVOICE_UNIX_FLOOR: u64 = 1_000_000_000;

    /// Wrap Unix seconds as an invoice clock, or `None` when `secs` is
    /// below [`Self::INVOICE_UNIX_FLOOR`].
    #[must_use]
    pub const fn from_invoice_unix(secs: u64) -> Option<Self> {
        if secs < Self::INVOICE_UNIX_FLOOR {
            None
        } else {
            Some(Timestamp(secs))
        }
    }

    /// Whole seconds elapsed since an earlier instant, returning `None` if
    /// `earlier` is actually ahead of `self` (a clock that went backwards).
    #[must_use]
    pub const fn checked_secs_since(self, earlier: Timestamp) -> Option<u64> {
        self.0.checked_sub(earlier.0)
    }

    /// Advance by whole seconds, returning `None` on `u64` overflow.
    #[must_use]
    pub const fn checked_add_secs(self, secs: u64) -> Option<Timestamp> {
        match self.0.checked_add(secs) {
            Some(v) => Some(Timestamp(v)),
            None => None,
        }
    }
}

/// A per-output additional timelock — **block-height-only**.
///
/// Shekyl is block-height-only: the CryptoNote *timestamp* form of `unlock_time`
/// (a "creation cut" per `GENESIS_TX_WIRE_FORMAT.md` §9) is rejected at ingestion
/// and is **not representable here** — there is no `Time` variant, so it can never
/// be materialized from chain bytes regardless of caller. An output is locked by a
/// default timelock; an explicit one, if set, takes the later of the two.
///
/// Brought native off the vendored `shekyl-oxide` in the un-vendor slice-2 dissolve;
/// `Block` wraps [`BlockHeight`] (rule 18) rather than a bare integer. Serialization
/// is decoupled — the owning wire format encodes [`Timelock::to_unlock_raw`] as a
/// varint — so this foundational crate stays free of an io/curve dependency.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Timelock {
    /// No additional timelock. Orders before any [`Timelock::Block`].
    None,
    /// Additionally locked until this block height.
    Block(BlockHeight),
}

impl Timelock {
    /// The raw `unlock_time` value as persisted: `0` for [`Timelock::None`], else
    /// the block height.
    ///
    /// This is the forward half only. The reverse lift (raw `u64` → `Timelock`) is
    /// **not** a context-free operation: a raw value must be discriminated against the
    /// block-height/timestamp sentinel (`>= UNLOCK_TIME_BLOCK_SENTINEL` is the deleted
    /// CryptoNote timestamp form, not a block height). That discrimination is a
    /// consensus concern, so it lives with the consensus-aware consumer that owns the
    /// wire format (`shekyl-scanner`'s `timelock_from_unlock_time`), not here — keeping
    /// this foundational type free of a "treat any non-zero value as a block height"
    /// footgun.
    #[must_use]
    pub const fn to_unlock_raw(self) -> u64 {
        match self {
            Timelock::None => 0,
            Timelock::Block(h) => h.to_raw(),
        }
    }
}

impl ::zeroize::Zeroize for Timelock {
    fn zeroize(&mut self) {
        // Block heights are public chain data, not secrets; resetting to the
        // `None` default satisfies the `ZeroizeOnDrop` derive on containing wallet
        // structs without pretending to scrub a secret.
        *self = Timelock::None;
    }
}

#[cfg(test)]
mod tests;
