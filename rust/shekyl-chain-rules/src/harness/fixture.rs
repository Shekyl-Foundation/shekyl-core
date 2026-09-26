// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fixtures: well-formed values to mutate one field of.
//!
//! **"Well-formed" is a gated claim, not a label.** A fixture is built by
//! test code and never passes through a production builder, so it can be
//! illegal in ways nobody checks — and each latent illegality surfaces one
//! rule at a time, as a mid-commit surprise, when the rule that refuses it
//! lands (slice 5 commit 2: three fixtures listed coinbase-shaped bodies,
//! and CEN-H5 refused them). `fixture_sanity_tests` holds every
//! transaction shape here to `validate` / `tx_form` under **current**
//! coverage, at every slot it is meant for, so a bad fixture fails the
//! moment it is written — and the set it walks is [`TxShape`], a closed
//! enum: a new shape that the gate does not know is a **compile error**
//! (three non-exhaustive matches), not a doc line nobody re-reads. The
//! negative fixtures live with their rows and are labelled by the row they
//! refuse on.

use super::*;
use crate::verdict::TxSlot;
use shekyl_crypto_pq::output::sign_pqc_auth_for_output;
use shekyl_crypto_pq::signature::SCHEME_DOMAIN_PQC_AUTH_TX;
use shekyl_types::SigningPayloadHash;

/// The well-formed **transaction** shapes this module builds, as a
/// closed set. The sanity gate walks the chain from [`FIRST`](Self::FIRST)
/// through [`next`](Self::next) and judges each shape at every slot
/// [`valid_at`](Self::valid_at) names; adding a shape means adding a
/// variant, and the three `match`es below refuse to compile until it is
/// built, placed in the chain, and given its slots — the
/// `FormAttempt::next` arrangement, applied to fixtures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxShape {
    /// [`coinbase`].
    Coinbase,
    /// [`listed`] — the ordinary spend.
    Listed,
    /// [`serve_credit_only`].
    ServeCreditOnly,
}

impl TxShape {
    /// Where the chain starts.
    pub const FIRST: Self = Self::Coinbase;

    /// The shape after this one; `None` closes the chain. A variant
    /// left out of this chain is unreachable from `FIRST` and the gate
    /// never sees it — so a new variant is *placed*, deliberately, here.
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::Coinbase => Some(Self::Listed),
            Self::Listed => Some(Self::ServeCreditOnly),
            Self::ServeCreditOnly => None,
        }
    }

    /// A representative instance of the shape.
    pub fn build(self) -> Transaction {
        match self {
            Self::Coinbase => coinbase(1),
            Self::Listed => listed(point(9)),
            Self::ServeCreditOnly => serve_credit_only([0x77; 32]),
        }
    }

    /// The slots at which the shape is a valid transaction. The coinbase
    /// is valid at the miner slot only; every other shape at the pool's
    /// slot and listed.
    pub const fn valid_at(self) -> &'static [TxSlot] {
        match self {
            Self::Coinbase => &[TxSlot::Miner],
            Self::Listed | Self::ServeCreditOnly => &[TxSlot::Lone, TxSlot::Listed(0)],
        }
    }

    /// Every shape, walking the chain from `FIRST`.
    pub fn all() -> Vec<Self> {
        let mut shapes = Vec::new();
        let mut shape = Some(Self::FIRST);
        while let Some(current) = shape {
            shapes.push(current);
            shape = current.next();
        }
        shapes
    }
}

/// The compressed Ed25519 basepoint `G`: canonical, prime-order,
/// non-identity — an output key CEN-F9 accepts. As a **mask** it is the
/// trivial form CEN-F10 refuses (`mask = 1, amount = 0`), which is
/// what the F10 fixture uses it for.
pub const G: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

/// `2·G` compressed: a canonical prime-order point that is neither the
/// identity, nor `G`, nor `zeroCommit(0) = G` — a commitment mask CEN-F10
/// accepts for a zero-amount coinbase output. `fixture_points_are_what_
/// they_claim` (miner_tests) pins both constants through
/// `shekyl-ct-balance`.
pub const TWO_G: [u8; 32] = [
    0xc9, 0xa3, 0xf8, 0x6a, 0xae, 0x46, 0x5f, 0x0e, 0x56, 0x51, 0x38, 0x64, 0x51, 0x0f, 0x39, 0x97,
    0x56, 0x1f, 0xa2, 0xc9, 0xe8, 0x5e, 0xa2, 0x1d, 0xc2, 0x29, 0x23, 0x09, 0xf3, 0xcd, 0x60, 0x22,
];

/// Sixteen distinct canonical prime-order points — `k·G` for `k = 1..=16`,
/// so [`POINTS[0]`](Self) is [`G`] and `POINTS[1]` is [`TWO_G`] — the
/// **one** table every fixture draws its output keys, commitment masks
/// and key images from (slice 5, ruled 2026-09-23: one table, not three;
/// no 4.H rule links the three uses, and a filled byte pattern is almost
/// never a point). Ceiling **16** = the wire's `MAX_OUTPUTS`; key images
/// draw at other indices.
///
/// **The contiguity is load-bearing.** Because `POINTS[k−1] = k·G`,
/// multiples add: [`spend`]'s masks are `2·G ‥ (N+1)·G` and its one
/// pseudo-out is their sum, so CEN-H18 holds by the table's construction
/// and not by anything the rule computes. The store and the ingest call
/// that one function — a private copy is how a fixture drifted the last
/// time a point rule landed. A scalar past 16 (the sum leaves the table
/// at five outputs) is [`multiple_of_g`], which is [`point_at`] outside
/// the table and the pinned entry inside it. `fixture_points_are_what_
/// they_claim` holds `POINTS[k−1] == k·G` for every `k`, so the two
/// cannot disagree.
///
/// **Derived once, pinned, never re-derived in production code** (the
/// crate's production surface has no curve dependency; the test surface
/// has `curve25519-dalek`). The gate asserts what a fixture needs —
/// every entry a canonical prime-order point (`shekyl-ct-balance`),
/// pairwise distinct, entries 0 and 1 the named constants — and the
/// multiplicity above. Provenance for the record: the values were first
/// produced by RFC 8032 arithmetic over `2^255 − 19`,
/// `d = −121665/121666`, `G = (x(4/5), 4/5)`, repeated affine addition,
/// compressed as `y ‖ sign(x) << 7` little-endian — thirty lines of
/// Python with no dependencies, which reproduced `G` and `TWO_G` before
/// the other fourteen were taken; the gate now says the same.
pub const POINTS: [[u8; 32]; 16] = [
    G,
    TWO_G,
    hex32(*b"d4b4f5784868c3020403246717ec169ff79e26608ea126a1ab69ee77d1b16712"),
    hex32(*b"2f1132ca61ab38dff00f2fea3228f24c6c71d58085b80e47e19515cb27e8d047"),
    hex32(*b"edc876d6831fd2105d0b4389ca2e283166469289146e2ce06faefe98b22548df"),
    hex32(*b"f47e49f9d07ad2c1606b4d94067c41f9777d4ffda709b71da1d88628fce34d85"),
    hex32(*b"b862409fb5c4c4123df2abf7462b88f041ad36dd6864ce872fd5472be363c5b1"),
    hex32(*b"b4b937fca95b2f1e93e41e62fc3c78818ff38a66096fad6e7973e5c90006d321"),
    hex32(*b"c0f1225584444ec730446e231390781ffdd2f256e9fcbeb2f40dddc2c2233d7f"),
    hex32(*b"2c7be86ab07488ba43e8e03d85a67625cfbf98c8544de4c877241b7aaafc7fe3"),
    hex32(*b"1337036ac32d8f30d4589c3c1c595812ce0fff40e37c6f5a97ab213f318290ad"),
    hex32(*b"f9e42d2edc81d23367967352b47e4856b82578634e6c1de72280ce8b60ce70c0"),
    hex32(*b"801f40eaaee1ef8723279a28b2cf4037b889dad222604678748b53ed0db0db92"),
    hex32(*b"39289c8998fd69835c26b619e89848a7bf02b7cb7ad1ba1581cbc4506f2550ce"),
    hex32(*b"df5c2eadc44c6d94a19a9aa118afe5ac3193d26401f76251f522ff042dfbcb92"),
    hex32(*b"eb2767c137ab7ad8279c078eff116ab0786ead3a2e0f989f72c37f82f2969670"),
];

/// The `k`-th point of [`POINTS`], `k` from 1: a distinct canonical
/// point for the `k`-th output, mask or key image of a fixture. Panics
/// past the ceiling — a fixture wanting more than sixteen distinct
/// points from the *pinned* table wants more than the wire allows
/// outputs; a fixture that needs an unbounded supply (a key image per
/// block over a long chain) uses [`point_at`].
pub const fn point(k: usize) -> [u8; 32] {
    POINTS[k - 1]
}

/// `k·G`, compressed, for any `k ≥ 1` — the **computed** form of
/// [`POINTS`], for fixtures whose need is unbounded: the ingest's
/// seed-epoch chains spend a fresh key image per block for two thousand
/// blocks, which no pinned table should grow to. Same derivation home
/// as the table (the harness derives; production only verifies), and
/// `fixture_points_are_what_they_claim` holds `point_at(k) == point(k)`
/// for the pinned sixteen. Panics on `0`: `0·G` is the identity, which
/// no rule accepts anywhere and no fixture should be able to ask for by
/// accident.
pub fn point_at(k: u64) -> [u8; 32] {
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;
    assert!(k >= 1, "0·G is the identity; a fixture never wants it");
    (ED25519_BASEPOINT_POINT * Scalar::from(k))
        .compress()
        .to_bytes()
}

/// `k·G` for `k ≥ 1`, from the pinned table when `k` is in range and
/// from [`point_at`] past it. [`spend`]'s pseudo-out scalar is the sum
/// of its mask scalars, which exceeds [`POINTS`]'s ceiling before the
/// wire's output cap does; callers that already know `k` is in
/// `1..=16` keep using [`point`].
pub fn multiple_of_g(k: u64) -> [u8; 32] {
    if let Ok(index) = usize::try_from(k) {
        if (1..=POINTS.len()).contains(&index) {
            return point(index);
        }
    }
    point_at(k)
}

/// Masks start at `2·G`. `1·G` is `zeroCommit(0)`, and CEN-H17 refuses it.
const FIRST_MASK_SCALAR: u64 = 2;

/// Sum of the mask scalars `FIRST_MASK_SCALAR ..= FIRST_MASK_SCALAR + N - 1`.
/// Zero when there are no outputs, so a zero-output spend asks for no point.
///
/// `Σ = N · (first + last) / 2`. One of `N` and `(first + last)` is even,
/// so the division is exact; which one is divided first is what keeps the
/// product inside `u64`.
fn mask_scalar_sum(outputs: usize) -> u64 {
    let n = u64::try_from(outputs).expect("an output count fits in u64");
    if n == 0 {
        return 0;
    }
    let last = FIRST_MASK_SCALAR + n - 1;
    let pair = FIRST_MASK_SCALAR + last;
    if n % 2 == 0 {
        (n / 2).checked_mul(pair).expect("mask scalar sum fits")
    } else {
        n.checked_mul(pair / 2).expect("mask scalar sum fits")
    }
}

/// Thirty-two bytes from sixty-four lowercase hex digits, at compile
/// time — so the table above reads as the deriver printed it.
const fn hex32(hex: [u8; 64]) -> [u8; 32] {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("hex digit"),
        }
    }
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]);
        i += 1;
    }
    out
}

/// The `extra` CEN-I19 requires of a transaction with `n_outputs`
/// outputs: one `0x06` KEM-ciphertext field of `1120·n` bytes and one
/// `0x07` leaf-entry field of `64·n` conforming entries — empty when
/// `n == 0`. The KEM bytes are filler (no rule reads their content; the
/// leaf entries' leading points are what `PL-D3` checks, and
/// [`conforming_pqc_leaf_blob`] supplies canonical ones). Slice 6
/// commit 3 landed I19 and every fixture with outputs grew this field.
pub fn pqc_extra(n_outputs: usize) -> Vec<u8> {
    if n_outputs == 0 {
        return Vec::new();
    }
    tx_extra::serialize(&[
        TxExtraField::PqcKemCiphertext(vec![0x5A; HYBRID_KEM_CT_BYTES * n_outputs]),
        TxExtraField::PqcLeafEntries(conforming_pqc_leaf_blob(n_outputs)),
    ])
    .expect("two capped fields serialize")
}

/// The coinbase `extra` in CEN-I20's one layout for `n_outputs` outputs:
/// `[0x01 pubkey, 0x02 nonce(8), 0x06, 0x07]`, built by the grammar's
/// own constructor so the fixture cannot drift from the rule. The
/// pubkey is `G` and the nonce zero: no rule reads either's value.
pub fn coinbase_extra(n_outputs: usize) -> Vec<u8> {
    let kem = vec![0x5A; HYBRID_KEM_CT_BYTES * n_outputs];
    let leaf = conforming_pqc_leaf_blob(n_outputs);
    tx_extra::build_coinbase_extra(G, &[0; COINBASE_NONCE_BYTES], n_outputs, &kem, &leaf)
        .expect("the grammar's one layout builds")
}

/// A coinbase that satisfies every structural 4.F row for a block at
/// `height`: one `Input::Gen(height)` (F1, F5), `Ct::Null` (F3), one
/// output (F4) paying `0` with key `G` (F9) and mask `2·G` (F10),
/// `unlock_time = height + mined_money_unlock_window` (F6), and the
/// grammar's `extra` for one output (I19, I20). Amounts are
/// not this fixture's concern — the exact-payout row (F18) is not
/// landed — so a chain of these pays nothing and reads the tail subsidy
/// at every height.
///
/// The F6 claim holds at every height a chain can reach. Within the
/// window of `u64::MAX` no coinbase satisfies F6 — the rule's own sum
/// overflows and it refuses (`rules::miner::F6`) — so the fixture
/// saturates rather than panics there: the corpus tests build records
/// at `u64::MAX` to exercise height exhaustion in the *store*, and need
/// the bytes, not a verdict.
pub fn coinbase(height: u64) -> Transaction {
    let unlock_time = height.saturating_add(RuleSet::GENESIS.mined_money_unlock_window().to_raw());
    Transaction {
        prefix: TxPrefix {
            unlock_time,
            inputs: vec![Input::Gen(height)],
            outputs: vec![Output {
                amount: 0,
                key: G,
                view_tag: 1,
            }],
            extra: coinbase_extra(1),
        },
        ct: Ct::Null(CtBase {
            enc_amounts: vec![[0x55; 9]],
            enc_labels: vec![[0x66; 9]],
            commitments: vec![TWO_G],
        }),
    }
}

/// A spend of `key_image` with `outputs` zero-amount outputs, shaped to
/// pass every structural 4.H row that has landed.
///
/// One `ToKey` input with empty offsets. Output `k` (from 1) is keyed
/// `k·G`; its mask is `(k+1)·G`, so the masks are `2·G ‥ (N+1)·G` and
/// `G` — `zeroCommit(0)`, which CEN-H17 refuses — is never a mask. Fee
/// is zero and the one pseudo-out is the sum of those scalars, which is
/// CEN-H18 by construction of [`multiple_of_g`]. The committed base is
/// sized to the outputs (H8). A prunable region is present exactly when
/// there are outputs, and its one BP+ has the canonical layout for that
/// count (H19's layout half). One [`pqc_auth_filler`] per input, so the
/// txid is 4-part. The proof bytes are filler: H19's verification and
/// the 4.I membership rows are not landed, and when they land this
/// fixture is theirs to refuse. [`listed`] is the two-output case —
/// the fewest CEN-I1 admits (slice 6 commit 2); `spend(ki, 1)` is I1's
/// own negative fixture.
pub fn spend(key_image: [u8; 32], outputs: usize) -> Transaction {
    let n = u64::try_from(outputs).expect("an output count fits in u64");
    let prunable = (outputs > 0).then(|| Prunable {
        bulletproofs: vec![bp_plus_layout_for(outputs)],
        tree_depth: 0,
        fcmp_proof: vec![0xF0],
        pseudo_outs: vec![multiple_of_g(mask_scalar_sum(outputs))],
        serve_credit_pruned: Vec::new(),
    });
    Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs: vec![Input::ToKey {
                amount: 0,
                key_offsets: Vec::new(),
                key_image,
            }],
            outputs: (1..=n)
                .map(|k| Output {
                    amount: 0,
                    key: multiple_of_g(k),
                    view_tag: 2,
                })
                .collect(),
            extra: pqc_extra(outputs),
        },
        ct: Ct::Fcmp {
            fee: 0,
            reference_block: UNRECORDED_REFERENCE,
            base: CtBase {
                enc_amounts: vec![[0x11; 9]; outputs],
                enc_labels: vec![[0x22; 9]; outputs],
                commitments: (0..n)
                    .map(|i| multiple_of_g(FIRST_MASK_SCALAR + i))
                    .collect(),
            },
            pqc_auths: vec![pqc_auth_filler()],
            prunable,
        },
    }
}

/// [`spend`] with **two** outputs — the fewest CEN-I1 admits of a
/// non-serve-credit transaction (slice 6 commit 2; one output until
/// then, which every 4.H row accepted and I1 refuses). The shape most
/// call sites mean by "a listed transaction".
pub fn listed(key_image: [u8; 32]) -> Transaction {
    spend(key_image, 2)
}

/// The reference block no chain holds — what [`spend`] carries until a
/// chain anchors it ([`referencing`]): CEN-I10's own negative fixture.
pub const UNRECORDED_REFERENCE: BlockHash = BlockHash::from_bytes([0x99; 32]);

/// `tx` with its `Fcmp` `reference_block` set to `reference` — the one
/// place a fixture's anchor is written, so every crate that lists a
/// spend on a chain anchors it the same way. A `Null` ct has no
/// reference and is returned unchanged.
#[must_use]
pub fn referencing(mut tx: Transaction, reference: BlockHash) -> Transaction {
    if let Ct::Fcmp {
        reference_block, ..
    } = &mut tx.ct
    {
        *reference_block = reference;
    }
    tx
}

/// The newest reference CEN-I11 admits for a spend listed in the block
/// that connects at `connecting`: the block `REFERENCE_BLOCK_MIN_AGE`
/// below it (`ref_height ≤ chain_height − MIN_AGE`, `blockchain.cpp:4121`,
/// with `chain_height` the connecting height). `None` when the chain is
/// too young to carry a spend at all — the first block that can list
/// one is height `MIN_AGE`, referencing genesis.
#[must_use]
pub fn newest_admissible_reference(connecting: BlockHeight) -> Option<BlockHeight> {
    connecting.checked_sub_count(crate::rules::tx_against::REFERENCE_BLOCK_MIN_AGE)
}

/// Whether a row reads `tx`'s `referenceBlock` as a chain fact.
///
/// CEN-I10/I11 read it on a regular spend (a [`Input::ToKey`]). CEN-J21,
/// in flight, reads it on an emission even when that emission has no fee
/// input: the reference is the membership anchor of the emission vin.
/// A serve-credit's [`Ct::Fcmp`] carries the field and no row reads it, so
/// the decision is not "any `Fcmp`" — that would put the spend window on a
/// shape that may be listed at any height. A coinbase is [`Ct::Null`] and
/// has no reference.
fn judges_a_reference(tx: &Transaction) -> bool {
    tx.prefix.inputs.iter().any(|input| {
        matches!(
            input,
            Input::ToKey { .. } | Input::ArchivalRewardEmission { .. }
        )
    })
}

/// `tx` anchored for a block connecting at `height` on a chain whose
/// block hashes so far are `hashes`: its reference is the block at
/// [`newest_admissible_reference`]. The one anchoring body for every
/// crate's chain builder — the store's `connect_chain`, the ingest's
/// `chain_listing` — so no fixture anchors a reference differently from
/// the crate that judges it. A serve credit or a coinbase — shapes whose
/// reference no row reads — is returned unchanged and may be listed at
/// any height. Panics when a judged reference is listed on a chain too
/// young to hold one: the fixture asked for a shape CEN-I11 refuses.
#[must_use]
pub fn anchored_at(hashes: &[BlockHash], height: u64, tx: Transaction) -> Transaction {
    if !judges_a_reference(&tx) {
        return tx;
    }
    let at = newest_admissible_reference(BlockHeight::from_raw(height)).unwrap_or_else(|| {
        panic!(
            "a reference needs {} blocks beneath it (CEN-I11); height {height} has fewer",
            crate::rules::tx_against::REFERENCE_BLOCK_MIN_AGE
        )
    });
    let reference = hashes
        .get(usize::try_from(at.to_raw()).expect("a fixture height fits usize"))
        .unwrap_or_else(|| panic!("the chain holds no block at {at} to reference"));
    // Signed after anchoring: the reference is in the pruned segment every
    // signature binds (I17), so a signature made before it moved would not
    // verify.
    signed(referencing(tx, *reference))
}

/// Every `pqc_auths` slot of `tx` **signed** — by a hybrid key derived
/// deterministically from its input, over the §1.1 signing hash of this
/// body — so a fixture anchored here verifies under CEN-I18 as a wallet's
/// spend would, and the fixture substrate does not collapse the moment the
/// signature row lands (§1.2's cascade, met at one site). Two passes,
/// because the message binds every input's public key (I17): the keys are
/// derived first, the signatures made second. A body with no preimage
/// (no `pqc_auths`, or no prunable region) is returned unchanged.
///
/// This is the wallet's arrangement (`shekyl-tx-builder`'s
/// `phase1_payload_hashes` then `sign_pqc_auths`) with a fixture key in
/// place of the output's HKDF secret; the signer is the production one
/// ([`sign_pqc_auth_for_output`]), so what verifies here is what verifies
/// on chain. What it does **not** make real is the proof — `fcmp_proof`
/// stays [`bp_plus_layout_for`]'s kind of filler, because a membership
/// proof needs the tree it is a member of; that is the captured chains'
/// business (§5 row 1) and CEN-I15's witness.
#[must_use]
pub fn signed(mut tx: Transaction) -> Transaction {
    let Some(count) = fcmp_auths(&tx).map(Vec::len) else {
        return tx;
    };
    if count == 0 {
        return tx;
    }
    let seeds: Vec<[u8; 64]> = tx
        .prefix
        .inputs
        .iter()
        .enumerate()
        .map(|(index, input)| fixture_signing_seed(index, input))
        .collect();
    // Pass 1 — the public keys, which the message binds.
    for (auth, seed) in fcmp_auths_mut(&mut tx).into_iter().flatten().zip(&seeds) {
        let derived = sign_pqc_auth_for_output(seed, 0, SCHEME_DOMAIN_PQC_AUTH_TX, &[0u8; 32])
            .expect("a fixture seed derives a hybrid keypair");
        auth.auth_version = 1;
        auth.scheme_id = shekyl_crypto_pq::signature::HYBRID_SCHEME_ID_ED25519_ML_DSA_65;
        auth.flags = 0;
        auth.hybrid_public_key = derived.hybrid_public_key;
    }
    // Pass 2 — the signatures, over the hashes those keys are part of.
    let hashes = tx.pqc_signing_payload_hashes();
    if hashes.len() != count {
        // No prunable region (the storage-pruned form): nothing to sign over.
        return tx;
    }
    for ((auth, seed), hash) in fcmp_auths_mut(&mut tx)
        .into_iter()
        .flatten()
        .zip(&seeds)
        .zip(&hashes)
    {
        auth.hybrid_signature = fixture_signature(seed, hash);
    }
    tx
}

/// The signature a fixture seed makes over `hash` — **memoized**, because
/// the production signer is hedged (ML-DSA-65 draws randomness on every
/// sign) and a fixture must be a pure function of what built it: tests
/// rebuild a body and expect the bytes the store already holds, and a
/// block's hash is over those bytes. The key `(seed, hash)` is everything
/// the signature's validity depends on, since the hash binds the whole
/// body (I17); process-wide, so parallel test threads agree. This is why
/// determinism lives here and not as a deterministic-signing entry point
/// on the scheme: the crypto surface should not offer production code a
/// way to sign without randomness.
fn fixture_signature(seed: &[u8; 64], hash: &SigningPayloadHash) -> Vec<u8> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    /// `(seed, signed hash)` → the canonical signature bytes.
    type Signatures = HashMap<([u8; 64], [u8; 32]), Vec<u8>>;
    static SIGNATURES: OnceLock<Mutex<Signatures>> = OnceLock::new();
    let cache = SIGNATURES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache
        .lock()
        .expect("the fixture signature cache is not poisoned");
    cache
        .entry((*seed, hash.to_bytes()))
        .or_insert_with(|| {
            sign_pqc_auth_for_output(seed, 0, SCHEME_DOMAIN_PQC_AUTH_TX, hash.as_bytes())
                .expect("a fixture seed signs")
                .signature
        })
        .clone()
}

/// The 64-byte "combined shared secret" a fixture input's signing key is
/// derived from: the key image doubled for a `ToKey`, so the same spend
/// always signs with the same key and two spends never share one; a
/// constant per position for the archival arms.
fn fixture_signing_seed(index: usize, input: &Input) -> [u8; 64] {
    let mut seed = [0u8; 64];
    match input {
        Input::ToKey { key_image, .. } => {
            seed[..32].copy_from_slice(key_image);
            seed[32..].copy_from_slice(key_image);
        }
        _ => seed.fill(0xE0 ^ u8::try_from(index).expect("a fixture has few inputs")),
    }
    seed
}

fn fcmp_auths(tx: &Transaction) -> Option<&Vec<PqcAuth>> {
    match &tx.ct {
        Ct::Fcmp { pqc_auths, .. } => Some(pqc_auths),
        Ct::Null(_) => None,
    }
}

fn fcmp_auths_mut(tx: &mut Transaction) -> Option<&mut Vec<PqcAuth>> {
    match &mut tx.ct {
        Ct::Fcmp { pqc_auths, .. } => Some(pqc_auths),
        Ct::Null(_) => None,
    }
}

/// `tx` anchored on `chain` for the block that connects next
/// ([`anchored_at`] over the mock's recorded hashes).
#[must_use]
pub fn anchored_on(chain: &MockChain, tx: Transaction) -> Transaction {
    let connecting = Tip::connecting_height(chain.tip().as_ref());
    let hashes: Vec<BlockHash> = chain.recorded.iter().map(|block| block.hash).collect();
    anchored_at(&hashes, connecting.to_raw(), tx)
}

/// [`listed`], [`anchored_on`] `chain` — what a test that lists a spend
/// on a chain means by one.
#[must_use]
pub fn listed_on(chain: &MockChain, key_image: [u8; 32]) -> Transaction {
    anchored_on(chain, listed(key_image))
}

/// The youngest chain on which a listed spend is admissible: `MIN_AGE`
/// blocks, so the next block connects at height `MIN_AGE` and a spend
/// it lists references genesis ([`anchored_on`]). The chain every
/// fixture that is *about a spend* and not about the chain builds on.
#[must_use]
pub fn spendable_chain() -> MockChain {
    chain_of(crate::rules::tx_against::REFERENCE_BLOCK_MIN_AGE.to_raw())
}

/// A chain of `len` coinbase-only blocks with distinct identities
/// (timestamps a target block time apart, all below the harness clock)
/// and the genesis constant of work per block — long enough for a
/// spend to reference when `len ≥ MIN_AGE`, and with enough work that
/// D4's window, once it opens, derives a real target rather than the
/// zero a work-less chain yields (moved here from `pow_tests`, slice 6
/// commit 5).
#[must_use]
pub fn chain_of(len: u64) -> MockChain {
    (0..len).fold(MockChain::default(), |chain, h| {
        chain.push(
            recorded_with_work(
                1_000 + h * 120,
                CumulativeDifficulty::from_raw(u128::from(h + 1) * GENESIS_DIFFICULTY),
            ),
            root(u8::try_from(h % 250).expect("fits") + 1),
        )
    })
}

/// A per-input PQC authentication in **CEN-I16's shape** — version 1,
/// solo scheme, no flags, a key blob of exactly
/// [`PQC_HYBRID_SINGLE_KEY_LEN`] — with filler bytes in the blobs:
/// what the wire needs to round-trip a non-serve-credit `Fcmp`
/// transaction (`pqc_auths.len() == nvin`), what I16's structure
/// admits, and nothing CEN-I18 would accept. The **unanchored** slot:
/// every body that reaches `tx_against` goes through [`anchored_at`],
/// which replaces this with a real key and a real signature
/// ([`signed`]); a body judged by `tx_form` alone keeps the filler, as
/// no stateless row reads the blobs. The blobs were empty until slice 6
/// commit 2 landed I16.
pub fn pqc_auth_filler() -> PqcAuth {
    PqcAuth {
        auth_version: 1,
        scheme_id: 1,
        flags: 0,
        hybrid_public_key: vec![0x5A; PQC_HYBRID_SINGLE_KEY_LEN],
        hybrid_signature: Vec::new(),
    }
}

/// A BP+ with the **canonical layout** for `outputs` outputs — `|L| = |R|
/// = 6 + ⌈log₂ outputs⌉` (CEN-H19's layout half) — and filler scalars.
/// It proves nothing; it is the shape the layout rule accepts, for
/// fixtures whose subject is not the proof.
pub fn bp_plus_layout_for(outputs: usize) -> BpPlus {
    let rounds = 6 + outputs.next_power_of_two().trailing_zeros() as usize;
    BpPlus {
        a: [0xA0; 32],
        a1: [0xA1; 32],
        b: [0xB0; 32],
        r1: [0xC1; 32],
        s1: [0xD1; 32],
        d1: [0xE1; 32],
        l: vec![[0x1F; 32]; rounds],
        r: vec![[0x2F; 32]; rounds],
    }
}

/// A **serve-credit-only** transaction (CEN-H20's shape: serve-credit
/// inputs and nothing else, no outputs, zero fee, no spend material),
/// carrying `record` as its one pass record. The one legal non-coinbase
/// shape with **no key image** — what a test needs when it must list the
/// same body twice (SI-3) without tripping the spent-key-image set. The
/// record's bytes are the wire's minimum (tag byte, then payload); the
/// serving-credit rules that read them are 4.J's, not this crate's yet.
pub fn serve_credit_only(record: [u8; 32]) -> Transaction {
    let mut canonical_bytes = vec![shekyl_wire::transaction::TAG_INPUT_SERVE_CREDIT];
    canonical_bytes.extend_from_slice(&record);
    Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs: vec![Input::ServeCredit { canonical_bytes }],
            outputs: Vec::new(),
            extra: Vec::new(),
        },
        ct: Ct::Fcmp {
            fee: 0,
            reference_block: UNRECORDED_REFERENCE,
            base: CtBase {
                enc_amounts: Vec::new(),
                enc_labels: Vec::new(),
                commitments: Vec::new(),
            },
            pqc_auths: Vec::new(),
            prunable: None,
        },
    }
}

/// A header with every field set to a recognisable non-zero value —
/// the shape of a *recorded* block. A candidate takes its `previous` and
/// `curve_tree_root` from the chain it is built on ([`candidate_on`]).
pub fn header() -> BlockHeader {
    BlockHeader {
        major_version: 1,
        minor_version: 0,
        timestamp: 1_700_000_000,
        previous: BlockHash::from_bytes([0x11; 32]),
        nonce: 7,
        curve_tree_root: CurveTreeRoot::from_bytes([0x22; 32]),
        attestation_root: AttestationRoot::from_bytes([0x33; 32]),
    }
}

/// A well-formed candidate **on `chain`'s tip**: `previous` is the tip's
/// hash (the null hash on an empty chain — CEN-A2) and `curve_tree_root`
/// is the tree state at the connecting height (`root_at(tip + 1)`; the
/// empty tree at genesis — CEN-B5); the header lists exactly the bodies
/// it carries. Mutate one field to build a negative fixture.
pub fn candidate_on(chain: &MockChain, listed: Vec<Transaction>) -> Candidate {
    let tip = chain.tip();
    let connecting = Tip::connecting_height(tip.as_ref());
    let root = match chain.root(connecting) {
        AtHeight::Recorded(root) => root,
        AtHeight::AboveTip => unreachable!("the mock records the root at tip + 1"),
    };
    let block = Block {
        header: BlockHeader {
            previous: tip.map_or(BlockHash::NULL, |t| t.hash),
            curve_tree_root: root,
            ..header()
        },
        miner_transaction: coinbase(connecting.to_raw()),
        transaction_hashes: listed.iter().map(Transaction::hash).collect(),
    };
    Candidate::new(block, listed)
}

/// A well-formed **genesis** candidate: [`candidate_on`] an empty chain.
pub fn candidate(listed: Vec<Transaction>) -> Candidate {
    candidate_on(&MockChain::default(), listed)
}

/// A recorded block whose header carries `timestamp`, identity derived,
/// with **no work recorded** (`cumulative_difficulty` zero). Enough for
/// every fixture that is not about difficulty — a chain shorter than
/// the LWMA-1 window never reads the field — and a chain that *is*
/// about it builds its series with [`recorded_with_work`].
pub fn recorded(timestamp: u64) -> RecordedBlock {
    recorded_with_work(timestamp, CumulativeDifficulty::ZERO)
}

/// A recorded block with `timestamp` and `cumulative_difficulty` both
/// chosen — the LWMA-1 fixtures' shape.
pub fn recorded_with_work(
    timestamp: u64,
    cumulative_difficulty: CumulativeDifficulty,
) -> RecordedBlock {
    let block = Block {
        header: BlockHeader {
            timestamp,
            ..header()
        },
        // Recorded blocks are never judged, so the coinbase's height
        // claim does not matter; `0` keeps the identity a pure
        // function of `timestamp`.
        miner_transaction: coinbase(0),
        transaction_hashes: Vec::new(),
    };
    RecordedBlock {
        hash: block.hash(),
        header: block.header,
        cumulative_difficulty,
        // No emission recorded and no listed transactions: a chain
        // whose fixtures are not about the coinbase reads the tail
        // subsidy at every height and a zero volume window. A fixture
        // that is about them sets both (`recorded_with_emission`).
        coins_generated: AtomicUnits::ZERO,
        cumulative_tx_count: 0,
    }
}

/// A curve-tree root filled with `byte`.
#[must_use]
pub const fn root(byte: u8) -> CurveTreeRoot {
    CurveTreeRoot::from_bytes([byte; 32])
}

#[cfg(test)]
mod anchor_tests {
    use super::*;

    /// CEN-J21's shape: an emission with no fee input still carries a
    /// reference the row will read. A serve credit carries the field and
    /// no row reads it, including at height 0.
    #[test]
    fn an_emission_with_no_fee_input_is_anchored_and_a_serve_credit_is_not() {
        let chain = chain_of(crate::rules::tx_against::REFERENCE_BLOCK_MIN_AGE.to_raw());
        let hashes: Vec<BlockHash> = chain.recorded.iter().map(|block| block.hash).collect();
        let height = crate::rules::tx_against::REFERENCE_BLOCK_MIN_AGE.to_raw();

        let mut emission = listed([0x11; 32]);
        emission.prefix.inputs = vec![Input::ArchivalRewardEmission {
            canonical_bytes: vec![0x04, 0],
        }];
        let anchored = anchored_at(&hashes, height, emission);
        let Ct::Fcmp {
            reference_block, ..
        } = anchored.ct
        else {
            panic!("an emission carries a reference");
        };
        assert_eq!(
            reference_block, hashes[0],
            "the newest admissible reference is genesis"
        );

        let credit = serve_credit_only([0x77; 32]);
        let left = anchored_at(&hashes, 0, credit.clone());
        assert_eq!(
            left.ct, credit.ct,
            "a serve credit is not put in the spend window"
        );
    }
}
