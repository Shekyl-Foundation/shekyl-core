// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The negative-fixture harness: a mock chain, a branded mock view, a view
//! whose every read faults, and the two assertions every rule test is
//! written with (`CHAIN_RULES_CRATE.md` §8.7).
//!
//! Test-only (`#[cfg(test)]` at the declaration). Rules are generic over
//! `ChainView<'id>`, so a rule is exercised here against a [`MockChain`](crate::harness::MockChain) of
//! a few recorded blocks with no database — the capability the C++ never
//! had (C2-R8 §9.1). A harness with no subject is a vacuous pass; the probe
//! in `harness_probe_tests.rs` is the subject that keeps this one honest.

use core::convert::Infallible;
use core::fmt::Debug;
use core::marker::PhantomData;
use std::collections::BTreeSet;

use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{
    AttestationRoot, BlockHash, BlockHeight, CurveTreeRoot, KeyImage, PowHash, Timestamp,
};
use shekyl_units::AtomicUnits;
use shekyl_wire::{
    Block, BlockHeader, BpPlus, Ct, CtBase, Input, Output, PqcAuth, Prunable, Transaction, TxPrefix,
};

use crate::block::{Candidate, StructurallyValid};
use crate::census::CenRow;
use crate::fault::{Fault, FormAttempt};
use crate::rule_set::RuleSet;
use crate::substrate::Substrate;
use crate::validate::form;
use crate::verdict::{InvalidBlock, Locus, Verdict};
use crate::view::{AtHeight, ChainView, RecordedBlock, Tip};

/// Invariant brand, as in `verdict.rs`.
type Brand<'id> = PhantomData<fn(&'id ()) -> &'id ()>;

/// A recorded chain in memory.
///
/// Blocks and roots are **dense by construction**: [`push`](Self::push)
/// appends at `tip + 1`, so — like the store — the only absence the view can
/// report is above the tip. Key images are a set.
///
/// Roots are keyed the way the store keys them (S-CHAIN-W SCW-19):
/// `root_at(h)` is the tree state **at** `h` — after block `h − 1` connected,
/// before block `h` drained — so `roots[0]` is the empty tree, the root
/// pushed *with* block `h` is `roots[h + 1]`, and `root_at(tip + 1)` is
/// recorded (the state the next candidate is checked against, CEN-B5) while
/// `root_at(tip + 2)` is `AboveTip`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MockChain {
    recorded: Vec<RecordedBlock>,
    /// `roots[h]` = the tree state at height `h`; `roots.len() == recorded.len() + 1`.
    roots: Vec<CurveTreeRoot>,
    key_images: BTreeSet<KeyImage>,
}

impl Default for MockChain {
    fn default() -> Self {
        Self {
            recorded: Vec::new(),
            roots: vec![CurveTreeRoot::EMPTY],
            key_images: BTreeSet::new(),
        }
    }
}

impl MockChain {
    /// Append a block at `tip + 1` and the tree state **after** it — what
    /// `root_at(tip + 2)` will return, and what the header of the block
    /// after it must carry (CEN-B5).
    pub fn push(mut self, block: RecordedBlock, root_after: CurveTreeRoot) -> Self {
        self.recorded.push(block);
        self.roots.push(root_after);
        self
    }

    /// Record a spent key image.
    pub fn with_key_image(mut self, key_image: KeyImage) -> Self {
        self.key_images.insert(key_image);
        self
    }

    /// The last recorded block — height and identity — if any.
    #[must_use]
    pub fn tip(&self) -> Option<Tip> {
        let len = u64::try_from(self.recorded.len()).expect("a Vec fits in u64");
        let height = BlockHeight::from_raw(len.checked_sub(1)?);
        let block = self.recorded.last()?;
        Some(Tip {
            height,
            hash: block.hash,
        })
    }

    /// Project a branded view and run `f` against it.
    ///
    /// `'id` is fresh per call — `f` must accept *any* brand, so no caller
    /// can name it, and two calls yield two brands. The mock's analogue of
    /// the store's `write`: a `ChainValid<'id, MockView<'_, 'id>>` minted
    /// inside one call is not a `ChainValid` of any other.
    pub fn with_view<R>(&self, f: impl for<'id> FnOnce(MockView<'_, 'id>) -> R) -> R {
        f(MockView {
            chain: self,
            _brand: PhantomData,
        })
    }

    fn block(&self, height: BlockHeight) -> AtHeight<&RecordedBlock> {
        usize::try_from(height.to_raw())
            .ok()
            .and_then(|index| self.recorded.get(index))
            .map_or(AtHeight::AboveTip, AtHeight::Recorded)
    }

    fn root(&self, height: BlockHeight) -> AtHeight<CurveTreeRoot> {
        usize::try_from(height.to_raw())
            .ok()
            .and_then(|index| self.roots.get(index))
            .map_or(AtHeight::AboveTip, |root| AtHeight::Recorded(*root))
    }
}

/// A `ChainView<'id>` over a [`MockChain`]. Never faults.
pub struct MockView<'a, 'id> {
    chain: &'a MockChain,
    _brand: Brand<'id>,
}

impl<'id> ChainView<'id> for MockView<'_, 'id> {
    type Fault = Infallible;

    fn has_key_image(&self, key_image: &KeyImage) -> Result<bool, Infallible> {
        Ok(self.chain.key_images.contains(key_image))
    }

    fn block_at(&self, height: BlockHeight) -> Result<AtHeight<RecordedBlock>, Infallible> {
        Ok(match self.chain.block(height) {
            AtHeight::Recorded(block) => AtHeight::Recorded(block.clone()),
            AtHeight::AboveTip => AtHeight::AboveTip,
        })
    }

    fn root_at(&self, height: BlockHeight) -> Result<AtHeight<CurveTreeRoot>, Infallible> {
        Ok(self.chain.root(height))
    }

    fn tip(&self) -> Result<Option<Tip>, Infallible> {
        Ok(self.chain.tip())
    }
}

/// The fault a [`FaultingView`] raises.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Faulted;

/// A view whose every read faults — the substrate failing under the rule.
#[derive(Default)]
pub struct FaultingView<'id>(Brand<'id>);

impl<'id> ChainView<'id> for FaultingView<'id> {
    type Fault = Faulted;

    fn has_key_image(&self, _: &KeyImage) -> Result<bool, Faulted> {
        Err(Faulted)
    }

    fn block_at(&self, _: BlockHeight) -> Result<AtHeight<RecordedBlock>, Faulted> {
        Err(Faulted)
    }

    fn root_at(&self, _: BlockHeight) -> Result<AtHeight<CurveTreeRoot>, Faulted> {
        Err(Faulted)
    }

    fn tip(&self) -> Result<Option<Tip>, Faulted> {
        Err(Faulted)
    }
}

/// The environment a fixture is judged in: a fixed clock and a longhash
/// function the test chooses.
///
/// The default longhash is the **all-zero** hash — `0 · d < 2^256` for
/// every target, so PoW passes at any difficulty and a fixture that is not
/// about PoW never trips on it. A PoW fixture swaps in a closure that
/// returns what it needs; a fault fixture swaps in one that returns
/// [`Faulted`].
#[derive(Clone, Copy)]
pub struct MockSubstrate {
    /// What `local_clock` returns.
    pub clock: Timestamp,
    /// What `longhash` returns, given the preimage and the seed.
    pub longhash: fn(&[u8], &BlockHash) -> Result<PowHash, Faulted>,
}

impl MockSubstrate {
    /// A clock comfortably after every fixture header's timestamp
    /// ([`fixture::header`] is `1_700_000_000`), so CEN-C1 passes unless a
    /// test moves one or the other.
    pub const CLOCK: Timestamp = Timestamp::from_raw(1_700_000_100);

    /// The longhash that satisfies every target. The `Result` is the fn
    /// pointer's shape, not this function's choice.
    #[allow(clippy::unnecessary_wraps)]
    pub fn always_satisfies(_: &[u8], _: &BlockHash) -> Result<PowHash, Faulted> {
        Ok(PowHash::from_bytes([0; 32]))
    }
}

impl Default for MockSubstrate {
    fn default() -> Self {
        Self {
            clock: Self::CLOCK,
            longhash: Self::always_satisfies,
        }
    }
}

impl Substrate for MockSubstrate {
    type Fault = Faulted;

    fn local_clock(&self) -> Result<Timestamp, Faulted> {
        Ok(self.clock)
    }

    fn longhash(&self, pow_blob: &[u8], seed: &BlockHash) -> Result<PowHash, Faulted> {
        (self.longhash)(pow_blob, seed)
    }
}

/// The seed CEN-D3 expects for a candidate on `chain`'s tip: the null hash
/// at genesis admission, else the identity of the block at
/// [`seed_height`](crate::seed_height). What an honest driver claims to
/// `form`.
#[must_use]
pub fn expected_seed(chain: &MockChain) -> BlockHash {
    let connecting = BlockHeight::from_raw(chain.tip().map_or(0, |tip| tip.height.to_raw() + 1));
    let Some(seed_height) = crate::seed_height(connecting) else {
        return BlockHash::NULL;
    };
    match chain.block(seed_height) {
        AtHeight::Recorded(block) => block.hash,
        AtHeight::AboveTip => unreachable!("the seed height is below the tip"),
    }
}

/// Run the stateless stage under `rule_set` with the default substrate,
/// claiming `seed`. Panics if the substrate faults or a stateless rule
/// refuses — a fixture that wants to exercise either calls [`form`] itself.
#[track_caller]
pub fn formed_under(
    candidate: Candidate,
    rule_set: &RuleSet,
    seed: BlockHash,
) -> StructurallyValid {
    match form(
        candidate,
        rule_set,
        &MockSubstrate::default(),
        seed,
        FormAttempt::FIRST,
    ) {
        Ok(Ok(formed)) => formed,
        Ok(Err(refused)) => panic!("the fixture was refused by a stateless rule: {refused}"),
        Err(Faulted) => unreachable!("the default MockSubstrate never faults"),
    }
}

/// [`formed_under`] the genesis rule set, claiming the seed `chain` expects
/// — the honest driver's call, so D3 holds and the view stage judges the
/// candidate.
#[track_caller]
pub fn formed_on(chain: &MockChain, candidate: Candidate) -> StructurallyValid {
    formed_under(candidate, &RuleSet::GENESIS, expected_seed(chain))
}

/// [`formed_on`] an empty chain — a genesis candidate.
#[track_caller]
pub fn formed(candidate: Candidate) -> StructurallyValid {
    formed_on(&MockChain::default(), candidate)
}

/// Unwrap a result whose error cannot exist.
pub fn infallible<T>(result: Result<T, Infallible>) -> T {
    match result {
        Ok(value) => value,
        Err(never) => match never {},
    }
}

/// Unwrap `validate`'s outer position over a view that cannot fault: the
/// view arm is uninhabited, and the crate's own arms are a fixture failure
/// unless the test asked for them.
#[track_caller]
pub fn judged<T>(result: Result<T, Fault<Infallible>>) -> T {
    match result {
        Ok(value) => value,
        Err(Fault::View(never)) => match never {},
        Err(Fault::Stale(stale)) => panic!("unexpected stale premise: {stale}"),
        Err(Fault::Corrupt(corrupt)) => panic!("unexpected corrupt view: {corrupt}"),
    }
}

/// Assert `result` is exactly a refusal on `rule` at `locus`.
///
/// Panics on a pass ("the rule did not fire"), on a refusal by any other
/// row ("the wrong rule fired"), and on the right row at the wrong place
/// (miner vs listed vs input index) — the three ways a negative fixture
/// goes vacuous.
#[track_caller]
pub fn assert_refused<T: Debug>(result: Verdict<T>, rule: CenRow, locus: Locus) {
    match result {
        Err(InvalidBlock {
            rule: fired,
            locus: at,
        }) if fired == rule && at == locus => {}
        Err(other) => panic!("expected {rule} at {locus}, but {other}"),
        Ok(passed) => {
            panic!("expected {rule} at {locus}, but the candidate passed: {passed:?}")
        }
    }
}

/// Assert `f` passes `last_ok` and refuses `first_bad` on `rule` at `locus`
/// — the two sides of a boundary, so an off-by-one in the rule fails here.
#[track_caller]
pub fn boundary_pair<T: Debug, V>(
    last_ok: V,
    first_bad: V,
    rule: CenRow,
    locus: Locus,
    f: impl Fn(V) -> Verdict<T>,
) {
    if let Err(refused) = f(last_ok) {
        panic!("the last acceptable value was refused: {refused}");
    }
    assert_refused(f(first_bad), rule, locus);
}

/// Fixtures: well-formed values to mutate one field of.
///
/// **"Well-formed" is a gated claim, not a label.** A fixture is built by
/// test code and never passes through a production builder, so it can be
/// illegal in ways nobody checks — and each latent illegality surfaces one
/// rule at a time, as a mid-commit surprise, when the rule that refuses it
/// lands (slice 5 commit 2: three fixtures listed coinbase-shaped bodies,
/// and CEN-H5 refused them). `fixture_sanity_tests` holds every
/// transaction shape here to `validate` / `tx_form` under **current**
/// coverage, at every slot it is meant for, so a bad fixture fails the
/// moment it is written — and the set it walks is [`TxShape`], a closed
/// enum: a new shape that the gate does not know is a **compile error**
/// (three non-exhaustive matches), not a doc line nobody re-reads. The
/// negative fixtures live with their rows and are labelled by the row they
/// refuse on.
pub mod fixture {
    use super::*;
    use crate::verdict::TxSlot;

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
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66,
    ];

    /// `2·G` compressed: a canonical prime-order point that is neither the
    /// identity, nor `G`, nor `zeroCommit(0) = G` — a commitment mask CEN-F10
    /// accepts for a zero-amount coinbase output. `fixture_points_are_what_
    /// they_claim` (miner_tests) pins both constants through
    /// `shekyl-ct-balance`.
    pub const TWO_G: [u8; 32] = [
        0xc9, 0xa3, 0xf8, 0x6a, 0xae, 0x46, 0x5f, 0x0e, 0x56, 0x51, 0x38, 0x64, 0x51, 0x0f, 0x39,
        0x97, 0x56, 0x1f, 0xa2, 0xc9, 0xe8, 0x5e, 0xa2, 0x1d, 0xc2, 0x29, 0x23, 0x09, 0xf3, 0xcd,
        0x60, 0x22,
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
    /// multiples add: masks `2·G ‥ (N+1)·G` balance against one pseudo-out
    /// of `(Σk)·G` with zero fee, and that identity — an arithmetic fact
    /// about how the table was *constructed*, not anything the code under
    /// test computes — is what makes the store's `spend(_, N)`
    /// (`connect_fixtures.rs`), the ingest's `spend`, and [`listed`] pass
    /// CEN-H18. Renumber the table, skip an entry, or take a non-contiguous
    /// subset and those fixtures stop balancing for a reason that has
    /// nothing to do with the rule. `fixture_points_are_what_they_claim`
    /// therefore asserts `POINTS[k−1] == k·G` for every `k`, with test-only
    /// curve arithmetic — the identity is a gate, not a convention.
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

    /// A coinbase that satisfies every structural 4.F row for a block at
    /// `height`: one `Input::Gen(height)` (F1, F5), `Ct::Null` (F3), one
    /// output (F4) paying `0` with key `G` (F9) and mask `2·G` (F10),
    /// `unlock_time = height + mined_money_unlock_window` (F6). Amounts are
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
        let unlock_time =
            height.saturating_add(RuleSet::GENESIS.mined_money_unlock_window().to_raw());
        Transaction {
            prefix: TxPrefix {
                unlock_time,
                inputs: vec![Input::Gen(height)],
                outputs: vec![Output {
                    amount: 0,
                    key: G,
                    view_tag: 1,
                }],
                extra: Vec::new(),
            },
            ct: Ct::Null(CtBase {
                enc_amounts: vec![[0x55; 9]],
                enc_labels: vec![[0x66; 9]],
                commitments: vec![TWO_G],
            }),
        }
    }

    /// A **listed** (non-coinbase) transaction spending `key_image`, shaped
    /// to pass every structural 4.H row that has landed: one `ToKey` input
    /// with empty offsets (CEN-I6), one zero-amount output keyed `G` with a
    /// `2·G` mask (H7, H17), `Ct::Fcmp` with the committed base sized to the
    /// outputs (H8), `unlock_time` below the sentinel (H16), a prunable
    /// region whose one BP+ has the canonical **layout** for one output
    /// (H19's layout half: `|L| = |R| = 6`) with one pseudo-out for its one
    /// spend, and a **fee of zero** so that pseudo-out (`2·G`) balances the
    /// one mask (`2·G`) exactly (H18 — multiples of `G` add, which is what
    /// makes [`POINTS`] a balance fixture as well as a point table). The
    /// proof *bytes* are filler: H19's verification and the 4.I
    /// membership rows are not landed, and when they land this fixture is
    /// theirs to refuse — the sanity gate will say so, and the fix is a
    /// tx-builder-produced proof, not a longer filler. Mutate one field to
    /// build a negative fixture.
    pub fn listed(key_image: [u8; 32]) -> Transaction {
        Transaction {
            prefix: TxPrefix {
                unlock_time: 0,
                inputs: vec![Input::ToKey {
                    amount: 0,
                    key_offsets: Vec::new(),
                    key_image,
                }],
                outputs: vec![Output {
                    amount: 0,
                    key: G,
                    view_tag: 2,
                }],
                extra: Vec::new(),
            },
            ct: Ct::Fcmp {
                fee: 0,
                reference_block: BlockHash::from_bytes([0x99; 32]),
                base: CtBase {
                    enc_amounts: vec![[0x11; 9]],
                    enc_labels: vec![[0x22; 9]],
                    commitments: vec![TWO_G],
                },
                pqc_auths: vec![pqc_auth_filler()],
                prunable: Some(Prunable {
                    bulletproofs: vec![bp_plus_layout_for(1)],
                    tree_depth: 0,
                    fcmp_proof: vec![0xF0],
                    pseudo_outs: vec![TWO_G],
                    serve_credit_pruned: Vec::new(),
                }),
            },
        }
    }

    /// A per-input PQC authentication with **empty** key and signature
    /// blobs: what the wire needs to round-trip a non-serve-credit `Fcmp`
    /// transaction (`pqc_auths.len() == nvin`, no length prefix — a spend
    /// with none parses as the storage-pruned form), and nothing the
    /// signature rows (4.I) would accept. Filler, like [`bp_plus_layout_for`].
    pub fn pqc_auth_filler() -> PqcAuth {
        PqcAuth {
            auth_version: 1,
            scheme_id: 1,
            flags: 0,
            hybrid_public_key: Vec::new(),
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
                reference_block: BlockHash::from_bytes([0x99; 32]),
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
}

#[cfg(test)]
#[path = "harness_probe_tests.rs"]
mod harness_probe_tests;

#[cfg(test)]
#[path = "fixture_sanity_tests.rs"]
mod fixture_sanity_tests;
