// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved.
// BSD-3-Clause

//! Bench-support surface for the §5.3 **B9 dispatch-overhead**
//! benchmark (`docs/design/STAGE_2_KEY_ENGINE_ACTOR.md`).
//!
//! The whole module is gated behind the `bench-internals` feature and
//! re-exported through [`crate::__bench_internals`]. It exists so the
//! external Criterion / iai-callgrind bench targets can measure the
//! actor-dispatch overhead without the `KeyEngine` trait (which is
//! `pub(crate)`) or [`KeyEngineHandle`] (likewise `pub(crate)`) leaking
//! into the public API: the harness is the single `pub` surface, it
//! owns the otherwise-`pub(crate)` machinery as private fields, and its
//! measured methods return a bare `bool` (claimed / not claimed) so no
//! `pub(crate)` type crosses the bench-function boundary.
//!
//! # What B9 measures (and why this shape)
//!
//! B9 is a **bench-vs-bench ratio**, not an absolute gate (§5.3): the
//! actor path (`KeyEngineHandle::try_claim_output`, an `ask` round-trip
//! through the mailbox) should land within 5% of the composition
//! baseline (`LocalKeys::try_claim_output`, the same crypto with no
//! mailbox). Because both calls are `async` (awaitable for Stage-4
//! flexibility; the `LocalKeys` body completes synchronously inside the
//! future per `local_keys.rs`'s module docstring), the harness's
//! measured methods are `async` and the bench drives them on a runtime.
//!
//! Three measured methods, matching §5.3's three reported numbers:
//!
//! - [`baseline_claim_mine`](KeyDispatchBenchHarness::baseline_claim_mine)
//!   — direct `LocalKeys` over a `Mine` output (full path: X25519
//!   view-tag + hybrid ML-KEM-768 decap + HKDF + key-image + handle
//!   insertion). The composition baseline.
//! - [`actor_claim_mine`](KeyDispatchBenchHarness::actor_claim_mine) —
//!   the same `Mine` output via the actor `ask`. The ratio against the
//!   baseline is the B9 signal; the messaging overhead is expected to
//!   be lost in the ML-KEM-768 decap noise.
//! - [`actor_claim_not_mine`](KeyDispatchBenchHarness::actor_claim_not_mine)
//!   — a `NotMine` output via the actor `ask` (X25519 pre-filter only,
//!   the cheap common case). This is where the 5% envelope is hardest
//!   to hold; §5.3 records the dispatch cost against the *cheapest*
//!   real op as evidence for (not a gate on) the §8.3 view-scan split.
//!
//! There is **no** `actor_*` iai-callgrind sibling: the `ask` is a
//! cross-thread async round-trip, and iai-callgrind runs under Callgrind
//! (Valgrind serializes all threads onto a simulated single core), so an
//! `ask`'s instruction count folds in nondeterministic runtime-scheduling
//! machinery rather than the clean deterministic signal iai exists for.
//! The actor path is criterion-(wall-clock)-only by design — a reasoned
//! deviation from the criterion+iai pairing discipline
//! (`docs/design/STAGE_0_HARNESS.md`), reversion-claused: reopen the iai
//! sibling if a deterministic async-dispatch measurement method lands.
//! Only the deterministic-crypto baseline gets an iai sibling.

use std::collections::HashMap;

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, Scalar};
use shekyl_crypto_pq::account::{generate_account_from_raw_seed, AllKeysBlob, DerivationNetwork};
use shekyl_crypto_pq::kem::HybridCiphertext;
use shekyl_crypto_pq::output::construct_output;
use shekyl_engine_state::{
    payment_id::PaymentId,
    subaddress::SubaddressIndex,
    transfer::{TransferDetails, SPENDABLE_AGE},
    BlockchainTip, LedgerBlock, ReorgBlocks,
};
use shekyl_oxide::primitives::Commitment;

use crate::engine::key_actor::KeyEngineHandle;
use crate::engine::local_keys::LocalKeys;
use crate::engine::merge::populate_engine_handle_fields;
use crate::engine::traits::key::{KeyEngine, OutputClaimResult, OutputDetectionInput, ViewTag};

/// Deterministic seed for the wallet under measurement. Distinct from
/// the `Engine`/`LocalKeys` fixture seeds elsewhere in the bench suite
/// so the dispatch fixture's identity material is non-aliased.
const DISPATCH_BENCH_SEED: [u8; 32] = [0x5Bu8; 32];

/// A *different* wallet's seed — used to build the `NotMine` output
/// (paid to a stranger; the wallet under measurement does not own it).
const DISPATCH_BENCH_STRANGER_SEED: [u8; 32] = [0x9Eu8; 32];

/// Sender-side tx-key secret for `construct_output`. Its value does not
/// affect receiver-side recovery (the recipient only sees the
/// ciphertext), so any fixed non-zero value is fine.
const DISPATCH_BENCH_TX_KEY_SECRET: [u8; 32] = [0x11u8; 32];

/// Rederive a fresh [`AllKeysBlob`] from `seed` (testnet, raw32).
///
/// Duplicated from the `key_actor` / `local_keys` test helpers per the
/// bench-fixture duplication discipline (`STAGE_0_HARNESS.md` §4.2:
/// benches duplicate test-helper logic locally rather than widening
/// test-helper visibility). Rederivation is deterministic, so two blobs
/// from the same seed are byte-identical — which is how the actor side
/// and the `LocalKeys` baseline share key material despite `AllKeysBlob`
/// being non-`Clone`.
fn make_blob(seed: [u8; 32]) -> AllKeysBlob {
    let (_master_seed, blob) = generate_account_from_raw_seed(&seed, DerivationNetwork::Testnet)
        .expect("bench rederivation succeeds for raw32 testnet seeds");
    blob
}

/// Build a synthetic on-chain output paid to `recipient`'s primary
/// address, packaged as the [`OutputDetectionInput`] the trait surface
/// consumes. Mirrors the `key_actor` test helper `build_output_paid_to`.
fn build_output_paid_to(
    recipient: &AllKeysBlob,
    output_index: u64,
    amount: u64,
    tx_hash: [u8; 32],
) -> OutputDetectionInput {
    let constructed = construct_output(
        &DISPATCH_BENCH_TX_KEY_SECRET,
        &recipient.x25519_pk,
        &recipient.ml_kem_ek,
        recipient.spend_pk.as_canonical_bytes(),
        amount,
        output_index,
    )
    .expect("construct_output succeeds for synthetic bench output");

    OutputDetectionInput {
        ciphertext: HybridCiphertext {
            x25519: constructed.kem_ciphertext_x25519,
            ml_kem: constructed.kem_ciphertext_ml_kem.clone(),
        },
        output_key: constructed.output_key,
        commitment: constructed.commitment,
        view_tag: ViewTag([constructed.view_tag_x25519]),
        enc_amount: constructed.enc_amount,
        amount_tag_on_chain: constructed.amount_tag,
        output_index,
        tx_hash,
    }
}

/// Fixture for the §5.3 B9 dispatch-overhead bench.
///
/// Owns the composition baseline ([`LocalKeys`]), the actor
/// (`KeyEngineHandle`), and the two prebuilt detection inputs (a
/// `Mine` output paid to the wallet under measurement, and a `NotMine`
/// output paid to a stranger). All construction is **setup** — held
/// outside the measured region by the bench's `b.iter` / iai `setup =`
/// boundary; only the `try_claim_output` calls are measured.
///
/// # Runtime requirement
///
/// [`KeyDispatchBenchHarness::new`] spawns the `KeyEngineHandle`,
/// which (post Stage-2 require-ambient, §4.2) asserts an ambient Tokio
/// runtime. The bench must call `new` inside a runtime context (e.g.
/// `rt.block_on(async { KeyDispatchBenchHarness::new() })` or under an
/// `rt.enter()` guard) on a runtime that outlives the harness — the
/// actor task lives on it for the harness's lifetime.
pub struct KeyDispatchBenchHarness {
    /// Composition baseline: the in-process `KeyEngine` implementor over
    /// the same key material the actor holds.
    local: LocalKeys,
    /// The actor under measurement.
    handle: KeyEngineHandle,
    /// Prebuilt `Mine` output (paid to this wallet's primary address).
    mine_input: OutputDetectionInput,
    /// Prebuilt `NotMine` output (paid to a stranger).
    not_mine_input: OutputDetectionInput,
}

impl Default for KeyDispatchBenchHarness {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyDispatchBenchHarness {
    /// Build the fixture. **Must run inside an ambient Tokio runtime**
    /// (see the type docstring) because spawning the actor asserts one.
    pub fn new() -> Self {
        // Two blobs from the SAME seed (rederivation is deterministic →
        // byte-identical) so the actor and the `LocalKeys` baseline hold
        // the same key material despite `AllKeysBlob` being non-`Clone`.
        let actor_blob = make_blob(DISPATCH_BENCH_SEED);
        let local = LocalKeys::from_test_seed(DISPATCH_BENCH_SEED);

        let mine_input = build_output_paid_to(&actor_blob, 0, 1_337, [0x33u8; 32]);

        let stranger = make_blob(DISPATCH_BENCH_STRANGER_SEED);
        let not_mine_input = build_output_paid_to(&stranger, 0, 42, [0x44u8; 32]);

        let handle = KeyEngineHandle::spawn(actor_blob);

        Self {
            local,
            handle,
            mine_input,
            not_mine_input,
        }
    }

    /// Composition baseline: direct `LocalKeys::try_claim_output` on a
    /// `Mine` output. Returns `true` (the output is claimed) — the
    /// `black_box`-able result keeps the optimizer from eliding the
    /// crypto.
    pub async fn baseline_claim_mine(&self) -> bool {
        matches!(
            self.local
                .try_claim_output(&self.mine_input)
                .await
                .expect("baseline claim succeeds"),
            OutputClaimResult::Mine(_)
        )
    }

    /// Actor path: the same `Mine` output via the `ask` round-trip.
    pub async fn actor_claim_mine(&self) -> bool {
        matches!(
            self.handle
                .try_claim_output(&self.mine_input)
                .await
                .expect("actor claim succeeds"),
            OutputClaimResult::Mine(_)
        )
    }

    /// Actor path, cheap case: a `NotMine` output via the `ask`
    /// round-trip (X25519 view-tag pre-filter only). Returns `true` when
    /// the result is `NotMine` (the expected outcome) so the bench can
    /// `black_box` a stable value.
    pub async fn actor_claim_not_mine(&self) -> bool {
        matches!(
            self.handle
                .try_claim_output(&self.not_mine_input)
                .await
                .expect("actor claim succeeds"),
            OutputClaimResult::NotMine
        )
    }
}

/// Actor-free fixture for the deterministic-crypto **baseline** iai
/// sibling.
///
/// [`KeyDispatchBenchHarness`] spawns a `KeyActor` in `new` (which needs
/// an ambient multi-thread runtime). The iai-callgrind baseline must
/// avoid that: it measures only the composition baseline
/// (`LocalKeys::try_claim_output`), and running a multi-thread runtime
/// under Callgrind is both unnecessary and noisy. This fixture holds
/// just the `LocalKeys` and a `Mine` input — no actor, no spawn, so it
/// constructs without an ambient runtime. The single async call is
/// driven by the iai bench's own current-thread runtime; that
/// `block_on`-of-an-immediately-`Ready`-future overhead is small and
/// constant (the `LocalKeys` body completes synchronously inside the
/// future), so the measured instruction count stays dominated by the
/// hybrid ML-KEM-768 decap.
pub struct KeyBaselineBenchFixture {
    local: LocalKeys,
    mine_input: OutputDetectionInput,
}

impl Default for KeyBaselineBenchFixture {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyBaselineBenchFixture {
    /// Build the fixture. Needs no ambient runtime (no actor spawn).
    pub fn new() -> Self {
        let blob = make_blob(DISPATCH_BENCH_SEED);
        let local = LocalKeys::from_test_seed(DISPATCH_BENCH_SEED);
        let mine_input = build_output_paid_to(&blob, 0, 1_337, [0x33u8; 32]);
        Self { local, mine_input }
    }

    /// The composition baseline: direct `LocalKeys::try_claim_output` on
    /// a `Mine` output.
    pub async fn claim_mine(&self) -> bool {
        matches!(
            self.local
                .try_claim_output(&self.mine_input)
                .await
                .expect("baseline claim succeeds"),
            OutputClaimResult::Mine(_)
        )
    }
}

/// Boxed, no-arg builder for the baseline iai fixture (boundary rule:
/// `LocalKeys` is well above the 64-byte cutoff; the `Box` moves only a
/// pointer across the bench boundary).
pub fn build_key_baseline_fixture() -> Box<KeyBaselineBenchFixture> {
    Box::new(KeyBaselineBenchFixture::new())
}

/// Teardown for iai-callgrind's `teardown = …` (lifts the `LocalKeys`
/// zeroize-on-drop out of the measured region, per the §4.2 symmetry
/// rule).
pub fn drop_key_baseline_fixture(_fixture: Box<KeyBaselineBenchFixture>) {}

// ---------------------------------------------------------------------------
// §5.3 merge-path bench (6-i construction-time view-secret projection)
// ---------------------------------------------------------------------------

/// View secret keying the deterministic `OutputHandle` derivation in the
/// merge post-pass. Any fixed 32-byte value drives `derive_output_handle`
/// (cSHAKE256 PRF); the projection cost is independent of its content.
const MERGE_BENCH_VIEW_SECRET: [u8; 32] = [0x6Du8; 32];

/// Batch size for the merge-path projection fixture: the number of
/// freshly-merged outputs the 6-i post-pass walks in one refresh.
///
/// `256` is a meaningful single-refresh wallet-output batch (large
/// enough that the per-output projection work dominates fixture
/// addressing overhead, small enough that the iai-callgrind Valgrind run
/// completes within the §4.4 dynamic-check budget). The frozen baseline
/// pins to this workload at the merge SHA; a future
/// workload-characterization PR that needs a different N adds a sibling
/// builder rather than mutating this constant.
pub const MERGE_BENCH_OUTPUT_COUNT: usize = 256;

/// Fixture for the §5.3 merge-path bench. Holds a `LedgerBlock`
/// pre-populated with `n` transfers whose engine-derived fields
/// (`source_ciphertext`, `output_handle`) are `None`, a matching
/// detection-residue map, and the flat inserted-index list — exactly the
/// shape [`Engine::apply_scan_result`](super::Engine::apply_scan_result)
/// hands `populate_engine_handle_fields` at `merge.rs:218`.
///
/// [`run_projection`](MergeProjectionBenchFixture::run_projection) drives
/// the real post-pass over the batch; the per-output cost (HashMap
/// lookup + `derive_output_handle` cSHAKE256 + ciphertext clone) is the
/// 6-i marginal cost the §8.1 6-ii-deferral decision is evidence-based
/// against. The post-pass is synchronous and runtime-free, so this bench
/// is iai-callgrind-friendly (deterministic instruction count), unlike
/// the actor dispatch path.
pub struct MergeProjectionBenchFixture {
    ledger: LedgerBlock,
    view_secret: [u8; 32],
    residue: HashMap<([u8; 32], u64), HybridCiphertext>,
    inserted: Vec<usize>,
}

/// Build one transfer with `source_ciphertext`/`output_handle` unset, so
/// the post-pass does full per-output work. Mirrors the canonical
/// `sample_transfer` shape in `benches/common/engine_fixture.rs`; kept in
/// lockstep with it (and with `TransferDetails`) if the struct grows
/// fields — a shape mismatch would let the bench measure the wrong thing.
fn unpopulated_transfer(seed: u64) -> TransferDetails {
    let lo = (seed & 0xff) as u8;
    let tx_hash = [lo; 32];
    TransferDetails {
        tx_hash,
        internal_output_index: seed,
        global_output_index: 1_000 + seed,
        block_height: 100,
        key: ED25519_BASEPOINT_POINT,
        key_offset: Scalar::ONE,
        commitment: Commitment::new(Scalar::ONE, 1_000_000 + seed),
        subaddress: Some(SubaddressIndex::new((seed & 0xffff_ffff) as u32)),
        payment_id: Some(PaymentId([lo; 8])),
        spent: false,
        spent_height: None,
        key_image: None,
        staked: false,
        stake_tier: 0,
        stake_lock_until: 0,
        last_claimed_height: 0,
        // The post-pass populates these from `None`; that is the measured work.
        source_ciphertext: None,
        output_handle: None,
        eligible_height: 100 + SPENDABLE_AGE,
        frozen: false,
        fcmp_precomputed_path: None,
    }
}

impl MergeProjectionBenchFixture {
    /// Build the fixture with `n` unpopulated transfers and a residue map
    /// matching all of them.
    pub fn new(n: usize) -> Self {
        let mut transfers = Vec::with_capacity(n);
        let mut residue = HashMap::with_capacity(n);
        for i in 0..n {
            let seed = i as u64;
            let td = unpopulated_transfer(seed);
            let key = (td.tx_hash, td.internal_output_index);
            // A realistically-sized on-chain hybrid ciphertext (~1088-byte
            // ML-KEM + 32-byte X25519), so the per-output `clone()` in the
            // post-pass reflects production memcpy cost.
            residue.insert(
                key,
                HybridCiphertext {
                    x25519: [(seed & 0xff) as u8; 32],
                    ml_kem: vec![(seed.wrapping_add(1) & 0xff) as u8; 1088],
                },
            );
            transfers.push(td);
        }

        let tip = BlockchainTip::new(1_000_000, [0xAA; 32]);
        let reorg_blocks = ReorgBlocks {
            blocks: (999_990..=1_000_000)
                .map(|h| (h, [(h & 0xff) as u8; 32]))
                .collect(),
        };
        let ledger = LedgerBlock::new(transfers, tip, reorg_blocks);
        let inserted = (0..n).collect();

        Self {
            ledger,
            view_secret: MERGE_BENCH_VIEW_SECRET,
            residue,
            inserted,
        }
    }

    /// The measured 6-i projection over the batch: the real merge
    /// post-pass at `merge.rs:218`.
    pub fn run_projection(&mut self) {
        populate_engine_handle_fields(
            &mut self.ledger,
            &self.view_secret,
            &self.residue,
            &self.inserted,
        );
    }

    /// Number of transfers whose `output_handle` is populated — a
    /// `black_box`-able witness that the projection ran (and a guard
    /// against the optimizer eliding the work).
    pub fn populated_count(&self) -> usize {
        self.inserted
            .iter()
            .filter(|&&i| self.ledger.transfers[i].output_handle.is_some())
            .count()
    }
}

/// No-arg, boxed builder for the merge-path fixture.
///
/// Boxed per the iai-callgrind boundary rule
/// (`docs/design/STAGE_0_HARNESS.md` §4.2): the fixture carries a
/// `LedgerBlock` of [`MERGE_BENCH_OUTPUT_COUNT`] transfers (far above the
/// 64-byte cutoff), so passing it across the bench-function boundary by
/// value would dominate the measurement with memcpy. The `Box` moves
/// only an 8-byte pointer. The no-arg shape suits iai-callgrind's
/// `#[bench::name(setup = …)]` attribute (resolved at macro-expansion
/// time, prefers a fully-applied function path) and criterion's
/// `iter_batched` setup closure (fresh fixture per measured invocation,
/// so the idempotent post-pass does full work every time).
pub fn build_merge_projection_fixture() -> Box<MergeProjectionBenchFixture> {
    Box::new(MergeProjectionBenchFixture::new(MERGE_BENCH_OUTPUT_COUNT))
}

/// Teardown for iai-callgrind's `teardown = …`: taking ownership
/// schedules `Drop` outside the measured region (the symmetry rule,
/// §4.2). The criterion sibling does not need it (`iter_batched`
/// amortizes / excludes drop).
pub fn drop_merge_projection_fixture(_fixture: Box<MergeProjectionBenchFixture>) {}
