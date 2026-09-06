//! Ruling B measurement half — the oracles for the layered determinism bar.
//!
//! Spec: `docs/V3_SHARD_VISUALIZATION.md`, *Rendering determinism and
//! empirical closure (ruling B)*. The thresholds here are **pre-registered**
//! (fixed 2026-09-05, before any cross-platform run produced a number) and
//! change only by recorded amendment citing the measurement — never to make
//! a red run green.
//!
//! Oracle independence: the goldens under `tests/goldens/` were committed
//! once from the designated reference run (`examples/gen_goldens.rs`; the
//! producing commit names the implementation, architecture, and toolchain).
//! Nothing in this file writes them. If a test here can rewrite the artifact
//! it is checked against, the oracle has no independent existence.

use std::io::Cursor;
use std::path::PathBuf;

use shekyl_shard_visual::{
    fixtures, parameters_from_aggregate, recipe_from_params, render_candidate_png_from_params,
    RENDER_REVISION,
};

/// Pre-registered raster threshold θ (spec: RGB-RMS on decoded pixels,
/// 0–255 scale). Registered reasoning: honest cross-platform divergence is
/// isolated boundary-rounding jitter (RMS ≪ 1); the defect classes the
/// oracle exists to catch start an order of magnitude above (dropped
/// element RMS ≈ 10–20, wrong palette ≈ 30+).
const THETA: f64 = 2.0;

/// Pre-registered avalanche floor (spec: *Sensitivity, not continuity*).
const AVALANCHE_FLOOR: f64 = 20.0;

/// Golden raster size — the mobile thumbnail target, and the size named in
/// the goldens' filenames.
const GOLDEN_SIZE: u32 = 128;

/// Size the avalanche sweep renders at. Derived from [`GOLDEN_SIZE`] rather
/// than repeated as a literal, and deliberately the same size: the spec
/// records parity and avalanche under one scope statement ("at 128px"), so
/// if the measurement size ever moves, both must move together or that
/// statement silently stops describing the tests. The avalanche sweep does
/// not read the goldens, hence its own name.
const AVALANCHE_SIZE: u32 = GOLDEN_SIZE;

fn goldens_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/goldens")
}

/// The fixture corpus, with its own existence asserted (rule 47,
/// `.cursor/rules/47-gate-subject-assertion.mdc`).
///
/// Every oracle in this file iterates the corpus, and `for x in empty {}`
/// passes. Without this assertion an emptied `fixtures::all()` would turn all
/// three tests green while measuring nothing — absence of signal read as
/// absence of defect. The KAT is the worst case: an empty corpus and an
/// empty artifact compare equal, so the set-equality check would agree that
/// nothing matches nothing.
fn corpus() -> Vec<fixtures::PreviewFixture> {
    let all = fixtures::all();
    assert!(
        !all.is_empty(),
        "fixture corpus is empty — these oracles measure nothing without it \
         (rule 47: a gate asserts its own subject exists)"
    );
    all
}

/// Decode PNG bytes to raw RGB8 pixels. **The comparison axis is decoded
/// pixels, never PNG file bytes** (spec: bytes go through the encoder's
/// compression, filtering, and the ruling-A provenance chunks — a byte
/// comparison would measure the compressor, not the picture).
///
/// `what` names the image being decoded (`"golden genesis"`, `"rendered
/// genesis"`) so a format failure says which side of the comparison was
/// malformed. Both sides pass through here, so a message naming only one of
/// them would misdirect the reader of a failure.
fn decode_rgb8(what: &str, png_bytes: &[u8]) -> (u32, u32, Vec<u8>) {
    let decoder = png::Decoder::new(Cursor::new(png_bytes));
    let mut reader = decoder.read_info().expect("png header");
    let mut buf = vec![0u8; reader.output_buffer_size().expect("png buffer size")];
    let info = reader.next_frame(&mut buf).expect("png frame");
    assert_eq!(
        info.color_type,
        png::ColorType::Rgb,
        "{what}: expected RGB8 color type"
    );
    assert_eq!(
        info.bit_depth,
        png::BitDepth::Eight,
        "{what}: expected 8-bit depth"
    );
    buf.truncate(info.buffer_size());
    (info.width, info.height, buf)
}

/// Per-pixel RGB root-mean-square distance on the 0–255 scale, over all
/// pixels and channels — the spec's registered metric, verbatim.
fn rgb_rms(a: &[u8], b: &[u8]) -> f64 {
    assert_eq!(a.len(), b.len(), "images must have identical dimensions");
    let sum_sq: f64 = a
        .iter()
        .zip(b)
        .map(|(&x, &y)| {
            let d = f64::from(x) - f64::from(y);
            d * d
        })
        .sum();
    #[allow(
        clippy::cast_precision_loss,
        reason = "channel counts cap at 4096*4096*3 << 2^53; the cast is exact"
    )]
    let n = a.len() as f64;
    (sum_sq / n).sqrt()
}

/// Structure layer, full-recipe KAT: every fixture's `CandidateRecipe` must
/// match the committed artifact field-for-field. Bar: **bit-exact,
/// forever** — falsified by any recipe field differing on any platform or
/// implementation. The Python explorer pins to a copy of this same
/// artifact (`shekyl-dev` `visualization/tests/fixtures/recipes.json`,
/// source commit named in its `_reference_run` record), never to the Rust
/// crate at runtime.
#[test]
fn full_recipe_kat_matches_committed_artifact() {
    let raw = std::fs::read_to_string(goldens_dir().join("recipes.json"))
        .expect("committed tests/goldens/recipes.json");
    let golden: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&raw).expect("recipes.json parses");

    let fixtures = corpus();

    // The provenance record is a PREREQUISITE of this artifact, not incidental
    // metadata that may be filtered away unchecked (rule 47). What makes these
    // generated goldens reviewable is that they name the run that produced
    // them; if that record is deleted the nine ids still match and every
    // recipe still compares equal, so this gate would stay green after the
    // thing that justifies it disappeared.
    let reference_run = golden
        .get("_reference_run")
        .expect("recipes.json must carry its _reference_run provenance record");

    // THE REVISION PIN, enforced rather than documented. Goldens are only
    // meaningful under the pixel derivation that produced them. Without this
    // equality, "a changed golden byte under an unchanged RENDER_REVISION is a
    // mistake" is a convention a reviewer has to apply by hand; with it,
    // regenerating goldens without bumping the constant fails here.
    assert_eq!(
        reference_run
            .get("render_revision")
            .and_then(serde_json::Value::as_u64),
        Some(u64::from(RENDER_REVISION)),
        "goldens were generated under a different RENDER_REVISION than this \
         crate exports ({RENDER_REVISION}) — regenerate them, or bump the \
         constant if the pixel derivation changed"
    );
    assert_eq!(
        reference_run
            .get("golden_size")
            .and_then(serde_json::Value::as_u64),
        Some(u64::from(GOLDEN_SIZE)),
        "the artifact's golden_size must match the size these tests compare at"
    );

    // A dirty tree does not identify what was rendered: the sha names the
    // commit, and the uncommitted changes on top of it are unrecoverable, so
    // "generated at X with unknown edits" is not a designated reference run.
    // The generator records the flag for exactly this reason — reading it is
    // what makes recording it worth anything.
    assert_eq!(
        reference_run
            .get("source_tree_dirty")
            .and_then(serde_json::Value::as_bool),
        Some(false),
        "goldens were generated from a DIRTY tree — the recorded commit cannot \
         identify what was rendered. Commit the tree, regenerate, then commit \
         the artifact (the flag describes the tree the generator READ, so the \
         write it performs afterwards does not invalidate it)"
    );

    // The fields that let a reader identify the run. `unknown` is what the
    // generator writes when a capture fails, so it is rejected here — a
    // provenance record that cannot name its toolchain or tree is not
    // provenance, and accepting the placeholder would let the record decay
    // silently.
    for field in [
        "implementation",
        "profile",
        "rustc_version",
        "target_arch",
        "target_os",
        "source_tree_commit",
    ] {
        let value = reference_run
            .get(field)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        assert!(
            !value.is_empty() && value != "unknown",
            "_reference_run must name `{field}` — a provenance record missing \
             it cannot identify the run that produced these goldens"
        );
    }

    // Id-set equality in both directions: a fixture added without a golden
    // recipe, or a golden orphaned by a removed fixture, is a failure — a
    // one-directional check lets the artifact and the corpus drift apart.
    let mut golden_ids: Vec<&str> = golden
        .keys()
        .filter(|k| *k != "_reference_run")
        .map(String::as_str)
        .collect();
    let mut fixture_ids: Vec<&str> = fixtures.iter().map(|f| f.id.as_str()).collect();
    // BOTH sides sorted. serde_json's Map iterates sorted only while it is
    // backed by a BTreeMap; the `preserve_order` feature swaps in an IndexMap
    // that iterates in file order, and Cargo feature unification means any
    // crate in the workspace could enable it without touching this test.
    // Sorting here removes that hidden dependency — the assertion is about
    // set equality, never iteration order.
    golden_ids.sort_unstable();
    fixture_ids.sort_unstable();
    assert_eq!(
        golden_ids, fixture_ids,
        "committed recipe set must cover exactly the fixture corpus"
    );

    for fixture in &fixtures {
        let recipe = recipe_from_params(&parameters_from_aggregate(&fixture.aggregate));
        let actual = serde_json::to_value(&recipe).expect("serialize recipe");
        assert_eq!(
            actual, golden[&fixture.id],
            "recipe for fixture `{}` diverged from the committed artifact",
            fixture.id
        );
    }
}

/// Raster layer, parity against the designated-reference goldens:
/// RGB-RMS ≤ θ on decoded pixels for every fixture.
///
/// On the reference platform this is a regression pin (RMS is 0 by
/// construction — same code, same toolchain). The *parity measurement*
/// exists only when a different platform runs this test; that is why the
/// RMS is printed per fixture rather than only asserted — the printed
/// numbers from the floor-device run are the first cross-platform
/// measurement, and they get recorded in the spec § dated, whatever they
/// are. A run exceeding θ is a finding to adjudicate, not a dial to turn.
#[test]
fn raster_parity_within_theta_of_goldens() {
    for fixture in corpus() {
        let golden_path = goldens_dir().join(format!("{}_{}.png", fixture.id, GOLDEN_SIZE));
        let golden_bytes = std::fs::read(&golden_path).expect("committed golden png");
        let (gw, gh, golden_px) = decode_rgb8(&format!("golden {}", fixture.id), &golden_bytes);
        assert_eq!((gw, gh), (GOLDEN_SIZE, GOLDEN_SIZE), "golden dimensions");

        let params = parameters_from_aggregate(&fixture.aggregate);
        let rendered = render_candidate_png_from_params(&params, GOLDEN_SIZE).expect("render");
        let (rw, rh, rendered_px) = decode_rgb8(&format!("rendered {}", fixture.id), &rendered);
        assert_eq!((rw, rh), (gw, gh), "rendered dimensions match golden");

        let rms = rgb_rms(&golden_px, &rendered_px);
        println!("raster-parity {}: RMS = {rms:.6}", fixture.id);
        assert!(
            rms <= THETA,
            "fixture `{}` raster RMS {rms:.6} exceeds pre-registered θ = {THETA} — \
             a finding for the spec §, amended with this measurement attached",
            fixture.id
        );
    }
}

/// Sensitivity avalanche — both limbs, as ratified.
///
/// Limb 1 (the assertion): flipping one bit of the shard hash moves the
/// **decoded pixels** by RGB-RMS ≥ 20. The axis matters: a recipe-level
/// check here would be vacuous — SHAKE256 avalanches the recipe whether or
/// not the pixels listen to it, so a recipe assertion passes against a
/// renderer that ignores its input entirely. Only a pixel assertion fails
/// against that renderer (identical images, RMS 0).
///
/// Limb 2 (the falsification direction): if any two adjacent hashes ever
/// render near-identical pictures, the sensitivity property is falsified —
/// so the assertion is quantified over every fixture × several bit
/// positions spread across the hash, not demonstrated on one lucky pair. A
/// single pair passing is a demonstration; the quantified sweep is the
/// test.
#[test]
fn avalanche_bit_flip_moves_pixels_by_floor() {
    // (byte, bit) positions spread across the 32-byte hash: first byte,
    // interior, last byte.
    const FLIPS: [(usize, u8); 3] = [(0, 0), (15, 3), (31, 7)];

    let mut min_rms = f64::INFINITY;
    let mut min_case = String::new();
    for fixture in corpus() {
        let base_png = render_candidate_png_from_params(
            &parameters_from_aggregate(&fixture.aggregate),
            AVALANCHE_SIZE,
        )
        .expect("render base");
        let (_, _, base_px) = decode_rgb8(&format!("avalanche base {}", fixture.id), &base_png);

        for (byte, bit) in FLIPS {
            let mut flipped = fixture.aggregate.clone();
            flipped.shard_hash[byte] ^= 1 << bit;
            let flipped_png = render_candidate_png_from_params(
                &parameters_from_aggregate(&flipped),
                AVALANCHE_SIZE,
            )
            .expect("render flipped");
            let (_, _, flipped_px) = decode_rgb8(
                &format!("avalanche flipped {} byte {byte} bit {bit}", fixture.id),
                &flipped_png,
            );

            let rms = rgb_rms(&base_px, &flipped_px);
            if rms < min_rms {
                min_rms = rms;
                min_case = format!("{} byte {byte} bit {bit}", fixture.id);
            }
            assert!(
                rms >= AVALANCHE_FLOOR,
                "fixture `{}` hash bit flip (byte {byte}, bit {bit}) moved pixels by \
                 RMS {rms:.3} < pre-registered floor {AVALANCHE_FLOOR} — adjacent hashes \
                 rendering near-identical pictures falsifies the sensitivity property",
                fixture.id
            );
        }
    }
    println!("avalanche minimum over sweep: RMS = {min_rms:.3} ({min_case})");
}
