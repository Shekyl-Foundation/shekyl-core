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

fn goldens_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/goldens")
}

/// Decode PNG bytes to raw RGB8 pixels. **The comparison axis is decoded
/// pixels, never PNG file bytes** (spec: bytes go through the encoder's
/// compression, filtering, and the ruling-A provenance chunks — a byte
/// comparison would measure the compressor, not the picture).
fn decode_rgb8(png_bytes: &[u8]) -> (u32, u32, Vec<u8>) {
    let decoder = png::Decoder::new(Cursor::new(png_bytes));
    let mut reader = decoder.read_info().expect("png header");
    let mut buf = vec![0u8; reader.output_buffer_size().expect("png buffer size")];
    let info = reader.next_frame(&mut buf).expect("png frame");
    assert_eq!(info.color_type, png::ColorType::Rgb, "goldens are RGB8");
    assert_eq!(info.bit_depth, png::BitDepth::Eight, "goldens are RGB8");
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

    let fixtures = fixtures::all();
    // Id-set equality in both directions: a fixture added without a golden
    // recipe, or a golden orphaned by a removed fixture, is a failure — a
    // one-directional check lets the artifact and the corpus drift apart.
    let golden_ids: Vec<&str> = golden
        .keys()
        .filter(|k| *k != "_reference_run")
        .map(String::as_str)
        .collect();
    let mut fixture_ids: Vec<&str> = fixtures.iter().map(|f| f.id.as_str()).collect();
    fixture_ids.sort_unstable(); // golden keys iterate sorted (BTreeMap)
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
    for fixture in fixtures::all() {
        let golden_path = goldens_dir().join(format!("{}_{}.png", fixture.id, GOLDEN_SIZE));
        let golden_bytes = std::fs::read(&golden_path).expect("committed golden png");
        let (gw, gh, golden_px) = decode_rgb8(&golden_bytes);
        assert_eq!((gw, gh), (GOLDEN_SIZE, GOLDEN_SIZE), "golden dimensions");

        let params = parameters_from_aggregate(&fixture.aggregate);
        let rendered = render_candidate_png_from_params(&params, GOLDEN_SIZE).expect("render");
        let (rw, rh, rendered_px) = decode_rgb8(&rendered);
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
    for fixture in fixtures::all() {
        let base_png =
            render_candidate_png_from_params(&parameters_from_aggregate(&fixture.aggregate), 128)
                .expect("render base");
        let (_, _, base_px) = decode_rgb8(&base_png);

        for (byte, bit) in FLIPS {
            let mut flipped = fixture.aggregate.clone();
            flipped.shard_hash[byte] ^= 1 << bit;
            let flipped_png =
                render_candidate_png_from_params(&parameters_from_aggregate(&flipped), 128)
                    .expect("render flipped");
            let (_, _, flipped_px) = decode_rgb8(&flipped_png);

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
