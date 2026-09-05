use shekyl_shard_visual::fixtures;
use shekyl_shard_visual::{
    features_from_aggregate, parameters_from_aggregate, parameters_with_hash_override,
    recipe_from_params, render_candidate_png, render_candidate_png_from_params, VisualError,
    MAX_RENDER_SIZE,
};

#[test]
fn genesis_fixture_renders_png() {
    let fixture = fixtures::by_id("genesis").expect("genesis fixture");
    let png = render_candidate_png(&fixture.aggregate, 64).expect("png");
    assert!(png.starts_with(b"\x89PNG"));
    assert!(png.len() > 500);
}

#[test]
fn render_rejects_zero_size() {
    let fixture = fixtures::by_id("genesis").expect("genesis fixture");
    assert!(matches!(
        render_candidate_png(&fixture.aggregate, 0),
        Err(VisualError::InvalidSize { size: 0, .. })
    ));
}

#[test]
fn render_rejects_oversized() {
    let fixture = fixtures::by_id("genesis").expect("genesis fixture");
    let too_big = MAX_RENDER_SIZE.saturating_add(1);
    assert!(matches!(
        render_candidate_png(&fixture.aggregate, too_big),
        Err(VisualError::InvalidSize { size, .. }) if size == too_big
    ));
}

#[test]
fn recipe_is_deterministic_for_genesis() {
    let fixture = fixtures::by_id("genesis").expect("genesis fixture");
    let params = parameters_from_aggregate(&fixture.aggregate);
    let a = recipe_from_params(&params);
    let b = recipe_from_params(&params);
    assert_eq!(a, b);
    assert_eq!(a.fg_tile, "aperiodic_tile");
    assert_eq!(a.bg_truchet, "truchet");
    assert_eq!(a.final_mode, "difference");
}

#[test]
fn all_fixtures_render_at_preview_size() {
    for fixture in fixtures::all() {
        let png = render_candidate_png(&fixture.aggregate, 128).expect(&fixture.id);
        assert!(png.starts_with(b"\x89PNG"), "{}", fixture.id);
    }
}

#[test]
fn canonical_flag_tracks_input_provenance() {
    let fixture = fixtures::by_id("genesis").expect("genesis fixture");
    let canonical = parameters_from_aggregate(&fixture.aggregate);
    assert!(recipe_from_params(&canonical).canonical);

    let overridden = parameters_with_hash_override(&fixture.aggregate, [0xAB; 32]);
    assert!(!recipe_from_params(&overridden).canonical);

    let mut tweaked = parameters_from_aggregate(&fixture.aggregate);
    tweaked.push_structural_override("candidate_fg_opacity", "0.5");
    assert!(!recipe_from_params(&tweaked).canonical);
}

/// Golden recipe for the genesis fixture — the cross-implementation
/// derivation pin. The Python explorer pins the SAME literals
/// (`shekyl-dev/visualization/tests/test_candidate.py`), so a change
/// that breaks Rust/Python recipe parity breaks one of the two pins.
/// Pixel-level parity is ruling B's oracle; this pins the derivation.
#[test]
// Opacities are quantized to a 2-decimal grid at derivation time, so exact
// equality is the pin's contract: any drift, however small, must fail.
#[allow(clippy::float_cmp)]
fn genesis_recipe_matches_the_cross_implementation_pin() {
    let fixture = fixtures::by_id("genesis").expect("genesis fixture");
    let r = recipe_from_params(&parameters_from_aggregate(&fixture.aggregate));
    assert_eq!(r.spec_version, "candidate.v1");
    assert_eq!(r.fg_opacity, 0.26);
    assert_eq!(r.fg_tile_palette, "neon");
    assert_eq!(r.fg_phyllotaxis_palette, "earth");
    assert_eq!(r.bg_opacity, 0.65);
    assert_eq!(r.bg_truchet_palette, "prismatic");
    assert_eq!(r.bg_crystalline_palette, "earth");
    assert_eq!(r.final_opacity, 0.71);
}

#[test]
// Exact zero is the contract for the degenerate fallback, not a computed
// float — see the KAT's allow above.
#[allow(clippy::float_cmp)]
fn zero_output_aggregate_saturates_features_to_zero() {
    let mut agg = fixtures::by_id("genesis")
        .expect("genesis fixture")
        .aggregate;
    agg.tx_count = 0;
    agg.output_count = 0;
    agg.coinbase_output_count = 0;
    let f = features_from_aggregate(&agg);
    assert_eq!(f.output_richness, 0.0);
    // Degenerate synthetic input must not read as maximally
    // coinbase-heavy (review #617).
    assert_eq!(f.coinbase_ratio, 0.0);
}

/// The PNG bytes themselves carry provenance (`tEXt` chunks), so a saved
/// file stays self-describing without its recipe — the "visibly
/// non-canonical export" enforcement from ruling A (review #617).
#[test]
fn png_bytes_carry_provenance_chunks() {
    fn text_chunks(png_bytes: &[u8]) -> Vec<(String, String)> {
        let decoder = png::Decoder::new(std::io::Cursor::new(png_bytes));
        let reader = decoder.read_info().expect("readable png");
        reader
            .info()
            .uncompressed_latin1_text
            .iter()
            .map(|t| (t.keyword.clone(), t.text.clone()))
            .collect()
    }
    let fixture = fixtures::by_id("genesis").expect("genesis fixture");

    let canonical_png = render_candidate_png(&fixture.aggregate, 64).expect("png");
    let chunks = text_chunks(&canonical_png);
    assert!(chunks.contains(&("shekyl.spec_version".into(), "candidate.v1".into())));
    assert!(chunks.contains(&("shekyl.canonical".into(), "true".into())));

    let overridden = parameters_with_hash_override(&fixture.aggregate, [0xAB; 32]);
    let overridden_png = render_candidate_png_from_params(&overridden, 64).expect("png");
    let chunks = text_chunks(&overridden_png);
    assert!(chunks.contains(&("shekyl.canonical".into(), "false".into())));
}
