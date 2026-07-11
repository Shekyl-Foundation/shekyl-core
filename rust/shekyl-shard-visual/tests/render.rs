use shekyl_shard_visual::fixtures;
use shekyl_shard_visual::{
    parameters_from_aggregate, recipe_from_params, render_candidate_png, VisualError,
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
