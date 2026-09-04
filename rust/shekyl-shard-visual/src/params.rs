use crate::aggregate::ShardAggregate;
use crate::entropy::EntropyStream;
use crate::features::{features_from_aggregate, Features};
use crate::palette::{palette_by_index, Palette};

/// The complete deterministic input bundle a renderer consumes.
///
/// Fields are crate-private so provenance is unforgeable from outside
/// (review #617): `canonical` is decided by the constructor that built
/// the bundle and no public path can flip it back or swap a
/// render-determining input afterward. The only public mutation is
/// [`RenderParameters::push_structural_override`], which can only
/// *weaken* the claim (an override makes the render non-canonical in
/// [`crate::recipe_from_params`], never the reverse).
pub struct RenderParameters {
    pub(crate) shard_hash: [u8; 32],
    pub(crate) features: Features,
    pub(crate) palette: Palette,
    pub(crate) algorithm: &'static str,
    pub(crate) label: String,
    pub(crate) structural_overrides: Vec<(String, String)>,
    /// `true` only when every input came from the shard's own aggregate.
    /// A hash override or synthetic feature vector makes the render a
    /// viewer-chosen artifact, not chain state; the flag flows into
    /// [`crate::CandidateRecipe`] and the PNG's provenance chunks so
    /// exports stay visibly non-canonical (ruling A,
    /// `docs/V3_SHARD_VISUALIZATION.md`).
    pub(crate) canonical: bool,
}

impl RenderParameters {
    pub fn entropy(&self, namespace: &str) -> EntropyStream {
        EntropyStream::new(self.shard_hash, namespace)
    }

    pub fn override_value(&self, axis: &str) -> Option<&str> {
        self.structural_overrides
            .iter()
            .find(|(k, _)| k == axis)
            .map(|(_, v)| v.as_str())
    }

    /// Whether every input came from the shard's own aggregate with no
    /// overrides applied.
    #[must_use]
    pub fn is_canonical(&self) -> bool {
        self.canonical && self.structural_overrides.is_empty()
    }

    /// Human-facing label for this render.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Apply a tweak-view structural override. Add-only by design: an
    /// override can make a render non-canonical but nothing public can
    /// clear the set or restore the canonical claim.
    pub fn push_structural_override(&mut self, axis: impl Into<String>, value: impl Into<String>) {
        self.structural_overrides.push((axis.into(), value.into()));
    }

    pub(crate) fn with_palette(&self, palette: Palette) -> Self {
        Self {
            palette,
            ..self.clone_fields()
        }
    }

    fn clone_fields(&self) -> Self {
        Self {
            shard_hash: self.shard_hash,
            features: self.features,
            palette: self.palette,
            algorithm: self.algorithm,
            label: self.label.clone(),
            structural_overrides: self.structural_overrides.clone(),
            canonical: self.canonical,
        }
    }
}

const ALGORITHM_BUCKET_TABLE: [&str; 8] = [
    "mandelbrot",
    "julia",
    "voronoi",
    "voronoi",
    "attractor",
    "phyllotaxis",
    "lsystem",
    "flow_field",
];

pub fn assign_algorithm(shard_hash: [u8; 32]) -> &'static str {
    ALGORITHM_BUCKET_TABLE[(shard_hash[0] & 0b111) as usize]
}

pub fn assign_palette(shard_hash: [u8; 32]) -> Palette {
    palette_by_index((shard_hash[0] >> 3) as u32 & 0b111)
}

pub fn parameters_from_aggregate(agg: &ShardAggregate) -> RenderParameters {
    let features = features_from_aggregate(agg);
    RenderParameters {
        shard_hash: agg.shard_hash,
        features,
        palette: assign_palette(agg.shard_hash),
        algorithm: assign_algorithm(agg.shard_hash),
        label: format!("shard #{}", agg.shard_id),
        structural_overrides: Vec::new(),
        canonical: true,
    }
}

pub fn parameters_from_synthetic(shard_hash: [u8; 32], features: Features) -> RenderParameters {
    RenderParameters {
        shard_hash,
        features,
        palette: assign_palette(shard_hash),
        algorithm: assign_algorithm(shard_hash),
        label: "synthetic".into(),
        structural_overrides: Vec::new(),
        canonical: false,
    }
}

pub fn parameters_with_hash_override(
    agg: &ShardAggregate,
    hash_override: [u8; 32],
) -> RenderParameters {
    let mut params = parameters_from_aggregate(agg);
    params.shard_hash = hash_override;
    params.palette = assign_palette(hash_override);
    params.algorithm = assign_algorithm(hash_override);
    params.canonical = false;
    params
}
