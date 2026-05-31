use crate::aggregate::ShardAggregate;
use crate::entropy::EntropyStream;
use crate::features::{features_from_aggregate, Features};
use crate::palette::{palette_by_index, Palette};

pub struct RenderParameters {
    pub shard_hash: [u8; 32],
    pub hash_words: [u32; 8],
    pub features: Features,
    pub palette: Palette,
    pub algorithm: &'static str,
    pub label: String,
    pub structural_overrides: Vec<(String, String)>,
}

impl RenderParameters {
    pub fn hash_unit(&self, idx: usize) -> f64 {
        self.hash_words[idx % 8] as f64 / (1u64 << 32) as f64
    }

    pub fn entropy(&self, namespace: &str) -> EntropyStream {
        EntropyStream::new(self.shard_hash, namespace)
    }

    pub fn override_value(&self, axis: &str) -> Option<&str> {
        self.structural_overrides
            .iter()
            .find(|(k, _)| k == axis)
            .map(|(_, v)| v.as_str())
    }

    pub fn with_palette(&self, palette: Palette) -> Self {
        Self {
            palette,
            ..self.clone_fields()
        }
    }

    pub fn with_algorithm(&self, algorithm: &'static str) -> Self {
        Self {
            algorithm,
            ..self.clone_fields()
        }
    }

    fn clone_fields(&self) -> Self {
        Self {
            shard_hash: self.shard_hash,
            hash_words: self.hash_words,
            features: self.features,
            palette: self.palette,
            algorithm: self.algorithm,
            label: self.label.clone(),
            structural_overrides: self.structural_overrides.clone(),
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

fn hash_words(shard_hash: [u8; 32]) -> [u32; 8] {
    let mut words = [0u32; 8];
    for (i, chunk) in shard_hash.chunks_exact(4).enumerate().take(8) {
        words[i] = u32::from_le_bytes(chunk.try_into().expect("chunk"));
    }
    words
}

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
        hash_words: hash_words(agg.shard_hash),
        features,
        palette: assign_palette(agg.shard_hash),
        algorithm: assign_algorithm(agg.shard_hash),
        label: format!("shard #{} ({})", agg.shard_id, agg.dominant_regime),
        structural_overrides: Vec::new(),
    }
}

pub fn parameters_from_synthetic(shard_hash: [u8; 32], features: Features) -> RenderParameters {
    RenderParameters {
        shard_hash,
        hash_words: hash_words(shard_hash),
        features,
        palette: assign_palette(shard_hash),
        algorithm: assign_algorithm(shard_hash),
        label: "synthetic".into(),
        structural_overrides: Vec::new(),
    }
}

pub fn parameters_with_hash_override(
    agg: &ShardAggregate,
    hash_override: [u8; 32],
) -> RenderParameters {
    let mut params = parameters_from_aggregate(agg);
    params.shard_hash = hash_override;
    params.hash_words = hash_words(hash_override);
    params.palette = assign_palette(hash_override);
    params.algorithm = assign_algorithm(hash_override);
    params
}
