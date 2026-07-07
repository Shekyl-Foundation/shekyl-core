use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

const DOMAIN_SEP: u8 = 0x01;
const WORD_BYTES: usize = 4;
const INITIAL_BUFFER: usize = 64;

/// SHAKE256-derived deterministic entropy stream, namespaced per axis.
pub struct EntropyStream {
    shard_hash: [u8; 32],
    namespace: String,
    buf: Vec<u8>,
}

impl EntropyStream {
    pub fn new(shard_hash: [u8; 32], namespace: &str) -> Self {
        assert!(!namespace.is_empty(), "namespace must be non-empty");
        Self {
            shard_hash,
            namespace: namespace.to_owned(),
            buf: Vec::new(),
        }
    }

    fn ensure(&mut self, n_bytes: usize) {
        if self.buf.len() >= n_bytes {
            return;
        }
        let target = n_bytes.max(INITIAL_BUFFER.max(self.buf.len() * 2));
        let mut shake = Shake256::default();
        shake.update(&self.shard_hash);
        shake.update(&[DOMAIN_SEP]);
        shake.update(self.namespace.as_bytes());
        let mut reader = shake.finalize_xof();
        self.buf.resize(target, 0);
        reader.read(&mut self.buf);
    }

    pub fn uint32(&mut self, idx: u32) -> u32 {
        let idx = idx as usize;
        let offset = idx * WORD_BYTES;
        self.ensure(offset + WORD_BYTES);
        u32::from_le_bytes(
            self.buf[offset..offset + WORD_BYTES]
                .try_into()
                .expect("word slice"),
        )
    }

    pub fn unit(&mut self, idx: u32) -> f64 {
        self.uint32(idx) as f64 / (1u64 << 32) as f64
    }
}
