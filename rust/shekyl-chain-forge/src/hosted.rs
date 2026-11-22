// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A hosted chain's pin, and the check a fetched copy passes before
//! anything reads it (`CHAIN_FORGE.md` §10.4, `CF-R11`).
//!
//! A chain whose bytes are over the storage line (`CF-R6`, 5 MB) is not
//! committed. Its corpus, trace and manifest are the layers of an OCI
//! artifact on GHCR, and this repository commits only the **pin file**
//! (`chains/hosted.toml`): for each chain, the artifact's digest, the
//! commit it was forged at, and each layer's file name, media type, size
//! and SHA-256. The pin is the only source of truth: a copy whose layer
//! differs in one byte is refused, whoever published it, so nothing in the
//! hosting repository can change what this one accepts.
//!
//! `scripts/ci/fetch_test_chain.py` pulls a chain by digest into
//! [`fetched_dir`] and checks every layer against the pin. [`open`] checks
//! them again before a test reads them, so a stale or damaged local copy is
//! refused by name, never read. A missing copy is a failure that names the
//! fetch command and the forge command that rebuilds it at the pinned
//! commit, never a skip: the hosted copy is a cache (`CF-R6`), and a test
//! that skipped on a missing cache would pass without its subject.

use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::manifest::{Manifest, ManifestFault};

/// The pin file, under this crate's directory.
pub const PIN_FILE: &str = "chains/hosted.toml";

/// The OCI artifact type every hosted chain carries.
pub const ARTIFACT_TYPE: &str = "application/vnd.shekyl.test-chain";

/// The corpus layer's media type: layout 5 (`shekyl-corpus`'s
/// `CORPUS_FORMAT_VERSION`). A layout change bumps it with the constant
/// (rule 42's discipline applied to the artifact); the determinism test
/// holds the two together.
pub const CORPUS_MEDIA_TYPE: &str = "application/vnd.shekyl.corpus.v5";

/// The trace layer's media type: trace version 2 (`TRACE_VERSION`).
pub const TRACE_MEDIA_TYPE: &str = "application/vnd.shekyl.trace.v2";

/// The manifest layer's media type: format 6 ([`MANIFEST_FORMAT_VERSION`]).
///
/// [`MANIFEST_FORMAT_VERSION`]: crate::manifest::MANIFEST_FORMAT_VERSION
pub const MANIFEST_MEDIA_TYPE: &str = "application/vnd.shekyl.manifest.v6+json";

/// The three layers, by file name, in the order an artifact lists them.
pub const LAYERS: [(&str, &str); 3] = [
    (CORPUS_FILE, CORPUS_MEDIA_TYPE),
    (TRACE_FILE, TRACE_MEDIA_TYPE),
    (MANIFEST_FILE, MANIFEST_MEDIA_TYPE),
];

/// The corpus layer's file name.
pub const CORPUS_FILE: &str = "corpus.e2";
/// The trace layer's file name.
pub const TRACE_FILE: &str = "trace.e2";
/// The manifest layer's file name.
pub const MANIFEST_FILE: &str = "manifest.json";

/// The fetch command, run from the repository's root.
pub const FETCH_COMMAND: &str = "python3 scripts/ci/fetch_test_chain.py";

/// What refuses a pin file or a fetched chain.
#[derive(Debug, thiserror::Error)]
pub enum HostedFault {
    /// The pin file could not be read.
    #[error("the pin file {path}: {source}")]
    Read {
        /// The pin file.
        path: PathBuf,
        /// The read's error.
        source: io::Error,
    },
    /// The pin file is not TOML of this shape.
    #[error("the pin file: {0}")]
    Toml(#[from] toml::de::Error),
    /// The pin file parses, and a value in it is not well formed.
    #[error("the pin file: {0}")]
    Invalid(String),
    /// The chain has no pin.
    #[error("no hosted chain `{0}` is pinned in {PIN_FILE}")]
    NotPinned(String),
    /// A layer's file is not in the fetched directory.
    #[error(transparent)]
    Missing(Box<MissingLayer>),
    /// A layer's file differs from its pin.
    #[error(transparent)]
    Mismatch(Box<LayerMismatch>),
    /// A layer's file could not be read.
    #[error("the hosted chain's {path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// The read's error.
        source: io::Error,
    },
    /// The fetched manifest does not parse.
    #[error("the hosted chain's manifest: {0}")]
    Manifest(#[from] ManifestFault),
}

/// A pinned layer that is not in the fetched directory.
#[derive(Debug, thiserror::Error)]
#[error(
    "the hosted chain `{chain}` is not fetched: {path} is missing. Fetch it with \
     `{FETCH_COMMAND} {chain}`, or, from the repository root, rebuild it at the pinned \
     commit {commit} with `git checkout {commit} && cargo run --manifest-path rust/Cargo.toml \
     --locked --release -p shekyl-chain-forge --example forge -- --plan {plan} --out {dir} \
     && rm -f {dir}/blocks.txt` (CHAIN_FORGE.md §10.4). The forge writes blocks.txt beside \
     the layers; the pin check reads only the layers"
)]
pub struct MissingLayer {
    /// The chain.
    pub chain: String,
    /// The missing file.
    pub path: PathBuf,
    /// The commit the pin was forged at.
    pub commit: String,
    /// The chain's plan.
    pub plan: String,
    /// The fetched directory.
    pub dir: PathBuf,
}

/// A fetched layer whose size or SHA-256 is not its pin's.
#[derive(Debug, thiserror::Error)]
#[error(
    "the hosted chain `{chain}`: {file} is {found_size} bytes with SHA-256 {found_sha256}, \
     and the pin says {size} bytes with SHA-256 {sha256}. Delete {dir} and fetch it again \
     with `{FETCH_COMMAND} {chain}`"
)]
pub struct LayerMismatch {
    /// The chain.
    pub chain: String,
    /// The layer's file.
    pub file: String,
    /// Its size.
    pub found_size: u64,
    /// Its SHA-256.
    pub found_sha256: String,
    /// The pinned size.
    pub size: u64,
    /// The pinned SHA-256.
    pub sha256: String,
    /// The fetched directory.
    pub dir: PathBuf,
}

/// The pin file.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Pins {
    /// The `oras` release the fetch and the publishing workflow install.
    pub oras: OrasPin,
    /// Every hosted chain.
    #[serde(default)]
    pub chain: Vec<HostedChain>,
}

/// The `oras` release, pinned by version and by each platform's archive
/// checksum (`CF-R11`, rule 17).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OrasPin {
    /// The release, `X.Y.Z`.
    pub version: String,
    /// Each archive's SHA-256, by `<os>_<arch>` as the release names it.
    pub sha256: std::collections::BTreeMap<String, String>,
}

/// One hosted chain at one version.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostedChain {
    /// The chain's name: its plan's `chain`, and the package's last path
    /// segment.
    pub name: String,
    /// The plan, from the repository's root.
    pub plan: String,
    /// The commit the artifact was forged at (40 hex digits).
    pub commit: String,
    /// The artifact's `org.opencontainers.image.created`: the commit's
    /// committer time, so that publishing the same commit again gives the
    /// same digest.
    pub created: String,
    /// The repository the artifact is in, without a tag or digest.
    pub reference: String,
    /// The OCI manifest's digest, `sha256:<64 hex>`.
    pub digest: String,
    /// Each layer, in the artifact's order.
    pub layer: Vec<Layer>,
}

/// One layer of a hosted chain.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Layer {
    /// The file the layer is pulled to.
    pub file: String,
    /// Its media type.
    pub media_type: String,
    /// Its size in bytes.
    pub size: u64,
    /// Its SHA-256, 64 hex digits.
    pub sha256: String,
}

impl Pins {
    /// The committed pin file.
    ///
    /// # Errors
    ///
    /// [`HostedFault`].
    pub fn load() -> Result<Self, HostedFault> {
        let path = crate_dir().join(PIN_FILE);
        let text = std::fs::read_to_string(&path).map_err(|source| HostedFault::Read {
            path: path.clone(),
            source,
        })?;
        Self::parse(&text)
    }

    /// A pin file from its text, every value checked for form.
    ///
    /// # Errors
    ///
    /// [`HostedFault`].
    pub fn parse(text: &str) -> Result<Self, HostedFault> {
        let pins: Self = toml::from_str(text)?;
        pins.check()?;
        Ok(pins)
    }

    /// The pin of the chain named `name`.
    ///
    /// # Errors
    ///
    /// [`HostedFault::NotPinned`].
    pub fn chain(&self, name: &str) -> Result<&HostedChain, HostedFault> {
        self.chain
            .iter()
            .find(|chain| chain.name == name)
            .ok_or_else(|| HostedFault::NotPinned(name.to_owned()))
    }

    fn check(&self) -> Result<(), HostedFault> {
        let bad = |what: String| Err(HostedFault::Invalid(what));
        let version = &self.oras.version;
        if version.split('.').count() != 3
            || !version.split('.').all(|part| part.parse::<u32>().is_ok())
        {
            return bad(format!("oras version `{version}` is not X.Y.Z"));
        }
        if self.oras.sha256.is_empty() {
            return bad("oras pins no archive checksum".into());
        }
        for (platform, sum) in &self.oras.sha256 {
            if !is_hex(sum, 64) {
                return bad(format!(
                    "oras {platform}'s checksum `{sum}` is not 64 hex digits"
                ));
            }
        }
        let mut names = std::collections::BTreeSet::new();
        for chain in &self.chain {
            let name = &chain.name;
            if !names.insert(name.as_str()) {
                return bad(format!("chain `{name}` is pinned twice"));
            }
            if !is_hex(&chain.commit, 40) {
                return bad(format!("chain `{name}`'s commit is not 40 hex digits"));
            }
            match chain.digest.strip_prefix("sha256:") {
                Some(hex) if is_hex(hex, 64) => {}
                _ => return bad(format!("chain `{name}`'s digest is not sha256:<64 hex>")),
            }
            if !chain.reference.ends_with(&format!("/{name}")) {
                return bad(format!(
                    "chain `{name}`'s reference `{}` does not end in its name",
                    chain.reference
                ));
            }
            let files: Vec<(&str, &str)> = chain
                .layer
                .iter()
                .map(|layer| (layer.file.as_str(), layer.media_type.as_str()))
                .collect();
            if files != LAYERS {
                return bad(format!(
                    "chain `{name}`'s layers are {files:?}, and a hosted chain's are {LAYERS:?}"
                ));
            }
            for layer in &chain.layer {
                if !is_hex(&layer.sha256, 64) {
                    return bad(format!(
                        "chain `{name}`'s {} SHA-256 is not 64 hex digits",
                        layer.file
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Where a hosted chain is fetched to: `chains/<chain>/hosted/` under this
/// crate (ignored by git).
#[must_use]
pub fn fetched_dir(chain: &str) -> PathBuf {
    crate_dir().join("chains").join(chain).join("hosted")
}

/// A fetched chain whose every layer matched its pin.
#[derive(Clone, Debug)]
pub struct Fetched {
    dir: PathBuf,
    pin: HostedChain,
}

impl Fetched {
    /// The pin the copy matched.
    #[must_use]
    pub const fn pin(&self) -> &HostedChain {
        &self.pin
    }

    /// The corpus's path.
    #[must_use]
    pub fn corpus(&self) -> PathBuf {
        self.dir.join(CORPUS_FILE)
    }

    /// The trace's path.
    #[must_use]
    pub fn trace(&self) -> PathBuf {
        self.dir.join(TRACE_FILE)
    }

    /// The manifest, parsed.
    ///
    /// # Errors
    ///
    /// [`HostedFault`].
    pub fn manifest(&self) -> Result<Manifest, HostedFault> {
        let path = self.dir.join(MANIFEST_FILE);
        let text = std::fs::read_to_string(&path).map_err(|source| HostedFault::Io {
            path: path.clone(),
            source,
        })?;
        Ok(Manifest::parse(&text)?)
    }
}

/// The hosted chain `chain`, fetched and checked against the committed pin.
///
/// # Errors
///
/// [`HostedFault`]: not pinned, a layer missing (naming the fetch and the
/// forge commands), or a layer whose size or SHA-256 is not its pin's.
pub fn open(chain: &str) -> Result<Fetched, HostedFault> {
    let pins = Pins::load()?;
    let pin = pins.chain(chain)?.clone();
    open_in(&fetched_dir(chain), pin)
}

/// [`open`] over `dir`.
///
/// # Errors
///
/// As [`open`].
pub fn open_in(dir: &Path, pin: HostedChain) -> Result<Fetched, HostedFault> {
    for layer in &pin.layer {
        let path = dir.join(&layer.file);
        if !path.is_file() {
            return Err(HostedFault::Missing(Box::new(MissingLayer {
                chain: pin.name.clone(),
                path,
                commit: pin.commit.clone(),
                plan: pin.plan.clone(),
                dir: dir.to_path_buf(),
            })));
        }
        let (found_size, found_sha256) =
            file_sha256(&path).map_err(|source| HostedFault::Io { path, source })?;
        if found_size != layer.size || found_sha256 != layer.sha256 {
            return Err(HostedFault::Mismatch(Box::new(LayerMismatch {
                chain: pin.name.clone(),
                file: layer.file.clone(),
                found_size,
                found_sha256,
                size: layer.size,
                sha256: layer.sha256.clone(),
                dir: dir.to_path_buf(),
            })));
        }
    }
    Ok(Fetched {
        dir: dir.to_path_buf(),
        pin,
    })
}

/// A file's size and lowercase-hex SHA-256, read in pieces.
///
/// # Errors
///
/// The read's.
pub fn file_sha256(path: &Path) -> io::Result<(u64, String)> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut size = 0u64;
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
        size += u64::try_from(read).expect("a read fits u64");
    }
    Ok((size, hex::encode(hasher.finalize())))
}

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn is_hex(text: &str, len: usize) -> bool {
    text.len() == len
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZEROS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn pin_text(chains: &str) -> String {
        format!("[oras]\nversion = \"1.3.6\"\nsha256 = {{ linux_amd64 = \"{ZEROS}\" }}\n{chains}")
    }

    fn chain_text(name: &str, corpus: (u64, &str)) -> String {
        format!(
            "[[chain]]\nname = \"{name}\"\nplan = \"rust/shekyl-chain-forge/plans/{name}.toml\"\n\
             commit = \"{}\"\ncreated = \"2026-11-18T00:00:00Z\"\n\
             reference = \"ghcr.io/shekyl-foundation/test-chains/{name}\"\ndigest = \"sha256:{ZEROS}\"\n\
             [[chain.layer]]\nfile = \"corpus.e2\"\nmedia_type = \"{CORPUS_MEDIA_TYPE}\"\nsize = {}\nsha256 = \"{}\"\n\
             [[chain.layer]]\nfile = \"trace.e2\"\nmedia_type = \"{TRACE_MEDIA_TYPE}\"\nsize = 1\nsha256 = \"{ZEROS}\"\n\
             [[chain.layer]]\nfile = \"manifest.json\"\nmedia_type = \"{MANIFEST_MEDIA_TYPE}\"\nsize = 1\nsha256 = \"{ZEROS}\"\n",
            "a".repeat(40),
            corpus.0,
            corpus.1,
        )
    }

    #[test]
    fn the_committed_pin_file_parses() {
        Pins::load().expect("the committed pin file is well formed");
    }

    #[test]
    fn the_manifest_media_type_names_the_manifest_format() {
        assert!(MANIFEST_MEDIA_TYPE
            .contains(&format!(".v{}+", crate::manifest::MANIFEST_FORMAT_VERSION)));
    }

    #[test]
    fn a_malformed_pin_is_refused_by_name() {
        assert!(
            Pins::parse(&pin_text("")).is_ok(),
            "no chains is a pin file"
        );
        let good = chain_text("c", (1, ZEROS));
        assert!(Pins::parse(&pin_text(&good)).is_ok());
        for (bad, why) in [
            (good.replace(&"a".repeat(40), "abc"), "commit"),
            (good.replace("sha256:", "sha512:"), "digest"),
            (
                good.replace("test-chains/c\"", "test-chains/d\""),
                "reference",
            ),
            (good.replace("trace.e2", "trace.bin"), "layers"),
            (format!("{good}{good}"), "twice"),
            (
                good.replace("size = 1\n", "size = 1\nextra = 2\n"),
                "unknown",
            ),
        ] {
            let refused = Pins::parse(&pin_text(&bad)).expect_err(why).to_string();
            assert!(refused.contains(why), "{why}: {refused}");
        }
    }

    #[test]
    fn a_fetched_layer_one_byte_off_is_refused_and_a_missing_one_names_the_fetch() {
        let dir = tempfile::tempdir().expect("a scratch directory");
        let corpus = b"corpus bytes".to_vec();
        std::fs::write(dir.path().join(CORPUS_FILE), &corpus).expect("written");
        std::fs::write(dir.path().join(TRACE_FILE), b"t").expect("written");
        std::fs::write(dir.path().join(MANIFEST_FILE), b"m").expect("written");
        let (size, sha) = file_sha256(&dir.path().join(CORPUS_FILE)).expect("hashed");
        let one = |file: &str| file_sha256(&dir.path().join(file)).expect("hashed").1;
        let mut pins = Pins::parse(&pin_text(&chain_text("c", (size, &sha)))).expect("parses");
        let mut pin = pins.chain.remove(0);
        pin.layer[1].sha256 = one(TRACE_FILE);
        pin.layer[2].sha256 = one(MANIFEST_FILE);
        open_in(dir.path(), pin.clone()).expect("every layer matches its pin");

        let mut flipped = corpus.clone();
        flipped[0] ^= 1;
        std::fs::write(dir.path().join(CORPUS_FILE), &flipped).expect("written");
        let refused = open_in(dir.path(), pin.clone()).expect_err("one byte off is refused");
        assert!(
            matches!(&refused, HostedFault::Mismatch(mismatch) if mismatch.file == CORPUS_FILE),
            "{refused}"
        );

        std::fs::remove_file(dir.path().join(CORPUS_FILE)).expect("removed");
        let missing = open_in(dir.path(), pin).expect_err("a missing layer is refused");
        let text = missing.to_string();
        assert!(
            text.contains(FETCH_COMMAND)
                && text.contains("--manifest-path rust/Cargo.toml")
                && text.contains("--example forge")
                && text.contains("rm -f")
                && text.contains("blocks.txt"),
            "{text}"
        );
    }
}
