// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The build identity the binaries print (DC-Q20): computed once here, read
//! by `rust/shekyl-version` through `option_env!`.
//!
//! - A commit with one release tag: the tag without its `v`, tagged
//!   `release`. A release tag matches [`RELEASE_TAG_GRAMMAR`] in full
//!   (the maintainer's ruling, 2026-11-23).
//! - A commit with two release tags: refused, since neither names it.
//! - Any other commit, whatever other tags it carries (`archive/…`,
//!   `core-v3.1.0`): the default version, tagged with the commit's first
//!   nine hex digits.
//! - No git work tree (a source archive): refused, unless the caller names
//!   the version with `--version-override`, which is a release and takes
//!   the same grammar without the `v`.

use std::path::Path;
use std::process::Command;

/// The one release-tag grammar. `docs/RELEASE_PROMOTION.md` §3 and
/// `scripts/release/check_staging_deadlines.py` carry this text verbatim
/// (`scripts/ci/check_release_tag_grammar.py`); [`release_version`] is its
/// std-only matcher, and `release_tags.tsv` holds the two to one answer.
pub const RELEASE_TAG_GRAMMAR: &str =
    r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.]+)?$";

/// The three values the binaries carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// `SHEKYL_VERSION_FULL`: `<version>-<tag>`.
    pub full: String,
    /// `SHEKYL_RELEASE_NAME`.
    pub release_name: String,
    /// `SHEKYL_VERSION_IS_RELEASE`: a tagged commit or a named version.
    pub is_release: bool,
}

impl Identity {
    /// The version in a release archive's name, from this identity and no
    /// other read of git: `v<version>` at a release, the binaries' own value
    /// otherwise. A value a file name cannot carry is refused.
    pub fn archive_version(&self) -> Result<String, String> {
        let name = match self.full.strip_suffix("-release") {
            Some(version) if self.is_release => format!("v{version}"),
            _ => self.full.clone(),
        };
        if name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        {
            Ok(name)
        } else {
            Err(format!("the version {name:?} cannot name an archive"))
        }
    }
}

/// What git says about HEAD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHead {
    /// `git rev-parse --short=9 HEAD`, cut to nine characters.
    pub commit: String,
    /// `git tag -l --points-at HEAD`, as printed.
    pub tags: String,
}

impl GitHead {
    /// Reads HEAD of the work tree at `root`.
    pub fn read(root: &Path) -> Result<Self, String> {
        let commit = git(root, &["rev-parse", "--short=9", "HEAD"])?;
        let commit: String = commit.chars().take(9).collect();
        if commit.len() != 9 || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("git rev-parse printed {commit:?}, not a commit"));
        }
        let tags = git(root, &["tag", "-l", "--points-at", "HEAD"])?;
        Ok(Self { commit, tags })
    }
}

/// The identity for HEAD. Two release tags on one commit are refused.
pub fn from_git(head: &GitHead, default: &str, release_name: &str) -> Result<Identity, String> {
    let releases: Vec<&str> = head
        .tags
        .lines()
        .map(str::trim)
        .filter(|tag| release_version(tag).is_some())
        .collect();
    let full = match releases.as_slice() {
        [] => format!("{default}-{}", head.commit),
        [tag] => format!("{}-release", release_version(tag).unwrap_or(default)),
        many => {
            return Err(format!(
                "commit {} carries {} release tags ({}): a release has one",
                head.commit,
                many.len(),
                many.join(", ")
            ))
        }
    };
    Ok(Identity {
        is_release: !releases.is_empty(),
        full,
        release_name: release_name.to_owned(),
    })
}

/// The identity a caller names for a tree with no git history.
pub fn from_override(version: &str, release_name: &str) -> Result<Identity, String> {
    if release_version(&format!("v{version}")).is_none() {
        return Err(format!(
            "--version-override {version:?} is not a release version: with a `v` \
             in front it must match {RELEASE_TAG_GRAMMAR}"
        ));
    }
    Ok(Identity {
        full: format!("{version}-release"),
        release_name: release_name.to_owned(),
        is_release: true,
    })
}

/// The version a release tag names, without its `v`; `None` for any other
/// tag. The whole tag must match the release grammar.
fn release_version(tag: &str) -> Option<&str> {
    let version = tag.strip_prefix('v')?;
    let (core, suffix) = match version.split_once('-') {
        Some((core, suffix)) => (core, Some(suffix)),
        None => (version, None),
    };
    let mut numbers = core.split('.');
    let three = (0..3).all(|_| numbers.next().is_some_and(is_release_number));
    let suffix_ok = suffix
        .is_none_or(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.'));
    (three && numbers.next().is_none() && suffix_ok).then_some(version)
}

/// `0`, or digits with no leading zero.
fn is_release_number(text: &str) -> bool {
    !text.is_empty()
        && text.bytes().all(|b| b.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'))
}

fn git(root: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|e| {
            format!(
                "cannot run git ({e}); a source archive is built with --version-override <version>"
            )
        })?;
    if !out.status.success() {
        return Err(format!(
            "`git {}` failed ({}): {}; a source archive is built with --version-override <version>",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    String::from_utf8(out.stdout)
        .map(|s| s.trim().to_owned())
        .map_err(|_| format!("`git {}` printed bytes that are not UTF-8", args.join(" ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(tags: &str) -> GitHead {
        GitHead {
            commit: "842d36361".to_owned(),
            tags: tags.to_owned(),
        }
    }

    fn identity(tags: &str) -> Identity {
        from_git(&head(tags), "3.1.0", "Shekyl NG").expect("an identity")
    }

    fn is_commit_build(tags: &str) {
        let id = identity(tags);
        assert_eq!(id.full, "3.1.0-842d36361", "{tags}");
        assert!(!id.is_release, "{tags}");
    }

    #[test]
    fn no_tag_is_the_nine_character_commit() {
        is_commit_build("");
    }

    #[test]
    fn an_archive_tag_is_not_a_release() {
        is_commit_build("archive/chore-pqc-0.5-and-crypto-closure-review-2026-11-23");
    }

    #[test]
    fn a_prefixed_tag_is_not_a_release() {
        is_commit_build("core-v3.1.0");
    }

    #[test]
    fn a_plain_release_tag_names_the_version() {
        let id = identity("v3.1.0");
        assert_eq!(id.full, "3.1.0-release");
        assert!(id.is_release);
    }

    #[test]
    fn a_prerelease_tag_names_the_version() {
        let id = identity("v3.1.0-alpha.12");
        assert_eq!(id.full, "3.1.0-alpha.12-release");
        assert!(id.is_release);
    }

    #[test]
    fn a_release_tag_beside_an_archive_tag_is_the_release() {
        let id = identity("archive/x-2026-11-23\nv3.1.0-alpha.13");
        assert_eq!(id.full, "3.1.0-alpha.13-release");
    }

    #[test]
    fn two_release_tags_are_refused_and_named() {
        let err = from_git(&head("v3.1.0\nv3.1.0-alpha.12"), "3.1.0", "Shekyl NG")
            .expect_err("two release tags");
        assert!(err.contains("2 release tags"), "{err}");
        assert!(err.contains("v3.1.0-alpha.12"), "{err}");
    }

    #[test]
    fn the_grammar_is_matched_whole() {
        for good in [
            "v0.0.0",
            "v3.1.0",
            "v10.20.30",
            "v3.0.0-RC1",
            "v3.1.0-alpha.12",
        ] {
            assert!(release_version(good).is_some(), "{good}");
        }
        for bad in [
            "3.1.0",
            "V3.1.0",
            "v3.1",
            "v3.1.0.1",
            "v03.1.0",
            "v3.01.0",
            "v3.1.00",
            "v3.1.0-",
            "v3.1.0-a_b",
            "v3.1.0-a-b",
            "v3.1.0+build",
            "xv3.1.0",
            "v3.1.0 ",
        ] {
            assert!(release_version(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn the_matcher_decides_every_shared_case() {
        let cases = include_str!("../release_tags.tsv");
        let mut read = 0;
        for line in cases.lines().filter(|l| !l.starts_with('#')) {
            let mut cells = line.split('\t');
            let tag = cells.next().expect("a tag");
            let release = cells.next().expect("a release cell") == "release";
            assert_eq!(release_version(tag).is_some(), release, "{tag}");
            read += 1;
        }
        assert!(read > 0, "the case table is empty");
    }

    #[test]
    fn the_archive_version_is_the_identitys_own() {
        assert_eq!(
            identity("v3.1.0-alpha.13").archive_version().as_deref(),
            Ok("v3.1.0-alpha.13")
        );
        assert_eq!(
            identity("").archive_version().as_deref(),
            Ok("3.1.0-842d36361")
        );
    }

    #[test]
    fn a_version_a_file_name_cannot_carry_is_refused() {
        // The grammar keeps such a value out; this is the backstop behind it.
        let id = Identity {
            full: "e/x-2026-11-23-release".to_owned(),
            release_name: "Shekyl NG".to_owned(),
            is_release: true,
        };
        let err = id.archive_version().expect_err("a slash");
        assert!(err.contains("cannot name an archive"), "{err}");
    }

    #[test]
    fn an_override_is_a_release_and_must_be_a_version() {
        let id = from_override("3.1.0-alpha.13", "Shekyl NG").expect("a version");
        assert_eq!(id.full, "3.1.0-alpha.13-release");
        assert!(id.is_release);
        for bad in ["$(id)", "", "3.1", "03.1.0", "v3.1.0"] {
            assert!(from_override(bad, "Shekyl NG").is_err(), "{bad}");
        }
    }
}
