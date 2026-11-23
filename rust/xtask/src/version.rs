// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The build identity the binaries print (DC-Q20): computed once here, read
//! by `rust/shekyl-version` through `option_env!`.
//!
//! - A commit with a tag: the first `v`-prefixed token of `git tag -l
//!   --points-at HEAD` without its `v`, or the default when no tag has one;
//!   the tag part is `release`.
//! - Any other commit: the default version, tagged with the commit's first
//!   nine hex digits.
//! - No git work tree (a source archive): refused, unless the caller names
//!   the version with `--version-override`, which is a release.

use std::path::Path;
use std::process::Command;

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

    /// Whether a tag points at HEAD: the output is false when empty or when
    /// it spells one of the false constants (`0`, `OFF`, `NO`, `FALSE`, `N`, `IGNORE`, `NOTFOUND`, or
    /// `…-NOTFOUND`, any case), so a lone tag named `no` is not a release.
    pub fn is_tagged(&self) -> bool {
        let upper = self.tags.to_ascii_uppercase();
        !(upper.is_empty()
            || matches!(
                upper.as_str(),
                "0" | "OFF" | "NO" | "FALSE" | "N" | "IGNORE" | "NOTFOUND"
            )
            || upper.ends_with("-NOTFOUND"))
    }
}

/// The identity for HEAD.
pub fn from_git(head: &GitHead, default: &str, release_name: &str) -> Identity {
    if head.is_tagged() {
        let version = first_v_token(&head.tags).unwrap_or(default);
        Identity {
            full: format!("{version}-release"),
            release_name: release_name.to_owned(),
            is_release: true,
        }
    } else {
        Identity {
            full: format!("{default}-{}", head.commit),
            release_name: release_name.to_owned(),
            is_release: false,
        }
    }
}

/// The identity a caller names for a tree with no git history.
pub fn from_override(version: &str, release_name: &str) -> Result<Identity, String> {
    let ok = !version.is_empty()
        && version.starts_with(|c: char| c.is_ascii_digit())
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'));
    if !ok {
        return Err(format!(
            "--version-override {version:?} is not a version (digits first, then letters, digits, `.` and `-`)"
        ));
    }
    Ok(Identity {
        full: format!("{version}-release"),
        release_name: release_name.to_owned(),
        is_release: true,
    })
}

/// The first `v` followed by non-space characters, without the `v`, as
/// the release rule has always read it: anywhere in the text, so a
/// tag `x-v1` yields `1`.
fn first_v_token(tags: &str) -> Option<&str> {
    let bytes = tags.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'v' {
            let rest = &tags[i + 1..];
            let end = rest.find([' ', '\t', '\r', '\n']).unwrap_or(rest.len());
            if end > 0 {
                return Some(&rest[..end]);
            }
        }
        i += 1;
    }
    None
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

    #[test]
    fn an_untagged_commit_is_the_default_and_the_commit() {
        let id = from_git(&head(""), "3.1.0", "Shekyl NG");
        assert_eq!(id.full, "3.1.0-842d36361");
        assert!(!id.is_release);
    }

    #[test]
    fn a_v_tag_names_the_version() {
        let id = from_git(&head("v3.1.0-alpha.13"), "3.1.0", "Shekyl NG");
        assert_eq!(id.full, "3.1.0-alpha.13-release");
        assert!(id.is_release);
    }

    #[test]
    fn the_first_v_token_wins_wherever_it_is() {
        // The `v` inside `archive` comes first.
        assert_eq!(first_v_token("archive/x-v2\nv3.1.0"), Some("e/x-v2"));
        assert_eq!(first_v_token("candidate\nv3.1.0"), Some("3.1.0"));
    }

    #[test]
    fn a_tag_without_a_v_is_a_release_of_the_default() {
        let id = from_git(&head("candidate"), "3.1.0", "Shekyl NG");
        assert_eq!(id.full, "3.1.0-release");
        assert!(id.is_release);
    }

    #[test]
    fn a_lone_tag_spelling_a_false_constant_is_not_a_release() {
        for tag in ["no", "OFF", "0", "x-NOTFOUND"] {
            assert!(!head(tag).is_tagged(), "{tag}");
        }
        assert!(head("no\nv3.1.0").is_tagged());
    }

    #[test]
    fn the_archive_version_is_the_identitys_own() {
        let tagged = from_git(&head("v3.1.0-alpha.13"), "3.1.0", "Shekyl NG");
        assert_eq!(tagged.archive_version().as_deref(), Ok("v3.1.0-alpha.13"));
        let untagged = from_git(&head(""), "3.1.0", "Shekyl NG");
        assert_eq!(untagged.archive_version().as_deref(), Ok("3.1.0-842d36361"));
    }

    #[test]
    fn a_version_a_file_name_cannot_carry_is_refused() {
        let id = from_git(&head("archive/x-2026-11-23"), "3.1.0", "Shekyl NG");
        let err = id.archive_version().expect_err("a slash");
        assert!(err.contains("cannot name an archive"), "{err}");
    }

    #[test]
    fn an_override_is_a_release_and_must_be_a_version() {
        let id = from_override("3.1.0", "Shekyl NG").expect("a version");
        assert_eq!(id.full, "3.1.0-release");
        assert!(id.is_release);
        assert!(from_override("$(id)", "Shekyl NG").is_err());
        assert!(from_override("", "Shekyl NG").is_err());
    }
}
