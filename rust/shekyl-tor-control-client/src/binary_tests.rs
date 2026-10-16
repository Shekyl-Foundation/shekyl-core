// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Tests for the tor-directory pin gate.

use super::*;
use hex_literal::hex;

/// A pinned known-answer for the hash itself: SHA-256 of the empty input
/// (NIST). An empty file must hash to it — this pins the algorithm,
/// independent of any tor binary being present.
const EMPTY_SHA256: [u8; 32] =
    hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

/// Write a file and make it executable (the gate requires launchability).
fn write_executable(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// A pin over `(name, contents)` pairs, the first being the executable.
/// Owned so the [`TorPin`] a test borrows can live on the stack: the
/// production disposition is `'static`, and a test is not.
struct OwnedPin {
    files: Vec<PinnedFile>,
    case_insensitive_names: bool,
    bundle_version: &'static str,
    bundle_target: &'static str,
    tor_version: &'static str,
}

impl OwnedPin {
    fn pin(&self) -> TorPin<'_> {
        TorPin {
            bundle_version: self.bundle_version,
            bundle_target: self.bundle_target,
            tor_version: self.tor_version,
            executable: self.files[0].name,
            case_insensitive_names: self.case_insensitive_names,
            files: &self.files,
        }
    }
}

fn pin_for(files: &[(&'static str, &[u8])], case_insensitive_names: bool) -> OwnedPin {
    OwnedPin {
        files: files
            .iter()
            .map(|(name, bytes)| PinnedFile {
                name,
                sha256: sha256(bytes),
            })
            .collect(),
        case_insensitive_names,
        bundle_version: "0.0.0",
        bundle_target: "test-target",
        tor_version: "0.0.0.0",
    }
}

/// The Linux shape of a bundle: `tor` and three libraries.
const LINUX_FILES: [(&str, &[u8]); 4] = [
    ("tor", b"tor"),
    ("libevent-2.1.so.7", b"libevent"),
    ("libssl.so.3", b"libssl"),
    ("libcrypto.so.3", b"libcrypto"),
];

/// Lay `files` out in a fresh directory as a correctly staged bundle and
/// return the directory and the path of its executable.
fn staged(files: &[(&'static str, &[u8])]) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    for (i, (name, bytes)) in files.iter().enumerate() {
        let path = dir.path().join(name);
        if i == 0 {
            write_executable(&path, bytes);
        } else {
            std::fs::write(&path, bytes).unwrap();
        }
    }
    let exe = dir.path().join(files[0].0);
    (dir, exe)
}

#[test]
fn verify_matches_the_empty_input_sha256_vector() {
    let (dir, exe) = staged(&[("tor", b"")]);
    let files = [PinnedFile {
        name: "tor",
        sha256: EMPTY_SHA256,
    }];
    let pin = TorPin {
        bundle_version: "0.0.0",
        bundle_target: "test-target",
        tor_version: "0.0.0.0",
        executable: "tor",
        case_insensitive_names: false,
        files: &files,
    };
    let verified = verify_candidate(&exe, &pin).unwrap();
    // The witness carries the canonical form of the verified path, and
    // its directory.
    assert_eq!(verified.as_path(), exe.canonicalize().unwrap());
    assert_eq!(
        verified.library_dir(),
        dir.path().canonicalize().unwrap().as_path()
    );
}

#[test]
fn verify_accepts_a_correctly_staged_bundle() {
    let (_dir, exe) = staged(&LINUX_FILES);
    assert!(verify_candidate(&exe, &pin_for(&LINUX_FILES, false).pin()).is_ok());
}

/// The gate rejects a single flipped byte **in any pinned file**, not only
/// in `tor`, and the mismatch carries both digests so a bad pin bump is
/// self-diagnosing.
#[test]
fn verify_rejects_a_tampered_byte_in_any_pinned_file() {
    let pin = pin_for(&LINUX_FILES, false);
    for (name, original) in LINUX_FILES {
        let (dir, exe) = staged(&LINUX_FILES);
        let mut tampered = original.to_vec();
        *tampered.last_mut().unwrap() ^= 1;
        let victim = dir.path().join(name);
        // Rewrite in place, keeping the mode.
        let mode = std::fs::metadata(&victim).unwrap().permissions();
        std::fs::write(&victim, &tampered).unwrap();
        std::fs::set_permissions(&victim, mode).unwrap();
        match verify_candidate(&exe, &pin.pin()) {
            Err(TorBinaryError::HashMismatch {
                path,
                expected,
                actual,
            }) => {
                assert_eq!(path, victim.canonicalize().unwrap(), "{name}");
                assert_eq!(expected, sha256(original), "{name}");
                assert_eq!(actual, sha256(&tampered), "{name}");
            }
            other => panic!("{name}: expected HashMismatch, got {other:?}"),
        }
    }
}

/// Every refusal is a sentence an operator reads in a log line. A string
/// continuation that swallowed its indentation renders as a run of spaces
/// mid-sentence, and nothing else in the tree would notice.
#[test]
fn refusals_render_as_single_spaced_sentences() {
    let path = PathBuf::from("/x/tor");
    let errors = [
        TorBinaryError::Unavailable { reason: "r" },
        TorBinaryError::NotFound,
        TorBinaryError::NotAFile(path.clone()),
        TorBinaryError::NotExecutable(path.clone()),
        TorBinaryError::NotTheExecutable(path.clone()),
        TorBinaryError::Io {
            path: path.clone(),
            kind: std::io::ErrorKind::NotFound,
        },
        TorBinaryError::UnexpectedEntry {
            dir: PathBuf::from("/x"),
            name: OsString::from("libz.so.1"),
        },
        TorBinaryError::MissingFile {
            dir: PathBuf::from("/x"),
            name: "tor",
        },
        TorBinaryError::UnsafeLoaderPath(PathBuf::from("/x:y")),
        TorBinaryError::HashMismatch {
            path,
            expected: [0; 32],
            actual: [1; 32],
        },
    ];
    for error in errors {
        let text = error.to_string();
        assert!(!text.contains("  "), "{text:?}");
        assert!(!text.is_empty());
    }
}

// --- TB-7 part 3: the directory holds the pinned files and nothing else.
// Three plants, each of which a loader pointed at this directory would
// have used (TOR_BUNDLE_DISTRIBUTION.md §2 findings 10 to 12). ---

/// A file at the top level that the pin does not list. `libz.so.1` is the
/// library `tor` needs and the bundle does not carry.
#[test]
fn verify_refuses_a_planted_top_level_file() {
    let (dir, exe) = staged(&LINUX_FILES);
    std::fs::write(dir.path().join("libz.so.1"), b"planted").unwrap();
    match verify_candidate(&exe, &pin_for(&LINUX_FILES, false).pin()) {
        Err(TorBinaryError::UnexpectedEntry { name, .. }) => {
            assert_eq!(name, OsString::from("libz.so.1"));
        }
        other => panic!("expected UnexpectedEntry, got {other:?}"),
    }
}

/// glibc searches `glibc-hwcaps/<level>/` under a library-path entry
/// before the entry itself. A listing of the top level shows a directory
/// and no library; a scan for library names passes it. The allowlist does
/// not, because the directory is not a pinned file.
#[test]
fn verify_refuses_a_planted_glibc_hwcaps_library() {
    let (dir, exe) = staged(&LINUX_FILES);
    let hwcaps = dir.path().join("glibc-hwcaps").join("x86-64-v2");
    std::fs::create_dir_all(&hwcaps).unwrap();
    std::fs::write(hwcaps.join("libz.so.1"), b"planted").unwrap();
    match verify_candidate(&exe, &pin_for(&LINUX_FILES, false).pin()) {
        Err(TorBinaryError::UnexpectedEntry { name, .. }) => {
            assert_eq!(name, OsString::from("glibc-hwcaps"));
        }
        other => panic!("expected UnexpectedEntry, got {other:?}"),
    }
}

/// Windows searches the executable's directory first and treats
/// `VERSION.DLL` and `version.dll` as one name. The Windows pin lists
/// `tor.exe` alone, so either spelling beside it is refused — and under
/// the same rule `TOR.EXE` *is* the pinned executable, which is what shows
/// the comparison is by folded name and not a refusal of everything.
#[test]
fn verify_refuses_a_planted_version_dll_under_the_windows_name_rule() {
    let files: [(&str, &[u8]); 1] = [("tor.exe", b"tor")];
    let pin = pin_for(&files, true);

    for planted in ["VERSION.DLL", "version.dll"] {
        let (dir, exe) = staged(&files);
        std::fs::write(dir.path().join(planted), b"planted").unwrap();
        match verify_candidate(&exe, &pin.pin()) {
            Err(TorBinaryError::UnexpectedEntry { name, .. }) => {
                assert_eq!(name, OsString::from(planted));
            }
            other => panic!("{planted}: expected UnexpectedEntry, got {other:?}"),
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let upper = dir.path().join("TOR.EXE");
    write_executable(&upper, b"tor");
    assert!(verify_candidate(&upper, &pin.pin()).is_ok());
}

/// Two spellings of one pinned name are two directory entries and one slot.
/// The loader will open one of them; the gate has to refuse before it hashes
/// either, and before it reports a different file the directory also lacks.
/// Linux so the fixture can hold both spellings as distinct entries.
#[cfg(target_os = "linux")]
#[test]
fn verify_refuses_a_second_spelling_of_an_occupied_slot() {
    let files: [(&str, &[u8]); 3] = [
        ("tor.exe", b"tor"),
        ("version.dll", b"version"),
        ("libevent-2.1.so.7", b"libevent"),
    ];
    let pin = pin_for(&files, true);
    let dir = tempfile::tempdir().unwrap();
    write_executable(&dir.path().join("tor.exe"), b"tor");
    std::fs::write(dir.path().join("VERSION.DLL"), b"version").unwrap();
    std::fs::write(dir.path().join("version.dll"), b"other").unwrap();
    match verify_candidate(&dir.path().join("tor.exe"), &pin.pin()) {
        Err(TorBinaryError::UnexpectedEntry { name, .. }) => {
            assert!(
                name.to_string_lossy().eq_ignore_ascii_case("version.dll"),
                "{name:?}"
            );
        }
        other => panic!("expected UnexpectedEntry, got {other:?}"),
    }
}

/// The case rule is the platform's, not a blanket one: where names are
/// case-sensitive, a differently-cased name is a different, unpinned file.
#[test]
fn verify_compares_names_exactly_where_the_platform_does() {
    let files: [(&str, &[u8]); 1] = [("tor", b"tor")];
    let dir = tempfile::tempdir().unwrap();
    let upper = dir.path().join("TOR");
    write_executable(&upper, b"tor");
    assert!(matches!(
        verify_candidate(&upper, &pin_for(&files, false).pin()),
        Err(TorBinaryError::UnexpectedEntry { .. })
    ));
}

/// The first thing a developer tries: `SHEKYL_TOR_BINARY` pointed at the
/// `tor` inside a full extracted Expert Bundle. Its directory carries
/// `pluggable_transports/`, and the override tier is gated like any other.
#[test]
fn verify_refuses_a_full_extracted_bundle_through_the_override() {
    let (dir, exe) = staged(&LINUX_FILES);
    let transports = dir.path().join("pluggable_transports");
    std::fs::create_dir(&transports).unwrap();
    std::fs::write(transports.join("lyrebird"), b"transport").unwrap();

    let chosen = candidate_from(Some(exe.clone().into_os_string()), None, None, "tor")
        .expect("the override is the candidate");
    match verify_candidate(&chosen, &pin_for(&LINUX_FILES, false).pin()) {
        Err(TorBinaryError::UnexpectedEntry { name, .. }) => {
            assert_eq!(name, OsString::from("pluggable_transports"));
        }
        other => panic!("expected UnexpectedEntry, got {other:?}"),
    }
}

/// A pinned name that is a symlink is refused even when it points at the
/// right bytes: the loader would follow it out of the checked directory.
#[cfg(unix)]
#[test]
fn verify_refuses_a_symlinked_entry_in_the_directory() {
    let (dir, exe) = staged(&LINUX_FILES);
    let outside = tempfile::tempdir().unwrap();
    let real = outside.path().join("libssl.so.3");
    std::fs::write(&real, b"libssl").unwrap();
    let link = dir.path().join("libssl.so.3");
    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert!(matches!(
        verify_candidate(&exe, &pin_for(&LINUX_FILES, false).pin()),
        Err(TorBinaryError::NotAFile(_))
    ));
}

/// `LD_LIBRARY_PATH` is a list. A bundle that is correct in every file
/// but lives under a name the loader would split or expand is refused on
/// Linux, where the launcher sets that variable: with `a:b` in the path
/// the loader would search two directories, neither the one checked.
#[cfg(target_os = "linux")]
#[test]
fn verify_refuses_a_directory_the_loader_would_read_as_a_list() {
    for odd in ["a:b", "a;b", "$ORIGIN", "x${LIB}"] {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join(odd);
        std::fs::create_dir(&dir).unwrap();
        for (i, (name, bytes)) in LINUX_FILES.iter().enumerate() {
            if i == 0 {
                write_executable(&dir.join(name), bytes);
            } else {
                std::fs::write(dir.join(name), bytes).unwrap();
            }
        }
        assert_eq!(
            verify_candidate(&dir.join("tor"), &pin_for(&LINUX_FILES, false).pin()).unwrap_err(),
            TorBinaryError::UnsafeLoaderPath(dir.canonicalize().unwrap()),
            "{odd}"
        );
    }
}

#[test]
fn loader_path_rule_accepts_ordinary_directories_only() {
    for ok in [
        "/opt/shekyl/15.0.24-linux-x86_64",
        "/srv/My Name/shekyl/tor",
    ] {
        assert!(loader_reads_as_one_directory(Path::new(ok)), "{ok}");
    }
    for bad in [
        "/opt/a:b",
        "/opt/a;b",
        "/opt/$ORIGIN/tor",
        "relative/tor",
        "",
    ] {
        assert!(!loader_reads_as_one_directory(Path::new(bad)), "{bad}");
    }
}

/// The test constructor is the same contract as the gate: on Linux a
/// directory the loader would split is not a witness, so the launcher
/// cannot start tor against the system search path.
#[cfg(target_os = "linux")]
#[test]
#[should_panic(expected = "not one absolute loader path")]
fn unchecked_for_test_refuses_a_loader_list_path() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("a:b");
    std::fs::create_dir(&dir).unwrap();
    let exe = dir.join("tor");
    write_executable(&exe, b"tor");
    let _ = VerifiedTorBinary::unchecked_for_test(exe);
}

#[cfg(target_os = "linux")]
#[test]
#[should_panic(expected = "not one absolute loader path")]
fn unchecked_for_test_refuses_a_relative_path() {
    let _ = VerifiedTorBinary::unchecked_for_test(PathBuf::from("tor"));
}

#[test]
fn verify_refuses_a_directory_missing_a_pinned_file() {
    let (dir, exe) = staged(&LINUX_FILES);
    std::fs::remove_file(dir.path().join("libevent-2.1.so.7")).unwrap();
    assert_eq!(
        verify_candidate(&exe, &pin_for(&LINUX_FILES, false).pin()).unwrap_err(),
        TorBinaryError::MissingFile {
            dir: dir.path().canonicalize().unwrap(),
            name: "libevent-2.1.so.7",
        }
    );
}

/// An override naming one of the libraries is in a pinned directory but is
/// not what gets executed.
#[test]
fn verify_refuses_a_pinned_file_that_is_not_the_executable() {
    let (dir, _exe) = staged(&LINUX_FILES);
    assert!(matches!(
        verify_candidate(
            &dir.path().join("libssl.so.3"),
            &pin_for(&LINUX_FILES, false).pin()
        ),
        Err(TorBinaryError::NotTheExecutable(_))
    ));
}

/// A missing candidate is a NotFound-kind `Io`, not a false pass.
#[test]
fn verify_missing_file_is_io_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("does-not-exist");
    assert!(matches!(
        verify_candidate(&missing, &pin_for(&LINUX_FILES, false).pin()),
        Err(TorBinaryError::Io {
            kind: std::io::ErrorKind::NotFound,
            ..
        })
    ));
}

/// A directory is refused as not-a-regular-file (before any read).
#[test]
fn verify_directory_is_not_a_file() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(
        verify_candidate(dir.path(), &pin_for(&LINUX_FILES, false).pin()),
        Err(TorBinaryError::NotAFile(_))
    ));
}

/// A readable but non-executable candidate is refused with a curated error
/// — at spawn it would be a content-free failure tor never gets to log.
#[cfg(unix)]
#[test]
fn verify_non_executable_is_refused() {
    let (dir, exe) = staged(&LINUX_FILES);
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        verify_candidate(&exe, &pin_for(&LINUX_FILES, false).pin()).unwrap_err(),
        TorBinaryError::NotExecutable(dir.path().canonicalize().unwrap().join("tor"))
    );
}

/// One path, checked and used. Reached through a symlinked directory (an
/// install directory that is a link to the versioned one), the witness
/// names the **target** for both the executable and the library
/// directory — so what the loader is pointed at is what was checked.
#[cfg(unix)]
#[test]
fn verify_through_a_symlinked_directory_checks_and_uses_the_target() {
    let (dir, _exe) = staged(&LINUX_FILES);
    let links = tempfile::tempdir().unwrap();
    let link = links.path().join("current");
    std::os::unix::fs::symlink(dir.path(), &link).unwrap();

    let real_dir = dir.path().canonicalize().unwrap();
    let verified =
        verify_candidate(&link.join("tor"), &pin_for(&LINUX_FILES, false).pin()).unwrap();
    assert_eq!(verified.as_path(), real_dir.join("tor"));
    assert_eq!(verified.library_dir(), real_dir.as_path());

    // And the check is of the target: a plant there is seen through the link.
    std::fs::write(dir.path().join("libz.so.1"), b"planted").unwrap();
    assert!(matches!(
        verify_candidate(&link.join("tor"), &pin_for(&LINUX_FILES, false).pin()),
        Err(TorBinaryError::UnexpectedEntry { .. })
    ));
}

/// A candidate that is itself a symlink resolves to its target, and it is
/// the **target's** directory that must hold exactly the pinned files.
#[cfg(unix)]
#[test]
fn verify_canonicalizes_a_symlinked_candidate() {
    let (dir, exe) = staged(&LINUX_FILES);
    let links = tempfile::tempdir().unwrap();
    let link = links.path().join("tor-link");
    std::os::unix::fs::symlink(&exe, &link).unwrap();
    let verified = verify_candidate(&link, &pin_for(&LINUX_FILES, false).pin()).unwrap();
    assert_eq!(verified.as_path(), exe.canonicalize().unwrap());
    assert_eq!(
        verified.library_dir(),
        dir.path().canonicalize().unwrap().as_path()
    );
}

// --- candidate_from precedence KATs (the load-bearing selection policy,
// testable without touching process-global env). ---

/// Stage an executable at `<dir>/tor/tor`, the beside-the-executable
/// layout of an unpacked archive.
fn beside(dir: &Path) -> PathBuf {
    let tor_dir = dir.join(BESIDE_TOR_DIR);
    std::fs::create_dir(&tor_dir).unwrap();
    let exe = tor_dir.join("tor");
    write_executable(&exe, b"beside");
    exe
}

#[test]
fn candidate_override_wins_even_over_an_existing_beside_binary() {
    let dir = tempfile::tempdir().unwrap();
    beside(dir.path());
    let chosen = candidate_from(
        Some(OsString::from("/explicit/override/tor")),
        Some(dir.path()),
        None,
        "tor",
    );
    // The override is returned verbatim — even though it does not exist —
    // so a typo surfaces as *its* error, never a silent fallback.
    assert_eq!(chosen, Some(PathBuf::from("/explicit/override/tor")));
}

#[test]
fn candidate_empty_override_is_treated_as_unset() {
    let dir = tempfile::tempdir().unwrap();
    let exe = beside(dir.path());
    let chosen = candidate_from(Some(OsString::new()), Some(dir.path()), None, "tor");
    assert_eq!(chosen, Some(exe));
}

/// Tier 2 is `<exe_dir>/tor/tor`. A `tor` file directly beside the
/// executable — the layout before the bundle had a directory of its own —
/// is not a candidate: its directory is the executable's and could never
/// hold exactly the pinned files.
#[test]
fn candidate_beside_is_the_tor_directory_not_a_tor_file() {
    let dir = tempfile::tempdir().unwrap();
    write_executable(&dir.path().join("tor"), b"flat");
    assert_eq!(candidate_from(None, Some(dir.path()), None, "tor"), None);

    let dir = tempfile::tempdir().unwrap();
    let exe = beside(dir.path());
    assert_eq!(
        candidate_from(None, Some(dir.path()), None, "tor"),
        Some(exe)
    );
}

/// The system tier is consulted when nothing is beside the executable, and
/// a beside bundle displaces it.
#[test]
fn candidate_well_known_yields_to_beside() {
    let wk_dir = tempfile::tempdir().unwrap();
    let wk = wk_dir.path().join("tor");
    write_executable(&wk, b"staged");

    let empty_beside = tempfile::tempdir().unwrap();
    let chosen = candidate_from(None, Some(empty_beside.path()), Some(&wk), "tor");
    assert_eq!(chosen, Some(wk.clone()));

    let beside_dir = tempfile::tempdir().unwrap();
    let exe = beside(beside_dir.path());
    let chosen = candidate_from(None, Some(beside_dir.path()), Some(&wk), "tor");
    assert_eq!(chosen, Some(exe));
}

/// The system candidate is version-exact, composed from the pin's own
/// labels — the layout contract with packaging (`/opt/shekyl/
/// <bundle_version>-<bundle_target>/tor`), pinned here so a layout drift
/// fails a test instead of silently never matching an installed bundle.
#[cfg(unix)]
#[test]
fn well_known_candidate_is_version_exact_from_the_pin() {
    let mut owned = pin_for(&LINUX_FILES, false);
    owned.bundle_version = "15.0.24";
    owned.bundle_target = "linux-x86_64";
    assert_eq!(
        well_known_candidate(&owned.pin()),
        Some(PathBuf::from("/opt/shekyl/15.0.24-linux-x86_64/tor"))
    );
}

/// There is no `PATH` tier (TB-8): with nothing in the three tiers the
/// answer is "none", whatever `PATH` holds. `candidate_from` takes no
/// `PATH` argument, so this is the absence stated as a test rather than
/// left to be inferred from a signature.
#[test]
fn candidate_none_when_nothing_is_found() {
    let empty = tempfile::tempdir().unwrap();
    assert_eq!(candidate_from(None, Some(empty.path()), None, "tor"), None);
}

/// The compiled disposition is self-consistent: a pinned target's
/// executable is among its files and no two files fold to one name. (The
/// build script refuses a pin file that breaks these; this reads the
/// constant the binary actually carries.)
#[test]
fn compiled_disposition_is_well_formed() {
    match CURRENT_DISPOSITION {
        TorDisposition::Pinned(pin) => {
            assert!(pin.files.iter().any(|f| f.name == pin.executable));
            for (i, a) in pin.files.iter().enumerate() {
                for b in &pin.files[i + 1..] {
                    assert!(!a.name.eq_ignore_ascii_case(b.name));
                }
            }
        }
        TorDisposition::Unavailable { reason } => assert!(!reason.trim().is_empty()),
    }
    assert_eq!(TOR_SIGNING_KEY_FPR.len(), 40);
}

/// On a target we ship a managed tor for, the disposition must be
/// `Pinned` (so `discover_and_verify` can only fail on discovery or
/// verification, never on `Unavailable`). Guards against a row being
/// flipped in `config/tor_pins.json` without anyone meaning it.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn current_target_has_a_recorded_pin() {
    assert!(
        matches!(CURRENT_DISPOSITION, TorDisposition::Pinned(_)),
        "linux/x86_64 and linux/aarch64 must have a recorded tor pin"
    );
}

/// The recorded pin must match the *actual* bundle — the runtime guard for
/// the pin-time obligation (checklist bump correctness). Ignored in the
/// unit gate; the pin-verify lane (and the checklist re-verify step) runs
/// it with `SHEKYL_TEST_PINNED_TOR_BINARY` pointing at the `tor` inside a
/// directory staged by `scripts/release/tor_bundle.py` from the
/// signature-verified Expert Bundle — a distinct variable from the any-tor
/// `SHEKYL_TEST_TOR_BINARY` the lifecycle tests use, so the two contracts
/// cannot collide. Deliberately NOT `cfg`-gated: on a target with no pin it
/// fails loudly instead of compiling out and letting the checklist's
/// re-verify step pass with zero tests run.
#[test]
#[ignore = "requires the pinned Tor via SHEKYL_TEST_PINNED_TOR_BINARY"]
fn bundled_tor_matches_recorded_pin() {
    let TorDisposition::Pinned(pin) = CURRENT_DISPOSITION else {
        panic!("this build target has no recorded pin — pin it before re-verifying");
    };
    let bin = std::env::var_os("SHEKYL_TEST_PINNED_TOR_BINARY").expect(
        "SHEKYL_TEST_PINNED_TOR_BINARY must point at the staged, pinned tor \
         (GPG-verified per the RELEASE_CHECKLIST procedure) on the pin-verify lane",
    );
    verify_candidate(Path::new(&bin), &pin).expect(
        "the staged bundle must match the recorded pin — if the bundle version changed, \
         re-run the full checklist procedure (GPG-verify first), never record a hash \
         from an unverified file",
    );
}
