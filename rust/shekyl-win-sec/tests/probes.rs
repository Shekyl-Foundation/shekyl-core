// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The CI-durable probes from
//! [`WINDOWS_WALLET_PROBE_SHEET.md`](../../../docs/design/WINDOWS_WALLET_PROBE_SHEET.md)
//! §1, as tests rather than as a session.
//!
//! Each test names its probe id and carries the **prediction** it was
//! pre-registered with. A failure here is not a broken test — it is the
//! prediction being wrong, and the sheet's "Revisits on failure" column names
//! which decision that costs.
//!
//! Nothing in this file was written after seeing a result. It was committed
//! before any Windows machine ran it.

// Gated on BOTH windows and the feature the suite needs. Without the
// feature-gate a plain `cargo check --all-targets` on a Windows runner
// fails on the missing `sid_for_testing` rather than simply skipping a
// suite it was never asked to build — which is how this PR first went red.
#![cfg(all(windows, feature = "test-utils"))]

use shekyl_win_sec::{
    current_logon_sid, current_user_sid, OwnerOnlyDescriptor, PeerCheck, PeerCheckError,
};

/// P-9 — the SID the pipe name is derived from must be this process's own.
///
/// Predicted: equals `whoami /user`. Checked here in the weaker, dependency-
/// free form (well-formed, `S-1-5-21`-shaped, stable across calls); the
/// `whoami` comparison lives in the PowerShell runner because shelling out
/// from a unit test to verify a unit test's own subject is circular.
#[test]
fn p9_current_user_sid_is_wellformed_and_stable() {
    let a = current_user_sid().expect("P-9: could not read the current user SID");
    let b = current_user_sid().expect("P-9: second read failed");
    assert_eq!(
        a.as_str(),
        b.as_str(),
        "P-9: SID is not stable across calls"
    );
    assert!(
        a.as_str().starts_with("S-1-"),
        "P-9: not a SID string: {}",
        a.as_str()
    );
    // A machine-local user SID has the S-1-5-21-<3 sub-authorities>-<rid>
    // shape. Asserted loosely: a domain or well-known account is legitimate
    // and must not fail the probe.
    assert!(
        a.as_str().matches('-').count() >= 3,
        "P-9: implausibly short SID: {}",
        a.as_str()
    );
}

/// P-15 — the logon SID must actually be a logon SID.
///
/// Added 2026-08-20 (PR #516 review). `SE_GROUP_LOGON_ID` is `0xC000_0000`, a
/// **two-bit** marker, and an `& … != 0` test accepts either bit alone. The
/// failure mode is not "no match" but a silent widening: it would select some
/// other group this token belongs to, and WP-D6's DACL would grant *that*
/// group access to the wallet pipe — invisible to the client-side owner check,
/// because the owner would still be us.
///
/// Predicted: `S-1-5-5-<high>-<low>` — NT authority, `SECURITY_LOGON_IDS_RID`,
/// then the session LUID.
#[test]
fn p15_logon_sid_has_the_logon_shape() {
    let logon = current_logon_sid().expect("P-15: logon SID");
    assert!(
        logon.as_str().starts_with("S-1-5-5-"),
        "P-15: `{}` is not a logon SID. WP-D6's DACL grants this value, so a \
         wrong selection here is a wrong grant.",
        logon.as_str()
    );
    // A session LUID is two sub-authorities, so the full form has five dashes.
    assert_eq!(
        logon.as_str().matches('-').count(),
        5,
        "P-15: `{}` has the right prefix but the wrong shape for a session LUID",
        logon.as_str()
    );
    // And it must differ from the user SID — the whole point of WP-D6 is that
    // these are two different principals.
    let user = current_user_sid().expect("P-15: user SID");
    assert_ne!(
        logon.as_str(),
        user.as_str(),
        "P-15: the logon SID equals the user SID, so the DACL would grant the \
         whole account and the session boundary would not exist"
    );
}

/// P-1 — the SDDL string must produce the DACL we meant.
///
/// **Prediction corrected 2026-08-20 by the first real run.** The original
/// asserted that the owner SID appears literally in the round-tripped string.
/// It does not: Windows **canonicalises well-known SIDs to SDDL
/// abbreviations** on readback. The CI runner's descriptor came back as
///
/// ```text
/// O:LAG:LAD:P(A;;GA;;;S-1-5-5-0-774477)S:(ML;;NW;;;ME)
/// ```
///
/// — owner `LA`, not `S-1-5-21-…`. The *policy* was correct; the assertion's
/// method was wrong, which is the distinction §5 of the probe sheet exists to
/// keep straight.
///
/// That falsified more than one line. The WP-D6 union check added in the
/// previous review round asserted `!contains("(A;;GA;;;<literal user sid>)")`
/// — **fail-open**, because a regression that granted the user SID would
/// render as `(A;;GA;;;LA)` on any machine where that SID has an abbreviation
/// and sail past it. So the DACL is now asserted **structurally**: exactly one
/// ACE, and it is the logon SID's.
///
/// Owner identity moved to P-5, which compares SIDs read off a real object via
/// `ConvertSidToStringSidW` — always the literal form, never abbreviated — so
/// it is not exposed to canonicalisation at all.
#[test]
fn p1_descriptor_roundtrips_to_the_policy_we_wrote() {
    let sid = current_user_sid().expect("P-1: SID");
    let logon = current_logon_sid().expect("P-1: logon SID");
    let d = OwnerOnlyDescriptor::new(&sid, &logon).expect("P-1: descriptor");
    let back = d.to_sddl().expect("P-1: readback");

    let dacl = dacl_section(&back)
        .unwrap_or_else(|| panic!("P-1: no D: section in the descriptor: {back}"));

    assert!(
        dacl.starts_with('P'),
        "P-1: the DACL is not protected (`D:P`), so inherited ACEs can widen          it: {back}"
    );

    // Structural, and therefore immune to SID abbreviation: one ACE, no more.
    let ace_count = dacl.matches('(').count();
    assert_eq!(
        ace_count, 1,
        "P-1: the DACL holds {ace_count} ACEs, not 1. Allow-ACEs are combined          as a UNION, so any second grant re-widens the descriptor and undoes          WP-D6 — which is exactly the bug PR #516's review found: {back}"
    );

    // A logon SID (S-1-5-5-X-Y) is session-specific and has no SDDL
    // abbreviation, so it is safe to match literally.
    assert!(
        dacl.contains(logon.as_str()),
        "P-1: the single ACE is not the logon SID's, so the DACL is not          session-scoped: {back}"
    );

    assert!(
        back.contains("(ML;;NW;;;ME)"),
        "P-1: the Medium mandatory label is not in the round-tripped          descriptor — a downgraded or missing label would read as fine: {back}"
    );
    for lower in ["(ML;;NW;;;LW)", "(ML;;NW;;;UN)"] {
        assert!(
            !back.contains(lower),
            "P-1: descriptor carries {lower}, below the Medium floor WP-D4              requires: {back}"
        );
    }
}

/// P-2 — the DACL must be protected, so inherited ACEs cannot widen it.
///
/// Predicted: `SE_DACL_PROTECTED` set, from the `D:P` in the SDDL. If this
/// fails, WP-D1's "the name and the DACL carry what the 0700 directory
/// carries on Unix" no longer holds.
#[test]
fn p2_dacl_is_protected() {
    let sid = current_user_sid().expect("P-2: SID");
    let logon = current_logon_sid().expect("P-2: logon SID");
    let d = OwnerOnlyDescriptor::new(&sid, &logon).expect("P-2: descriptor");
    assert!(
        d.dacl_is_protected(),
        "P-2: DACL is NOT protected — `D:P` did not survive, so inherited \
         ACEs can widen access"
    );
}

/// P-3 — `first_pipe_instance(true)` must fail loudly when the name is taken.
///
/// Predicted: `Err`, never a silent join. This is WP-D3 mitigation (1); if it
/// joins, squatting stops being DoS-only even on the self-hosted path.
#[tokio::test]
async fn p3_first_pipe_instance_refuses_a_taken_name() {
    use tokio::net::windows::named_pipe::ServerOptions;

    let sid = current_user_sid().expect("P-3: SID");
    let logon = current_logon_sid().expect("P-3: logon SID");
    let d = OwnerOnlyDescriptor::new(&sid, &logon).expect("P-3: descriptor");
    let name = unique_pipe_name("p3");

    let _first = unsafe {
        ServerOptions::new()
            .first_pipe_instance(true)
            .create_with_security_attributes_raw(&name, d.attributes_ptr() as *mut _)
    }
    .expect("P-3: the FIRST create should succeed");

    let second = unsafe {
        ServerOptions::new()
            .first_pipe_instance(true)
            .create_with_security_attributes_raw(&name, d.attributes_ptr() as *mut _)
    };
    assert!(
        second.is_err(),
        "P-3: a second first_pipe_instance(true) SUCCEEDED on a taken name — \
         the loud-failure property is gone"
    );
}

/// P-7 — an **unlabelled** pipe must read as Medium, i.e. pass.
///
/// Predicted: `Ok`. Absence of a mandatory label is Medium by OS default, so
/// reading absence as failure would refuse every ordinary pipe and the wallet
/// could not start. This is the false-positive guard on WP-D4.
///
/// **Construction corrected 2026-08-20 by the first real run.** The original
/// created the pipe with a *default* descriptor to get "no label", and failed
/// on `OwnerMismatch` before reaching the integrity check at all: on an
/// account in Administrators, Windows gives a default-owner object the owner
/// `S-1-5-32-544` (`BUILTIN\Administrators`), not the user. The probe now
/// builds our own descriptor minus the label, so the only thing under test is
/// the label path. The platform fact is recorded in the sheet's §4 — it means
/// any pipe created without an explicit owner would be refused by our own peer
/// check on an admin account, which production never does.
#[tokio::test]
async fn p7_unlabelled_pipe_is_read_as_medium() {
    use tokio::net::windows::named_pipe::ServerOptions;

    let sid = current_user_sid().expect("P-7: SID");
    let logon = current_logon_sid().expect("P-7: logon SID");
    let d = OwnerOnlyDescriptor::without_label_for_testing(&sid, &logon).expect("P-7: descriptor");
    let name = unique_pipe_name("p7");
    let server = unsafe {
        ServerOptions::new()
            .first_pipe_instance(true)
            .create_with_security_attributes_raw(&name, d.attributes_ptr() as *mut _)
    }
    .expect("P-7: create");

    // SAFETY: `server` outlives the call; the handle is ours.
    match unsafe { PeerCheck::verify(handle_of(&server), &sid) } {
        Ok(_) => {}
        Err(PeerCheckError::IntegrityTooLow(level)) => panic!(
            "P-7: an UNLABELLED pipe was read as {level:?} rather than Medium — \
             every ordinary pipe would be refused"
        ),
        Err(e) => panic!("P-7: unexpected refusal: {e}"),
    }
}

/// P-5 — the peer check must accept our own pipe.
#[tokio::test]
async fn p5_peer_check_accepts_our_own_pipe() {
    use tokio::net::windows::named_pipe::ServerOptions;

    let sid = current_user_sid().expect("P-5: SID");
    let logon = current_logon_sid().expect("P-5: logon SID");
    let d = OwnerOnlyDescriptor::new(&sid, &logon).expect("P-5: descriptor");
    let name = unique_pipe_name("p5");
    let server = unsafe {
        ServerOptions::new()
            .first_pipe_instance(true)
            .create_with_security_attributes_raw(&name, d.attributes_ptr() as *mut _)
    }
    .expect("P-5: create");

    // SAFETY: `server` outlives the call; the handle is ours.
    unsafe { PeerCheck::verify(handle_of(&server), &sid) }.expect("P-5: our own pipe was refused");
}

/// P-6 — the peer check must **refuse** a mismatched owner. The bite check.
///
/// A check that never refuses is the fail-open shape this project has now hit
/// six times; asserting the happy path alone would repeat it exactly.
#[tokio::test]
async fn p6_peer_check_refuses_a_mismatched_owner() {
    use tokio::net::windows::named_pipe::ServerOptions;

    let sid = current_user_sid().expect("P-6: SID");
    let logon = current_logon_sid().expect("P-6: logon SID");
    let d = OwnerOnlyDescriptor::new(&sid, &logon).expect("P-6: descriptor");
    let name = unique_pipe_name("p6");
    let server = unsafe {
        ServerOptions::new()
            .first_pipe_instance(true)
            .create_with_security_attributes_raw(&name, d.attributes_ptr() as *mut _)
    }
    .expect("P-6: create");

    // LocalSystem — a real, well-known SID that is definitively not us.
    let wrong = shekyl_win_sec::sid_for_testing("S-1-5-18");
    // SAFETY: `server` outlives the call; the handle is ours.
    match unsafe { PeerCheck::verify(handle_of(&server), &wrong) } {
        Err(PeerCheckError::OwnerMismatch { .. }) => {}
        Ok(_) => panic!(
            "P-6: the peer check ACCEPTED a pipe owned by someone else — it is \
             fail-open and cannot protect the passphrase"
        ),
        Err(e) => panic!("P-6: refused, but for the wrong reason: {e}"),
    }
}

/// P-8 — the disk probe must return a plausible figure and refuse a bad path.
///
/// **Now tests the shipping function directly.** While the Windows arm lived
/// in `shekyl-engine-core` — a crate whose graph reaches `ring` and so cannot
/// be cross-compiled from Linux — this probe exercised a *copy*, and a CI gate
/// existed solely to prove the copy had not drifted. WP-D2's siting rule moved
/// the function into this crate, so the copy and its gate are deleted rather
/// than maintained.
#[test]
fn p8_disk_probe_is_sane_and_refuses_a_bad_path() {
    let temp = std::env::temp_dir();
    let n = shekyl_win_sec::free_bytes_available(&temp).expect("P-8: probe failed on %TEMP%");
    assert!(n > 0, "P-8: %TEMP% reports zero bytes available");
    assert!(
        n < (1u64 << 50),
        "P-8: implausible free-space figure ({n} bytes) — check the out-param order"
    );
    assert!(
        shekyl_win_sec::free_bytes_available(std::path::Path::new(r"Z:\no\such\shekyl-probe"))
            .is_err(),
        "P-8: a nonexistent path returned Ok — the probe cannot distinguish \
         'no room' from 'cannot tell'"
    );
}

// --- helpers ---------------------------------------------------------------

/// The `D:` section of an SDDL string, between the DACL marker and the SACL.
///
/// Split on `"S:"` rather than `'S'` — SIDs are full of `S`s, and the marker is
/// the only place the letter is followed by a colon.
fn dacl_section(sddl: &str) -> Option<&str> {
    let after = &sddl[sddl.find("D:")? + 2..];
    Some(match after.find("S:") {
        Some(i) => &after[..i],
        None => after,
    })
}

/// A per-test pipe name. Tests share a process, so a fixed name would make
/// P-3's "taken name" assertion fire in unrelated tests.
fn unique_pipe_name(tag: &str) -> String {
    format!(
        "{}probe-{tag}-{}",
        shekyl_win_sec::PIPE_PREFIX,
        std::process::id()
    )
}

fn handle_of(
    server: &tokio::net::windows::named_pipe::NamedPipeServer,
) -> windows_sys::Win32::Foundation::HANDLE {
    use std::os::windows::io::AsRawHandle;
    server.as_raw_handle().cast()
}
