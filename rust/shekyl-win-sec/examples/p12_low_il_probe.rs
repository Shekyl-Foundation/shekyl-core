// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! **P-12** — does the Medium mandatory label block a Low-IL opener?
//!
//! Pre-registered in `WINDOWS_WALLET_PROBE_SHEET.md` §3 as laptop-only, and
//! run by `scripts/ci/windows_probe.ps1` without `-CiOnly`. Predicted result:
//! the Low-integrity open fails with `ERROR_ACCESS_DENIED`. **Revisits on
//! failure: WP-D4** — a Low-IL/AppContainer process at the same user is the
//! *only* in-scope adversary per `WINDOWS_WALLET_SUPPORT.md` §6, so if the
//! label does not block, the server-side half of D4 is doing nothing and the
//! client-side integrity check becomes load-bearing alone.
//!
//! # Why an example rather than a `#[test]`
//!
//! Two reasons, and the second is the binding one.
//!
//! It needs a **second process** — a mandatory label is enforced by the OS
//! against an opener, and a Low-IL thread inside the test binary is not a
//! Low-IL opener. And §3 pre-declares this probe CI-fragile because a CI
//! service account's token may not be a faithful thing to derestrict from;
//! `scripts/ci/check_probe_registry.py` therefore asserts that §2/§3 probes
//! have **no** test function in `tests/probes.rs`. Adding one would fail that
//! gate, correctly — the sheet says this does not run in CI, and a `p12_*`
//! test would be a claim that it does.
//!
//! # The control, which is the part that makes this measurable
//!
//! A refusal proves nothing on its own. §4.2 records P-7 failing because it
//! never reached the label path it existed to test, and a Low-IL child that
//! fails to open the pipe for some *unrelated* reason — wrong name, dead
//! listener, an exe it cannot execute — would look exactly like a pass.
//!
//! So three things are established before the verdict is believed:
//!
//! 1. **The pipe is openable.** The parent opens it in-process at Medium
//!    first. If that fails, nothing below measured the label.
//! 2. **The child ran.** It reports through its exit code; a child that never
//!    started produces a code that is neither `0` nor a plausible
//!    `CreateFile` error, and is reported as such rather than as a pass.
//! 3. **The child was actually Low.** It reads its *own* token's integrity
//!    level and refuses to continue unless it is `S-1-16-4096`. Without this,
//!    a `SetTokenInformation` that silently did nothing would produce a
//!    Medium child, and the probe would measure the wrong thing in whichever
//!    direction happened to be convenient.
//!
//! The edit that makes this check fail is `low_il: false` at the call in
//! [`run_parent`]: the spawn path is otherwise identical for both children, so
//! integrity level is the single difference between them.
//!
//! # Exit codes
//!
//! The child speaks in exit codes rather than stdout: a Low-IL process writing
//! to a console handle it inherited from a Medium parent is its own permission
//! question, and it is not the one under test.
//!
//! | Code | Meaning |
//! |---|---|
//! | `0` | the pipe **opened** — for the Low child this is the P-12 failure |
//! | `5` | `ERROR_ACCESS_DENIED` — the predicted Low-child result |
//! | other small | some other `CreateFile` Win32 error |
//! | `200` | the child was not at Low integrity; nothing was measured |
//! | `201` | the child could not read its own integrity level |

fn main() {
    #[cfg(windows)]
    {
        std::process::exit(probe::main());
    }
    #[cfg(not(windows))]
    {
        eprintln!("P-12 is a Windows probe; this target has no mandatory labels.");
        std::process::exit(1);
    }
}

#[cfg(windows)]
mod probe {
    use std::ffi::c_void;
    use std::mem::size_of;

    use windows_sys::Win32::Foundation::{
        CloseHandle, LocalFree, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSidToSidW,
    };
    use windows_sys::Win32::Security::{
        DuplicateTokenEx, GetLengthSid, GetTokenInformation, SecurityImpersonation,
        SetTokenInformation, TokenIntegrityLevel, TokenPrimary, SID_AND_ATTRIBUTES,
        TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_MANDATORY_LABEL,
        TOKEN_QUERY,
    };
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_NONE, OPEN_EXISTING};
    use windows_sys::Win32::System::SystemServices::SE_GROUP_INTEGRITY;
    use windows_sys::Win32::System::Threading::{
        CreateProcessAsUserW, GetCurrentProcess, GetExitCodeProcess, OpenProcessToken,
        WaitForSingleObject, CREATE_NO_WINDOW, INFINITE, PROCESS_INFORMATION, STARTUPINFOW,
    };

    use tokio::net::windows::named_pipe::ServerOptions;

    use shekyl_win_sec::{
        current_logon_sid, current_user_sid, self_hosted_pipe_name, OwnerOnlyDescriptor,
        OwnerOnlyPipeListener,
    };

    /// `SECURITY_MANDATORY_LOW_RID` in string form. The child is spawned with
    /// this as its token's integrity label and asserts it back before it
    /// touches the pipe.
    const LOW_IL_SID: &str = "S-1-16-4096";

    /// The child ran but was not at Low integrity — the label was never
    /// actually the thing under test.
    const EXIT_NOT_LOW: u32 = 200;
    /// The child could not read its own integrity level.
    const EXIT_NO_IL: u32 = 201;

    /// `ERROR_ACCESS_DENIED`, the predicted Low-child result.
    const ACCESS_DENIED: u32 = 5;

    /// Spawn counters, so the listeners never share a name.
    const SPAWN_CONTROL: u64 = 1_201;
    const SPAWN_PROBE: u64 = 1_202;
    const SPAWN_UNLABELLED: u64 = 1_203;

    pub fn main() -> i32 {
        let args: Vec<String> = std::env::args().collect();
        match args.get(1).map(String::as_str) {
            Some("--open") => match args.get(2) {
                Some(name) => run_child(name),
                None => {
                    eprintln!("--open needs a pipe name");
                    1
                }
            },
            _ => run_parent(),
        }
    }

    // -- the child --------------------------------------------------------

    /// Assert this process really is Low, then try the pipe. Speaks only in
    /// exit codes; see the module docs for the table.
    fn run_child(name: &str) -> i32 {
        match own_integrity_sid() {
            None => int_from(EXIT_NO_IL),
            Some(sid) if sid != LOW_IL_SID => {
                // Deliberately loud on stderr as well: if this ever fires, the
                // exit code alone would look like an obscure CreateFile error.
                eprintln!("child integrity is {sid}, expected {LOW_IL_SID}");
                int_from(EXIT_NOT_LOW)
            }
            Some(_) => int_from(try_open(name)),
        }
    }

    /// This process's own integrity level, as a SID string.
    fn own_integrity_sid() -> Option<String> {
        let token = open_own_token(TOKEN_QUERY)?;

        let mut needed: u32 = 0;
        // SAFETY: the documented sizing form — a null buffer with zero length.
        // The call is expected to fail; only `needed` is read.
        unsafe {
            GetTokenInformation(
                token.0,
                TokenIntegrityLevel,
                std::ptr::null_mut(),
                0,
                &raw mut needed,
            );
        }
        if needed == 0 {
            return None;
        }

        // Backed by `u64`, not `u8`: `TOKEN_MANDATORY_LABEL` holds a pointer
        // and so wants 8-byte alignment, which a `Vec<u8>` does not give. The
        // same under-alignment lesson as P-14's hand-built ACL, and as the
        // defect Windows-target clippy caught in `current_user_sid` — third
        // instance in this crate, which is why it is spelled out again.
        let mut buf = vec![0u64; usize::try_from(needed).ok()?.div_ceil(8)];
        // SAFETY: `buf` is at least `needed` bytes long and correctly aligned;
        // the call writes at most `needed` of them.
        let ok = unsafe {
            GetTokenInformation(
                token.0,
                TokenIntegrityLevel,
                buf.as_mut_ptr().cast::<c_void>(),
                needed,
                &raw mut needed,
            )
        };
        if ok == 0 {
            return None;
        }

        // SAFETY: on success the buffer holds a `TOKEN_MANDATORY_LABEL` whose
        // `Sid` points into memory the OS owns for the life of the buffer.
        let label = unsafe { &*buf.as_ptr().cast::<TOKEN_MANDATORY_LABEL>() };
        sid_to_string(label.Label.Sid)
    }

    // -- the parent -------------------------------------------------------

    fn run_parent() -> i32 {
        let exe = match std::env::current_exe() {
            Ok(p) => p,
            Err(e) => {
                println!("P-12 UNRUN: cannot locate this executable to re-spawn: {e}");
                return 2;
            }
        };
        let me = match current_user_sid() {
            Ok(sid) => sid,
            Err(e) => {
                println!("P-12 UNRUN: cannot read this process's SID: {e}");
                return 2;
            }
        };

        // `OwnerOnlyPipeListener::bind` registers the instance with a tokio
        // runtime, so one has to be entered even though nothing is accepted:
        // the probe is about who can OPEN the name, not about what is served
        // over it.
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                println!("P-12 UNRUN: no tokio runtime: {e}");
                return 2;
            }
        };
        let _guard = runtime.enter();

        // --- CONTROL: the pipe is openable at Medium ---------------------
        //
        // Establishes that the name, the descriptor and the listener are all
        // live. Without it a Low-IL refusal is indistinguishable from a probe
        // that never reached the pipe at all (§4.2's P-7).
        let control_name = self_hosted_pipe_name(&me, SPAWN_CONTROL);
        let control = match OwnerOnlyPipeListener::bind(control_name.clone()) {
            Ok(l) => l,
            Err(e) => {
                println!("P-12 UNRUN: could not bind the control pipe: {e}");
                return 2;
            }
        };
        let control_code = try_open(&control_name);
        drop(control);
        if control_code != 0 {
            println!(
                "P-12 UNRUN: the control open FAILED with os error {control_code}. \
                 A Medium opener could not reach our own pipe, so nothing below \
                 would be measuring the mandatory label."
            );
            return 2;
        }
        println!("P-12 control: a Medium in-process opener reaches the pipe (as expected).");

        // --- THE PROBE: a genuinely Low-IL opener ------------------------
        let probe_name = self_hosted_pipe_name(&me, SPAWN_PROBE);
        let listener = match OwnerOnlyPipeListener::bind(probe_name.clone()) {
            Ok(l) => l,
            Err(e) => {
                println!("P-12 UNRUN: could not bind the probe pipe: {e}");
                return 2;
            }
        };

        // `low_il: true` is the whole probe. Flipping it to `false` is the
        // edit that makes this check fail, and the spawn path is otherwise
        // byte-identical between the two.
        let spawned = spawn_opener(&exe, &probe_name, true);
        drop(listener);

        let code = match spawned {
            Ok(code) => code,
            Err(e) => {
                println!(
                    "P-12 UNRUN: could not spawn a Low-integrity child: os error {e}. \
                     The probe did not execute; this is not a pass."
                );
                return 2;
            }
        };

        attribute_the_refusal(&exe, &me);
        verdict(code)
    }

    /// Supplementary, and deliberately **not** part of the verdict.
    ///
    /// P-12's pre-registered question is whether a Low-IL opener is blocked,
    /// and `verdict` answers exactly that. This asks the follow-up the answer
    /// invites: blocked *by what*? The same descriptor minus the label
    /// (`OwnerOnlyDescriptor::without_label_for_testing` — same owner, same
    /// session-scoped DACL) isolates the explicit `(ML;;NW;;;ME)` from the
    /// DACL, which the Low child also satisfies because it shares our logon
    /// session.
    ///
    /// `lib.rs` claims the explicit label is "an assertion rather than a gap
    /// being closed", because unlabelled objects are already Medium to the OS.
    /// If that is right, an unlabelled pipe refuses the Low child too, and the
    /// refusal is the platform default rather than our string. Recorded either
    /// way; §5 forbids folding it into the prediction.
    fn attribute_the_refusal(exe: &std::path::Path, me: &shekyl_win_sec::SidString) {
        let Ok(logon) = current_logon_sid() else {
            println!("P-12 note: no logon SID, so the label/DACL attribution was skipped.");
            return;
        };
        let Ok(descriptor) = OwnerOnlyDescriptor::without_label_for_testing(me, &logon) else {
            println!("P-12 note: could not build an unlabelled descriptor; attribution skipped.");
            return;
        };
        let name = self_hosted_pipe_name(me, SPAWN_UNLABELLED);
        // SAFETY: `descriptor` outlives the call, and `CreateNamedPipe` reads
        // the attributes only during it — the same contract `pipe.rs` relies on.
        let listener = unsafe {
            ServerOptions::new()
                .first_pipe_instance(true)
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(
                    name.as_str(),
                    descriptor.attributes_ptr().cast_mut().cast(),
                )
        };
        let Ok(listener) = listener else {
            println!("P-12 note: could not bind an unlabelled pipe; attribution skipped.");
            return;
        };

        let spawned = spawn_opener(exe, &name, true);
        drop(listener);

        match spawned {
            Ok(ACCESS_DENIED) => println!(
                "P-12 note: an UNLABELLED pipe also refused the Low child with \
                 ERROR_ACCESS_DENIED. The refusal is the platform's default \
                 Medium treatment of unlabelled objects, not our explicit \
                 (ML;;NW;;;ME) — which is what lib.rs already claims the label \
                 is: an assertion, not a gap being closed."
            ),
            Ok(0) => println!(
                "P-12 note: an UNLABELLED pipe ADMITTED the Low child. So the \
                 explicit (ML;;NW;;;ME) label is load-bearing, not belt-and-braces, \
                 and lib.rs's \"assertion rather than a gap being closed\" \
                 understates it. Worth a WP-D4 note."
            ),
            Ok(other) => println!(
                "P-12 note: the unlabelled-pipe attribution was inconclusive \
                 (child exited {other})."
            ),
            Err(e) => println!(
                "P-12 note: the unlabelled-pipe attribution could not spawn \
                 (os error {e})."
            ),
        }
    }

    /// Turn the Low child's exit code into the pre-registered verdict.
    fn verdict(code: u32) -> i32 {
        match code {
            ACCESS_DENIED => {
                println!(
                    "P-12 PASS: a Low-integrity process was refused with \
                     ERROR_ACCESS_DENIED (5), as predicted. WP-D4's server-side \
                     half blocks the only in-scope adversary."
                );
                0
            }
            0 => {
                println!(
                    "P-12 FAIL: a Low-integrity process OPENED the pipe. The Medium \
                     mandatory label did not block it, so WP-D4's server-side half is \
                     doing nothing and the client-side integrity check is load-bearing \
                     alone. Per the sheet, WP-D4 is what this revisits — not this probe."
                );
                1
            }
            EXIT_NOT_LOW => {
                println!(
                    "P-12 UNRUN: the child was not at Low integrity, so the label was \
                     never the thing under test. Not a pass."
                );
                2
            }
            EXIT_NO_IL => {
                println!(
                    "P-12 UNRUN: the child could not read its own integrity level, so it \
                     could not confirm it was the adversary this probe describes."
                );
                2
            }
            other => {
                println!(
                    "P-12 FAIL: the Low-integrity child exited {other}, which is neither \
                     a successful open (0) nor ERROR_ACCESS_DENIED (5). The refusal is \
                     not the one predicted, and an unexplained refusal is not evidence \
                     that the label did the refusing."
                );
                1
            }
        }
    }

    /// Re-spawn this executable as `--open <name>`, optionally at Low
    /// integrity, and return its exit code.
    ///
    /// `CreateProcessAsUserW` with a duplicate of our own token needs no
    /// privilege when the duplicate is *weaker* than the original, which
    /// lowering the integrity label makes it. That is the documented path for
    /// launching a Low-IL child and the reason this probe needs no elevation.
    fn spawn_opener(exe: &std::path::Path, pipe: &str, low_il: bool) -> Result<u32, u32> {
        let token = open_own_token(
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY,
        )
        .ok_or_else(last_error)?;

        let mut dup: HANDLE = std::ptr::null_mut();
        // SAFETY: `token` is a live token handle; `dup` is written only on
        // success and is closed by its guard below.
        let ok = unsafe {
            DuplicateTokenEx(
                token.0,
                TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY,
                std::ptr::null(),
                SecurityImpersonation,
                TokenPrimary,
                &raw mut dup,
            )
        };
        if ok == 0 {
            return Err(last_error());
        }
        let dup = TokenGuard(dup);

        if low_il {
            lower_to_low_integrity(dup.0)?;
        }

        let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
        startup.cb = u32::try_from(size_of::<STARTUPINFOW>()).unwrap_or(0);
        let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        let application = wide(&exe.to_string_lossy());
        // `lpCommandLine` is documented as writable, so it cannot be a
        // borrowed constant. argv[0] is quoted; the pipe name has no spaces
        // (it is a SID and two integers) but is quoted for the same reason.
        let mut command = wide(&format!("\"{}\" --open \"{pipe}\"", exe.to_string_lossy()));

        // SAFETY: both wide buffers are NUL-terminated and outlive the call;
        // `startup` and `info` are correctly sized and owned here.
        let created = unsafe {
            CreateProcessAsUserW(
                dup.0,
                application.as_ptr(),
                command.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                CREATE_NO_WINDOW,
                std::ptr::null(),
                std::ptr::null(),
                &raw mut startup,
                &raw mut info,
            )
        };
        if created == 0 {
            return Err(last_error());
        }

        // SAFETY: `info.hProcess` is a live process handle from the call above.
        unsafe { WaitForSingleObject(info.hProcess, INFINITE) };
        let mut code: u32 = 0;
        // SAFETY: same handle; the process has exited, so the code is final.
        let read = unsafe { GetExitCodeProcess(info.hProcess, &raw mut code) };
        // SAFETY: both handles came from `CreateProcessAsUserW` and are closed
        // exactly once.
        unsafe {
            CloseHandle(info.hThread);
            CloseHandle(info.hProcess);
        }
        if read == 0 {
            return Err(last_error());
        }
        Ok(code)
    }

    /// Set `token`'s integrity label to Low.
    fn lower_to_low_integrity(token: HANDLE) -> Result<(), u32> {
        let sid_text = wide(LOW_IL_SID);
        let mut sid: *mut c_void = std::ptr::null_mut();
        // SAFETY: `sid_text` is NUL-terminated and outlives the call; `sid` is
        // written only on success and freed below.
        let ok = unsafe { ConvertStringSidToSidW(sid_text.as_ptr(), &raw mut sid) };
        if ok == 0 {
            return Err(last_error());
        }

        // `SE_GROUP_INTEGRITY` is `0x20`, typed `i32` by windows-sys, and the
        // field is `u32`. Converted rather than cast so that a sign change
        // could never pass silently — `cast_sign_loss` is denied workspace-wide
        // for exactly this shape.
        let Ok(attributes) = u32::try_from(SE_GROUP_INTEGRITY) else {
            // SAFETY: `sid` came from `ConvertStringSidToSidW` and is dropped
            // here without being used again.
            unsafe { LocalFree(sid) };
            return Err(u32::MAX);
        };
        let label = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: sid,
                Attributes: attributes,
            },
        };
        // The documented length is the struct plus the SID it points at, not
        // the struct alone — the same variable-length-SID subtlety P-14 exists
        // for, in the writing direction.
        // SAFETY: `sid` is a valid SID from the conversion above.
        let len = size_of::<TOKEN_MANDATORY_LABEL>()
            + usize::try_from(unsafe { GetLengthSid(sid) }).unwrap_or(0);
        // SAFETY: `label` is a correctly-formed `TOKEN_MANDATORY_LABEL` and
        // `len` describes it plus its SID, as the API documents.
        let set = unsafe {
            SetTokenInformation(
                token,
                TokenIntegrityLevel,
                (&raw const label).cast::<c_void>(),
                u32::try_from(len).unwrap_or(0),
            )
        };
        let err = last_error();
        // SAFETY: `sid` came from `ConvertStringSidToSidW`, which documents
        // `LocalFree` as its release. `label` borrows it but is dead from here
        // — the token now holds its own copy of the label, which is the point
        // of the call above.
        unsafe { LocalFree(sid) };

        if set == 0 {
            return Err(err);
        }
        Ok(())
    }

    // -- shared helpers ---------------------------------------------------

    /// `CreateFile` on a pipe name. `0` means it opened; anything else is the
    /// Win32 error, and `5` is the refusal P-12 predicts for a Low-IL caller.
    ///
    /// Deliberately *not* `shekyl_win_sec::open_verified`: that runs the
    /// client-side peer check, which would conflate two different refusals.
    /// P-12 asks whether the **OS** blocks the open, so the open has to be
    /// raw.
    fn try_open(name: &str) -> u32 {
        let wide_name = wide(name);
        // SAFETY: `wide_name` is NUL-terminated and outlives the call; every
        // other argument is a constant or null.
        let handle = unsafe {
            CreateFileW(
                wide_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_NONE,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return last_error();
        }
        // SAFETY: a live handle from the call above, closed exactly once.
        unsafe { CloseHandle(handle) };
        0
    }

    /// A SID as its `S-1-…` string.
    fn sid_to_string(sid: *mut c_void) -> Option<String> {
        let mut out: *mut u16 = std::ptr::null_mut();
        // SAFETY: `sid` is a valid SID for the life of its buffer; `out` is
        // written only on success and freed below.
        let ok = unsafe { ConvertSidToStringSidW(sid, &raw mut out) };
        if ok == 0 || out.is_null() {
            return None;
        }
        let mut len = 0usize;
        // SAFETY: the OS returns a NUL-terminated wide string.
        while unsafe { *out.add(len) } != 0 {
            len += 1;
        }
        // SAFETY: `len` is the length up to the NUL, so the slice is in bounds.
        let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(out, len) });
        // SAFETY: `out` came from `ConvertSidToStringSidW`, released with
        // `LocalFree`, and is not used after this.
        unsafe { LocalFree(out.cast::<c_void>()) };
        Some(text)
    }

    fn open_own_token(access: u32) -> Option<TokenGuard> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: `GetCurrentProcess` is a pseudo-handle needing no close;
        // `token` is written only on success.
        let ok = unsafe { OpenProcessToken(GetCurrentProcess(), access, &raw mut token) };
        if ok == 0 {
            return None;
        }
        Some(TokenGuard(token))
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn last_error() -> u32 {
        std::io::Error::last_os_error()
            .raw_os_error()
            .and_then(|c| u32::try_from(c).ok())
            .unwrap_or(u32::MAX)
    }

    /// Exit codes are `u32` on Windows but `i32` at the `process::exit`
    /// boundary; the reserved codes and every Win32 error we can see here fit.
    fn int_from(code: u32) -> i32 {
        i32::try_from(code).unwrap_or(1)
    }

    /// Closes a token handle on every path out.
    struct TokenGuard(HANDLE);

    impl Drop for TokenGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: a live token handle, closed exactly once.
                unsafe { CloseHandle(self.0) };
            }
        }
    }
}
