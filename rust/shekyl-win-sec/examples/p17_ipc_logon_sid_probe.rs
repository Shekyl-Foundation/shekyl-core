// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! **P-17** — does the logon SID **by itself** refuse a caller from a
//! different logon session, the `IPC$` reachability WP-D6 exists for?
//!
//! Pre-registered in `WINDOWS_WALLET_PROBE_SHEET.md` §3 (corrected §3.1
//! before any run), and run by `scripts/ci/windows_probe.ps1` in **both**
//! modes — its precondition is a loopback SMB path, not an interactive
//! logon, and whether the CI runner has one is exactly the §3.1 promotion
//! question.
//!
//! # The four rows, and why each fence is lowered where it is
//!
//! Production keeps **three** fences against a foreign caller: the
//! `PIPE_REJECT_REMOTE_CLIENTS` flag, the owner-only DACL whose single ACE
//! is the logon SID, and the Medium mandatory label. A refusal with all of
//! them up attributes nothing — the P-7 lesson. So each row lowers exactly
//! the fences it is not measuring, the same move P-12 makes with
//! `without_label_for_testing`:
//!
//! | Row | Pipe | Path | Predicted |
//! |---|---|---|---|
//! | (a) control | production shape (flag + DACL + label) | `\\.\pipe\…` | opens — the DACL admits its own session |
//! | (b) mechanism | permissive (`D:(A;;GA;;;WD)`, no flag, no label) | `\\localhost\pipe\…` | opens, and the caller's logon SID **differs** from ours |
//! | (c) production | production shape | `\\localhost\pipe\…` | refused — by *some* fence; which one is deliberately not claimed |
//! | (d) the D6 claim | DACL only (no flag, no label) | `\\localhost\pipe\…` | refused with `ERROR_ACCESS_DENIED` — and now only the logon-SID ACE can be the refuser |
//!
//! Row (b) is what turns "loopback SMB produces a distinct logon session"
//! from a premise into an observation: the server impersonates the caller
//! and reads the logon SID off the impersonation token. If (b) cannot
//! connect, everything downstream is **UNRUN** — a refusal would be
//! unattributed. If (b) connects and the SIDs are *equal*, the prediction is
//! falsified outright (exit 1): loopback does not cross sessions and WP-D6's
//! `IPC$` story needs revisiting.
//!
//! # Exit codes
//!
//! | Code | Meaning |
//! |---|---|
//! | `0` | all four rows as predicted — the logon-SID ACE alone carries the boundary |
//! | `1` | a prediction was **falsified** — revisits WP-D6, see the sheet |
//! | `2` | UNRUN — a precondition (usually the loopback SMB path) is absent, or the harness could not attribute; never a pass |

fn main() {
    #[cfg(windows)]
    {
        std::process::exit(probe::main());
    }
    #[cfg(not(windows))]
    {
        eprintln!("P-17 is a Windows probe; this target has no pipe namespace or logon SIDs.");
        std::process::exit(1);
    }
}

#[cfg(windows)]
mod probe {
    use std::ffi::c_void;
    use std::sync::mpsc;
    use std::time::Duration;

    use windows_sys::Win32::Foundation::{
        CloseHandle, LocalFree, ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE,
        INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows_sys::Win32::Security::{RevertToSelf, SECURITY_ATTRIBUTES, TOKEN_QUERY};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING,
        PIPE_ACCESS_DUPLEX, SECURITY_IMPERSONATION, SECURITY_SQOS_PRESENT,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, ImpersonateNamedPipeClient, PIPE_READMODE_BYTE,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

    use shekyl_win_sec::{
        current_logon_sid, current_user_sid, logon_sid_of_token_for_testing, self_hosted_pipe_name,
        OwnerOnlyDescriptor,
    };

    /// `ERROR_ACCESS_DENIED` — the (d) prediction, and the only code that row
    /// accepts: any other refusal would mean a mechanism this probe did not
    /// lower, and must be looked at rather than counted.
    const ACCESS_DENIED: u32 = 5;

    /// `SDDL_REVISION_1` — the only revision that exists.
    const SDDL_REVISION: u32 = 1;

    /// How long to wait for the loopback client thread's verdict. The open
    /// either completes or fails within the SMB connect timeout (seconds);
    /// this is a hang ceiling for the harness, not a deadline for the OS.
    const CLIENT_TIMEOUT: Duration = Duration::from_secs(30);

    /// Spawn counters, so no two rows ever share a pipe name — a consumed or
    /// squatted instance must not be able to confound a neighbouring row.
    const SPAWN_MECH: u64 = 1_700;
    const SPAWN_CONTROL: u64 = 1_701;
    const SPAWN_PROD: u64 = 1_702;
    const SPAWN_DACL_ONLY: u64 = 1_703;

    /// Owns a raw handle; closes exactly once, on every path out — including
    /// the early-exit paths, which is what keeps a blocked peer from hanging
    /// the run (a closed server end turns the client's blocking read into an
    /// error instead of a wait).
    struct HandleGuard(HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            if self.0 != INVALID_HANDLE_VALUE && !self.0.is_null() {
                // SAFETY: the guard is the sole owner of a handle that came
                // from CreateNamedPipeW/CreateFileW/OpenThreadToken.
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn last_error() -> u32 {
        std::io::Error::last_os_error()
            .raw_os_error()
            .and_then(|e| u32::try_from(e).ok())
            .unwrap_or(0)
    }

    /// `\\.\pipe\X` → `\\localhost\pipe\X`: the same pipe, addressed through
    /// the loopback SMB path instead of the local pipe namespace. The name is
    /// what changes the transport; the object is identical.
    fn loopback_form(local: &str) -> Option<String> {
        local
            .strip_prefix(r"\\.\pipe\")
            .map(|tail| format!(r"\\localhost\pipe\{tail}"))
    }

    /// Try to open `name` for read+write. `0` means it opened (the handle is
    /// closed immediately); anything else is the Win32 error.
    ///
    /// `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION` is set explicitly
    /// rather than inherited from defaults: row (b)'s server must be able to
    /// impersonate this caller, and an implicit QOS level is exactly the kind
    /// of ambient fact a probe must not lean on.
    fn try_open(name: &str) -> u32 {
        let wide_name = wide(name);
        // SAFETY: `wide_name` is NUL-terminated and outlives the call.
        let handle = unsafe {
            CreateFileW(
                wide_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return last_error();
        }
        drop(HandleGuard(handle));
        0
    }

    /// Create one raw pipe instance at `name` with `attributes`, byte mode,
    /// one instance, `first_pipe_instance` — and the remote-client flag only
    /// when asked, because which fences are up is each row's whole design.
    fn create_instance(
        name: &str,
        attributes: *const SECURITY_ATTRIBUTES,
        reject_remote: bool,
    ) -> Result<HandleGuard, u32> {
        let mode = PIPE_TYPE_BYTE
            | PIPE_READMODE_BYTE
            | PIPE_WAIT
            | if reject_remote {
                PIPE_REJECT_REMOTE_CLIENTS
            } else {
                0
            };
        let wide_name = wide(name);
        // SAFETY: `wide_name` is NUL-terminated; `attributes` is either null
        // or points at a live SECURITY_ATTRIBUTES that outlives the call
        // (CreateNamedPipeW reads it only during the call).
        let handle = unsafe {
            CreateNamedPipeW(
                wide_name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                mode,
                1,
                512,
                512,
                0,
                attributes,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(last_error());
        }
        Ok(HandleGuard(handle))
    }

    /// A deliberately permissive descriptor — `D:(A;;GA;;;WD)`, no label —
    /// for the mechanism pipe only.
    ///
    /// Permissive on purpose and safe on purpose: this pipe exists for
    /// milliseconds, carries one probe byte in each direction and no wallet
    /// state, and every fence must be down so that the *only* question it
    /// answers is "what identity does a loopback caller arrive with". A
    /// refusal here would be unattributable noise.
    struct PermissiveSd(*mut c_void, SECURITY_ATTRIBUTES);
    impl PermissiveSd {
        fn new() -> Result<Self, u32> {
            let sddl = wide("D:(A;;GA;;;WD)");
            let mut sd: *mut c_void = std::ptr::null_mut();
            // SAFETY: `sddl` is NUL-terminated; `sd` is written only on
            // success and freed by Drop below, per the API's LocalFree
            // contract.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION,
                    &raw mut sd,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(last_error());
            }
            let attrs = SECURITY_ATTRIBUTES {
                nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
                lpSecurityDescriptor: sd,
                bInheritHandle: 0,
            };
            Ok(Self(sd, attrs))
        }
        fn attributes_ptr(&self) -> *const SECURITY_ATTRIBUTES {
            &raw const self.1
        }
    }
    impl Drop for PermissiveSd {
        fn drop(&mut self) {
            // SAFETY: `sd` came from the converter, which documents LocalFree.
            unsafe { LocalFree(self.0) };
        }
    }
    use std::mem::size_of;

    pub fn main() -> i32 {
        let Ok(me) = current_user_sid() else {
            println!("P-17 UNRUN: cannot read this process's user SID.");
            return 2;
        };
        let Ok(my_logon) = current_logon_sid() else {
            println!("P-17 UNRUN: cannot read this process's logon SID.");
            return 2;
        };

        // ---- (b) mechanism, first: everything downstream leans on it. ----
        let caller_logon = match mechanism_row(&me) {
            Ok(sid) => sid,
            Err(verdict) => return verdict,
        };
        if caller_logon == my_logon {
            println!(
                "P-17 FAIL: the loopback caller carries OUR logon SID ({}). Loopback SMB \
                 does not cross a logon-session boundary on this build, so the logon-SID \
                 ACE cannot be what stands between the pipe and `IPC$`. Revisits WP-D6 \
                 (sheet §3).",
                caller_logon.as_str()
            );
            return 1;
        }
        println!(
            "P-17 mechanism: the loopback caller's logon SID ({}) differs from ours ({}) \
             — loopback SMB is a distinct logon session, observed.",
            caller_logon.as_str(),
            my_logon.as_str()
        );

        // ---- (a) control: the production shape admits its own session. ----
        let Ok(descriptor) = OwnerOnlyDescriptor::new(&me, &my_logon) else {
            println!("P-17 UNRUN: could not build the production descriptor.");
            return 2;
        };
        let control_name = self_hosted_pipe_name(&me, SPAWN_CONTROL);
        let control = match create_instance(&control_name, descriptor.attributes_ptr(), true) {
            Ok(h) => h,
            Err(e) => {
                println!("P-17 UNRUN: could not bind the control pipe (os error {e}).");
                return 2;
            }
        };
        let local = try_open(&control_name);
        drop(control);
        if local != 0 {
            println!(
                "P-17 UNRUN: the control open FAILED (os error {local}) — the production \
                 shape refused its own session locally, so nothing below would measure \
                 the transport. Not a pass."
            );
            return 2;
        }
        println!("P-17 control: the production pipe opens locally at Medium (as expected).");

        // ---- (c) production shape over loopback: refused by SOMETHING. ----
        let prod_name = self_hosted_pipe_name(&me, SPAWN_PROD);
        let Some(prod_loopback) = loopback_form(&prod_name) else {
            println!("P-17 UNRUN: pipe name did not carry the expected prefix.");
            return 2;
        };
        let prod = match create_instance(&prod_name, descriptor.attributes_ptr(), true) {
            Ok(h) => h,
            Err(e) => {
                println!("P-17 UNRUN: could not bind the production-shape pipe (os error {e}).");
                return 2;
            }
        };
        let prod_result = try_open(&prod_loopback);
        drop(prod);
        if prod_result == 0 {
            println!(
                "P-17 FAIL: the PRODUCTION-SHAPE pipe admitted a loopback caller. That is \
                 a live `IPC$` hole, not a documentation gap. Revisits WP-D6 — urgently."
            );
            return 1;
        }
        println!(
            "P-17 production: the loopback open is refused (os error {prod_result}); which \
             fence refused it is deliberately not claimed — that is row (d)'s job."
        );

        // ---- (d) the D6 claim proper: DACL alone, every other fence down. --
        // `without_label_for_testing` keeps the same owner and the same
        // single-ACE DACL and drops the mandatory label; the remote-client
        // flag is off. If this refuses, only the logon-SID ACE can have done
        // it — the caller was admitted by an identical DACL-less-label shape
        // in (b)? No: (b) was permissive. What isolates the ACE is that every
        // OTHER mechanism this probe knows about is lowered, and (b) proved
        // the caller reaches pipes over this path when the DACL allows it.
        let Ok(dacl_only) = OwnerOnlyDescriptor::without_label_for_testing(&me, &my_logon) else {
            println!("P-17 UNRUN: could not build the DACL-only descriptor.");
            return 2;
        };
        let d_name = self_hosted_pipe_name(&me, SPAWN_DACL_ONLY);
        let Some(d_loopback) = loopback_form(&d_name) else {
            println!("P-17 UNRUN: pipe name did not carry the expected prefix.");
            return 2;
        };
        let d_pipe = match create_instance(&d_name, dacl_only.attributes_ptr(), false) {
            Ok(h) => h,
            Err(e) => {
                println!("P-17 UNRUN: could not bind the DACL-only pipe (os error {e}).");
                return 2;
            }
        };
        let d_result = try_open(&d_loopback);
        drop(d_pipe);
        match d_result {
            0 => {
                println!(
                    "P-17 FAIL: with the remote-client flag and the label both down, the \
                     loopback caller was ADMITTED. The logon-SID ACE does not carry the \
                     `IPC$` boundary on its own; removing the user-SID ACE in PR #516 \
                     bought nothing on this axis, and the flag is load-bearing where \
                     WP-D6 says the SID is. Revisits WP-D6."
                );
                1
            }
            ACCESS_DENIED => {
                println!(
                    "P-17 PASS: with every other fence down, the loopback caller is refused \
                     with ERROR_ACCESS_DENIED (5), as predicted — the logon-SID ACE alone \
                     carries the `IPC$` boundary. WP-D6's defence-in-depth claim is now an \
                     observation."
                );
                0
            }
            other => {
                println!(
                    "P-17 UNRUN: the DACL-only loopback open failed with os error {other}, \
                     not ERROR_ACCESS_DENIED — some mechanism this probe did not lower \
                     refused it first, so the ACE is not attributed. Not a pass."
                );
                2
            }
        }
    }

    /// Row (b): a permissive pipe, a loopback client, and the caller's logon
    /// SID read off the impersonation token. `Err` carries the process exit
    /// code (always `2`, UNRUN — nothing here is a prediction failure except
    /// the SID comparison, which the caller does).
    fn mechanism_row(me: &shekyl_win_sec::SidString) -> Result<shekyl_win_sec::SidString, i32> {
        let sd = match PermissiveSd::new() {
            Ok(sd) => sd,
            Err(e) => {
                println!("P-17 UNRUN: could not build the permissive descriptor (os error {e}).");
                return Err(2);
            }
        };
        let mech_name = self_hosted_pipe_name(me, SPAWN_MECH);
        let Some(mech_loopback) = loopback_form(&mech_name) else {
            println!("P-17 UNRUN: pipe name did not carry the expected prefix.");
            return Err(2);
        };
        let server = match create_instance(&mech_name, sd.attributes_ptr(), false) {
            Ok(h) => h,
            Err(e) => {
                println!("P-17 UNRUN: could not bind the mechanism pipe (os error {e}).");
                return Err(2);
            }
        };

        // The client: open over loopback, write one byte (impersonation
        // requires the server to have read from the caller), report the open
        // result, then block on a read until the server releases it. If the
        // server bails early, dropping its guard closes the instance and the
        // blocked read fails — the thread cannot outlive the row.
        let (tx, rx) = mpsc::channel::<u32>();
        let client = std::thread::spawn(move || {
            {
                let wide_name = wide(&mech_loopback);
                // SAFETY: NUL-terminated, outlives the call.
                let handle = unsafe {
                    CreateFileW(
                        wide_name.as_ptr(),
                        GENERIC_READ | GENERIC_WRITE,
                        0,
                        std::ptr::null(),
                        OPEN_EXISTING,
                        SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION,
                        std::ptr::null_mut(),
                    )
                };
                if handle == INVALID_HANDLE_VALUE {
                    let e = last_error();
                    _ = tx.send(e);
                    return;
                }
                let guard = HandleGuard(handle);
                let payload = [0x17u8];
                let mut written: u32 = 0;
                // SAFETY: live handle, valid one-byte buffer.
                let wrote = unsafe {
                    WriteFile(
                        guard.0,
                        payload.as_ptr(),
                        1,
                        &raw mut written,
                        std::ptr::null_mut(),
                    )
                };
                if wrote == 0 || written != 1 {
                    let e = last_error();
                    _ = tx.send(e);
                    return;
                }
                _ = tx.send(0);
                // Hold the connection until the server releases it: the
                // impersonation token must describe a live caller, not a
                // hung-up one.
                let mut release = [0u8; 1];
                let mut read: u32 = 0;
                // SAFETY: live handle, valid buffer; a server-side close
                // fails this read rather than hanging it.
                unsafe {
                    ReadFile(
                        guard.0,
                        release.as_mut_ptr(),
                        1,
                        &raw mut read,
                        std::ptr::null_mut(),
                    )
                };
            }
        });

        let Ok(open_code) = rx.recv_timeout(CLIENT_TIMEOUT) else {
            println!(
                "P-17 UNRUN: the loopback client reported nothing within {}s — the \
                 SMB connect neither succeeded nor failed in bounded time.",
                CLIENT_TIMEOUT.as_secs()
            );
            drop(server); // fail the client's read, then reap it
            drop(client.join());
            return Err(2);
        };
        if open_code != 0 {
            println!(
                "P-17 UNRUN: the loopback open of a PERMISSIVE pipe failed (os error \
                 {open_code}). The loopback SMB path itself is absent or refused — \
                 nothing downstream can attribute anything. On a box without \
                 `LanmanServer`/`IPC$` this is the expected disposition, and it is \
                 not a pass."
            );
            drop(server);
            drop(client.join());
            return Err(2);
        }

        // Accept the (already-arrived) connection, read the caller's byte,
        // impersonate, read the logon SID off the thread token, revert.
        // SAFETY: live server instance from create_instance above.
        let connected = unsafe { ConnectNamedPipe(server.0, std::ptr::null_mut()) };
        if connected == 0 && last_error() != ERROR_PIPE_CONNECTED {
            let e = last_error();
            println!("P-17 UNRUN: ConnectNamedPipe failed (os error {e}).");
            drop(server);
            drop(client.join());
            return Err(2);
        }
        let mut byte = [0u8; 1];
        let mut got: u32 = 0;
        // SAFETY: live handle, valid buffer.
        let read_ok = unsafe {
            ReadFile(
                server.0,
                byte.as_mut_ptr(),
                1,
                &raw mut got,
                std::ptr::null_mut(),
            )
        };
        if read_ok == 0 || got != 1 {
            let e = last_error();
            println!("P-17 UNRUN: could not read the caller's byte (os error {e}).");
            drop(server);
            drop(client.join());
            return Err(2);
        }

        // SAFETY: the caller has written and we have read, which is the
        // documented precondition; the impersonation is reverted on every
        // path below, and a failed revert aborts the process outright —
        // continuing to run with a caller's identity on this thread is not a
        // state this probe is allowed to be in.
        let imp = unsafe { ImpersonateNamedPipeClient(server.0) };
        if imp == 0 {
            let e = last_error();
            println!("P-17 UNRUN: ImpersonateNamedPipeClient failed (os error {e}).");
            drop(server);
            drop(client.join());
            return Err(2);
        }
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: current thread pseudo-handle; OpenAsSelf=1 so the query is
        // made with the PROCESS identity — querying an impersonation token
        // while impersonating a caller that cannot open its own token is the
        // documented trap this flag exists for.
        let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &raw mut token) };
        let token_guard = HandleGuard(token);
        let sid = if opened == 0 {
            Err(last_error())
        } else {
            logon_sid_of_token_for_testing(token_guard.0).map_err(|_| 0u32)
        };
        // SAFETY: paired with the successful impersonation above.
        let reverted = unsafe { RevertToSelf() };
        if reverted == 0 {
            eprintln!("P-17: RevertToSelf FAILED — aborting rather than run impersonated.");
            std::process::abort();
        }
        // Release the client and reap it before judging the SID: the row is
        // over either way, and no thread outlives it.
        let release = [0u8; 1];
        let mut sent: u32 = 0;
        // SAFETY: live handle, valid buffer.
        unsafe {
            WriteFile(
                server.0,
                release.as_ptr(),
                1,
                &raw mut sent,
                std::ptr::null_mut(),
            )
        };
        drop(server);
        drop(client.join());

        match sid {
            Ok(sid) => Ok(sid),
            Err(0) => {
                println!(
                    "P-17 UNRUN: the caller's token has no logon SID — the identity \
                     arrived, but not in a shape the DACL could ever have matched."
                );
                Err(2)
            }
            Err(e) => {
                println!("P-17 UNRUN: could not open the impersonation token (os error {e}).");
                Err(2)
            }
        }
    }
}
